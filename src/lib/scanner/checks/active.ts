// Active injection probes. Every probe is non-destructive and only reports a
// finding on *verified* behaviour (a unique marker reflected unencoded, a
// redirect Location we control, a database error string, an injected response
// header). Results are stashed in ev.probes[checkId] so the injection Checks
// stay pure functions. ev.probes[id] === undefined means "did not run"
// (→ N/A); [] means "ran, clean" (→ PASS); non-empty means findings.
import { httpGet } from "../http";
import type { HttpResult, RequestBudget } from "../http";
import type { Emit } from "./types";
import type { ActiveProbeResult, Check, Evidence } from "./types";

function marker(): string {
  // Deterministic-enough uniqueness without Math.random (varies per call site).
  return `sntnl${Date.now().toString(36)}${(probeCounter++).toString(36)}`;
}
let probeCounter = 0;

interface Candidate {
  url: string;
  params: string[];
}

function candidates(ev: Evidence, limit: number): Candidate[] {
  const out: Candidate[] = [];
  const seen = new Set<string>();
  const consider = (u: string) => {
    try {
      const url = new URL(u);
      const params = [...url.searchParams.keys()];
      if (!params.length) return;
      const key = url.origin + url.pathname + "?" + params.sort().join(",");
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ url: u, params });
    } catch {
      /* ignore */
    }
  };
  consider(ev.target);
  for (const l of ev.links) consider(l);
  for (const f of ev.forms) {
    if (f.method === "GET" && f.inputs.length) {
      const u = new URL(f.action);
      f.inputs.forEach((n) => u.searchParams.set(n, "1"));
      consider(u.toString());
    }
  }
  return out.slice(0, limit);
}

const SQL_ERRORS =
  /(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBCDriver|Unclosed quotation mark|quoted string not properly terminated|SQLSTATE\[|Warning: mysqli|valid MySQL result|com\.mysql\.jdbc)/i;
const NOSQL_ERRORS = /(MongoError|MongoServerError|MongoParseError|BSONError|BSONTypeError|E11000 duplicate key|CastError:.*(ObjectId|Number)|failed to parse.*ObjectId|couchdb.*(error|reason)|"\$where")/i;
const LDAP_ERRORS = /(javax\.naming|com\.sun\.jndi\.ldap|LDAPException|Invalid DN syntax|LDAP: error code|supplied argument is not a valid ldap)/i;
const CMD_OUTPUT = /uid=\d+\([a-z0-9_-]+\)\s+gid=\d+\(/i; // `id` command output
const METADATA_LEAK = /(ami-id|instance-id|iam\/security-credentials|instance-action|placement\/availability-zone|"AccessKeyId")/i;

// When a payload injected into several params at once triggers, re-test each
// param alone to attribute the finding to the exact parameter. The clean case
// stays at one request; these extra probes only run on a real hit (rare) and are
// budget-guarded. Returns the offending param, or undefined when it can't be
// pinned — an honest result, unlike blindly labelling params[0].
async function pinParam(
  c: Candidate,
  budget: RequestBudget,
  payload: string,
  detect: (res: HttpResult) => boolean,
  redirect: "follow" | "manual" = "follow",
): Promise<string | undefined> {
  if (c.params.length <= 1) return c.params[0];
  for (const p of c.params.slice(0, 4)) {
    if (budget.expired()) break;
    const u = new URL(c.url);
    u.searchParams.set(p, payload);
    const res = await httpGet(u.toString(), { budget, redirect });
    if (!res.error && detect(res)) return p;
  }
  return undefined;
}

export async function runActiveProbes(ev: Evidence, emit: Emit): Promise<void> {
  const budget = ev.budget;
  const cap = ev.profile === "DEEP" ? 20 : 8;
  const cands = candidates(ev, cap);

  const ids = [
    "xss-reflected", "open-redirect", "sqli-error", "ssti", "crlf-injection", "path-traversal",
    "host-header-injection", "nosqli-error", "cmd-injection", "ldap-injection", "ssrf-metadata",
  ];
  // A probe id becomes PASS/FAIL only once it has actually run at least once
  // (ev.probes[id] set to []). Left undefined → the check reports N/A ("did not
  // run"), never a misleading PASS. This matters when there are no injectable
  // params, or the budget is exhausted before a probe type gets a turn.
  const ensure = (id: string) => {
    if (!ev.probes[id]) ev.probes[id] = [];
  };

  // Host-header injection is per-target (one probe). fetch() forbids overriding
  // the real Host header, so the realistic vector is a reverse proxy trusting
  // X-Forwarded-Host / X-Host / Forwarded and reflecting it into an absolute URL
  // (a redirect Location) or the body — that is what we inject and detect.
  if (!budget.expired()) {
    ensure("host-header-injection");
    const m = marker();
    const bad = `${m}.example.com`;
    const res = await httpGet(ev.target, {
      budget,
      headers: { "X-Forwarded-Host": bad, "X-Host": bad, "X-Forwarded-Server": bad, Forwarded: `host=${bad}` },
      redirect: "manual",
    });
    const loc = res.headers["location"] ?? "";
    if (!res.error && (loc.includes(bad) || res.body.includes(bad))) {
      ev.probes["host-header-injection"].push({
        location: ev.target,
        confidence: "firm",
        evidence: `Güvenilmeyen X-Forwarded-Host değeri yönlendirmeye/gövdeye yansıdı: ${bad}`,
      });
    }
  }

  const REDIRECT_PARAMS = new Set(["next", "url", "redirect", "return", "returnurl", "returnto", "dest", "destination", "target", "r", "u", "goto", "continue", "redirect_uri"]);

  for (const c of cands) {
    if (budget.expired()) break;

    // Clean baseline for this endpoint — error-based probes must show an error
    // signature that is ABSENT without injection, or it's a false positive
    // (a page that merely contains the word "MongoDB" is not vulnerable).
    const baseRes = await httpGet(c.url, { budget });
    const baseBody = baseRes.error ? "" : baseRes.body;

    // --- Reflected XSS ---
    {
      ensure("xss-reflected");
      const m = marker();
      const payload = `"><svg/onload=${m}>`;
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 4)) u.searchParams.set(p, payload);
      const res = await httpGet(u.toString(), { budget });
      if (!res.error && res.body.includes(payload)) {
        const param = await pinParam(c, budget, payload, (r) => r.body.includes(payload));
        ev.probes["xss-reflected"].push({
          location: u.toString(),
          confidence: "firm",
          evidence: `Payload kodlanmadan yansıdı:\n${payload}`,
          param,
        });
      }
    }

    // --- SQL injection (error-based) ---
    if (!budget.expired()) {
      ensure("sqli-error");
      const payload = `'"\`` + "1";
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 4)) u.searchParams.set(p, payload);
      const res = await httpGet(u.toString(), { budget });
      const err = res.body && SQL_ERRORS.exec(res.body);
      if (!res.error && err && !SQL_ERRORS.test(baseBody)) {
        const param = await pinParam(c, budget, payload, (r) => SQL_ERRORS.test(r.body));
        ev.probes["sqli-error"].push({
          location: u.toString(),
          confidence: "firm",
          evidence: `Veritabanı hata imzası: ${err[0]}`,
          param,
        });
      }
    }

    // --- SSTI ---
    if (!budget.expired()) {
      ensure("ssti");
      const m = marker();
      // 7*7 in several template dialects; the marker guards against coincidental 49.
      const payload = `${m}{{7*7}}`;
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 3)) u.searchParams.set(p, payload);
      const res = await httpGet(u.toString(), { budget });
      if (!res.error && res.body.includes(`${m}49`)) {
        const param = await pinParam(c, budget, payload, (r) => r.body.includes(`${m}49`));
        ev.probes["ssti"].push({
          location: u.toString(),
          confidence: "firm",
          evidence: `Şablon ifadesi sunucuda değerlendirildi: {{7*7}} → 49`,
          param,
        });
      }
    }

    // --- Path traversal / LFI ---
    if (!budget.expired()) {
      ensure("path-traversal");
      const payload = "../../../../../../etc/passwd";
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 3)) u.searchParams.set(p, payload);
      const res = await httpGet(u.toString(), { budget });
      if (!res.error && /root:.*:0:0:/.test(res.body)) {
        const param = await pinParam(c, budget, payload, (r) => /root:.*:0:0:/.test(r.body));
        ev.probes["path-traversal"].push({
          location: u.toString(),
          confidence: "confirmed",
          evidence: "/etc/passwd içeriği yansıdı (root:...:0:0:)",
          param,
        });
      }
    }

    // --- Open redirect ---
    if (!budget.expired()) {
      ensure("open-redirect");
      const evil = "https://sentinel-redirect-test.example.com/";
      const redirectable = c.params.filter((p) => REDIRECT_PARAMS.has(p.toLowerCase()));
      for (const p of redirectable.slice(0, 3)) {
        if (budget.expired()) break;
        const u = new URL(c.url);
        u.searchParams.set(p, evil);
        const res = await httpGet(u.toString(), { budget, redirect: "manual" });
        const loc = res.headers["location"] ?? "";
        if (!res.error && res.status >= 300 && res.status < 400 && loc.startsWith(evil)) {
          ev.probes["open-redirect"].push({
            location: u.toString(),
            confidence: "confirmed",
            evidence: `Location: ${loc}`,
            param: p,
          });
        }
      }
    }

    // --- CRLF / response header injection ---
    if (!budget.expired()) {
      ensure("crlf-injection");
      const m = marker();
      // Build the query RAW: URLSearchParams.set() would percent-encode the
      // %0d%0a a second time, so the server would decode it back to the literal
      // text "%0d%0a" and never see a real CR/LF. Hand-writing the search string
      // keeps the single-encoded payload the server decodes into header breaks.
      const injParams = c.params.slice(0, 3);
      const raw = injParams.map((p) => `${encodeURIComponent(p)}=x%0d%0aX-Sentinel:${m}`).join("&");
      const u = new URL(c.url);
      u.search = "?" + raw;
      const res = await httpGet(u.toString(), { budget, redirect: "manual" });
      if (!res.error && res.headers["x-sentinel"] === m) {
        let param: string | undefined = injParams.length === 1 ? injParams[0] : undefined;
        if (injParams.length > 1) {
          for (const p of injParams) {
            if (budget.expired()) break;
            const us = new URL(c.url);
            us.search = `?${encodeURIComponent(p)}=x%0d%0aX-Sentinel:${m}`;
            const r = await httpGet(us.toString(), { budget, redirect: "manual" });
            if (!r.error && r.headers["x-sentinel"] === m) {
              param = p;
              break;
            }
          }
        }
        ev.probes["crlf-injection"].push({
          location: u.toString(),
          confidence: "confirmed",
          evidence: `Enjekte edilen X-Sentinel başlığı yanıtta göründü.`,
          param,
        });
      }
    }

    // --- NoSQL injection (error-based) ---
    if (!budget.expired()) {
      ensure("nosqli-error");
      const payload = `'"{[$where]}`;
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 3)) u.searchParams.set(p, payload);
      const res = await httpGet(u.toString(), { budget });
      const err = res.body && NOSQL_ERRORS.exec(res.body);
      if (!res.error && err && !NOSQL_ERRORS.test(baseBody)) {
        const param = await pinParam(c, budget, payload, (r) => NOSQL_ERRORS.test(r.body));
        ev.probes["nosqli-error"].push({ location: u.toString(), confidence: "firm", evidence: `NoSQL hata imzası: ${err[0]}`, param });
      }
    }

    // --- OS command injection ---
    if (!budget.expired()) {
      ensure("cmd-injection");
      const payload = "1;id|id`id`$(id)";
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 3)) u.searchParams.set(p, payload);
      const res = await httpGet(u.toString(), { budget });
      const err = res.body && CMD_OUTPUT.exec(res.body);
      if (!res.error && err) {
        const param = await pinParam(c, budget, payload, (r) => CMD_OUTPUT.test(r.body));
        ev.probes["cmd-injection"].push({ location: u.toString(), confidence: "confirmed", evidence: `Komut çıktısı yansıdı: ${err[0]}`, param });
      }
    }

    // --- LDAP injection (error-based) ---
    if (!budget.expired()) {
      ensure("ldap-injection");
      const payload = "*)(&(uid=*))";
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 3)) u.searchParams.set(p, payload);
      const res = await httpGet(u.toString(), { budget });
      const err = res.body && LDAP_ERRORS.exec(res.body);
      if (!res.error && err && !LDAP_ERRORS.test(baseBody)) {
        const param = await pinParam(c, budget, payload, (r) => LDAP_ERRORS.test(r.body));
        ev.probes["ldap-injection"].push({ location: u.toString(), confidence: "firm", evidence: `LDAP hata imzası: ${err[0]}`, param });
      }
    }

    // --- SSRF → cloud metadata (confirmed only on real metadata leak) ---
    if (!budget.expired()) {
      ensure("ssrf-metadata");
      const SSRF_PARAMS = /^(url|uri|link|src|source|dest|redirect|target|host|domain|site|feed|image|img|load|page|file|path|proxy|fetch|callback|data|reference|out|to|view|show|open|next|continue)$/i;
      const ssrfParams = c.params.filter((p) => SSRF_PARAMS.test(p));
      for (const p of ssrfParams.slice(0, 3)) {
        if (budget.expired()) break;
        const u = new URL(c.url);
        u.searchParams.set(p, "http://169.254.169.254/latest/meta-data/");
        const res = await httpGet(u.toString(), { budget });
        if (!res.error && res.body && METADATA_LEAK.test(res.body)) {
          ev.probes["ssrf-metadata"].push({ location: u.toString(), confidence: "confirmed", evidence: "Bulut metadata servisi içeriği yanıta yansıdı (169.254.169.254).", param: p });
        }
      }
    }
  }

  const total = ids.reduce((n, id) => n + (ev.probes[id]?.length ?? 0), 0);
  await emit({ type: "log", level: "info", message: `Aktif prob('lar): ${cands.length} uç test edildi, ${total} doğrulanmış bulgu.` });
}

// ---- Injection checks (read ev.probes) --------------------------------------

function probeCheck(
  id: string,
  probeId: string,
  meta: Omit<Check, "evaluate" | "id">,
): Check {
  return {
    id,
    ...meta,
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const hits = ev.probes[probeId];
      if (hits === undefined) return null; // did not run
      if (hits.length === 0) return { status: "pass" };
      return hits.map((h) => ({
        status: "fail" as const,
        location: h.location,
        confidence: h.confidence,
        evidence: h.evidence,
        titleSuffix: h.param ? ` — parametre «${h.param}»` : undefined,
      }));
    },
  };
}

export const INJECTION_CHECKS: Check[] = [
  probeCheck("xss-reflected", "xss-reflected", {
    category: "injection",
    title: "Yansıyan XSS (Cross-Site Scripting)",
    severity: "HIGH",
    cwe: "CWE-79",
    owasp: "A03:2021 Injection",
    description: "Bir parametreye gönderilen değer çıktıya kodlanmadan yansıtılıyor; saldırgan kurbanın tarayıcısında script çalıştırabilir.",
    remediation: "Çıktıyı bağlama göre kodlayın (HTML/attr/JS), girdiyi doğrulayın ve nonce tabanlı CSP uygulayın. Şablon motorunun otomatik kaçışını kapatmayın.",
    references: ["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
  }),
  probeCheck("sqli-error", "sqli-error", {
    category: "injection",
    title: "SQL Enjeksiyonu (hata tabanlı)",
    severity: "CRITICAL",
    cwe: "CWE-89",
    owasp: "A03:2021 Injection",
    description: "Bir parametreye tek tırnak eklendiğinde yanıtta veritabanı hata mesajı belirdi; girdi doğrudan SQL sorgusuna geçiyor olabilir.",
    remediation: "Parametreli sorgular / hazırlıklı ifadeler (prepared statements) kullanın; asla string birleştirmeyin. ORM'lerde ham sorgu birleştirmesinden kaçının; en az yetkili DB kullanıcısı verin.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
  }),
  probeCheck("ssti", "ssti", {
    category: "injection",
    title: "Sunucu Taraflı Şablon Enjeksiyonu (SSTI)",
    severity: "CRITICAL",
    cwe: "CWE-1336",
    owasp: "A03:2021 Injection",
    description: "Bir parametredeki şablon ifadesi ({{7*7}}) sunucuda değerlendirildi (49). Bu genellikle uzaktan kod çalıştırmaya (RCE) tırmanabilir.",
    remediation: "Kullanıcı girdisini şablon kaynağı olarak KULLANMAYIN; verileri yalnızca değişken olarak (sandbox'lı) geçirin. Logic-less şablonları tercih edin.",
    references: ["https://portswigger.net/research/server-side-template-injection"],
  }),
  probeCheck("path-traversal", "path-traversal", {
    category: "injection",
    title: "Yol Aşımı / Yerel Dosya Dahil Etme (LFI)",
    severity: "CRITICAL",
    cwe: "CWE-22",
    owasp: "A01:2021 Broken Access Control",
    description: "Bir parametre üzerinden ../../etc/passwd okundu; sunucu keyfi dosya okumaya açık.",
    remediation: "Dosya yollarını allowlist'e karşı doğrulayın, kullanıcı girdisini yol olarak kullanmayın; canonicalize edip kök dizin sınırını zorunlu kılın.",
    references: ["https://owasp.org/www-community/attacks/Path_Traversal"],
  }),
  probeCheck("open-redirect", "open-redirect", {
    category: "injection",
    title: "Açık Yönlendirme (Open Redirect)",
    severity: "MEDIUM",
    cwe: "CWE-601",
    owasp: "A01:2021 Broken Access Control",
    description: "Bir parametre, doğrulanmadan harici bir adrese yönlendiriyor; kimlik avı ve OAuth token sızdırma için kötüye kullanılabilir.",
    remediation: "Yönlendirme hedefini allowlist'e karşı doğrulayın veya yalnızca göreli yollara izin verin.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
  }),
  probeCheck("crlf-injection", "crlf-injection", {
    category: "injection",
    title: "CRLF / Yanıt Başlığı Enjeksiyonu",
    severity: "HIGH",
    cwe: "CWE-113",
    owasp: "A03:2021 Injection",
    description: "Bir parametre üzerinden yanıt başlıklarına enjeksiyon yapılabildi; başlık bölme, önbellek zehirleme ve XSS'e yol açabilir.",
    remediation: "Girdideki CR/LF karakterlerini reddedin; başlık değerlerini doğrudan kullanıcı girdisinden oluşturmayın.",
    references: ["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
  }),
  probeCheck("host-header-injection", "host-header-injection", {
    category: "injection",
    title: "Host Başlığı Enjeksiyonu",
    severity: "MEDIUM",
    cwe: "CWE-644",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Uygulama, Host başlığını güvenmeden yanıta/yönlendirmeye yansıtıyor; parola sıfırlama zehirlenmesi ve önbellek zehirlemesi için kötüye kullanılabilir.",
    remediation: "Host başlığını bir allowlist'e karşı doğrulayın; mutlak URL'leri sabit bir yapılandırılmış alan adından üretin.",
    references: ["https://portswigger.net/web-security/host-header"],
  }),
  probeCheck("nosqli-error", "nosqli-error", {
    category: "injection",
    title: "NoSQL Enjeksiyonu (hata tabanlı)",
    severity: "CRITICAL",
    cwe: "CWE-943",
    owasp: "A03:2021 Injection",
    description: "Bir parametreye NoSQL operatörü/özel karakter enjekte edildiğinde yanıtta NoSQL (ör. MongoDB) hata imzası belirdi; girdi doğrudan sorguya geçiyor olabilir.",
    remediation: "Girdiyi türüne göre doğrulayın, operatör enjeksiyonunu engelleyin (ör. string beklenirken nesne kabul etmeyin); ODM/sürücü parametrelemesini kullanın.",
    references: ["https://owasp.org/www-community/attacks/NoSQL_injection"],
  }),
  probeCheck("cmd-injection", "cmd-injection", {
    category: "injection",
    title: "İşletim Sistemi Komut Enjeksiyonu",
    severity: "CRITICAL",
    cwe: "CWE-78",
    owasp: "A03:2021 Injection",
    description: "Bir parametre üzerinden enjekte edilen `id` komutunun çıktısı (uid=…) yanıta yansıdı; sunucuda keyfi komut çalıştırılabiliyor.",
    remediation: "Kabuk çağrılarında kullanıcı girdisi kullanmayın; argümanları dizi olarak geçen güvenli API'ler (execFile) kullanın ve girdiyi katı allowlist ile doğrulayın.",
    references: ["https://owasp.org/www-community/attacks/Command_Injection"],
  }),
  probeCheck("ldap-injection", "ldap-injection", {
    category: "injection",
    title: "LDAP Enjeksiyonu (hata tabanlı)",
    severity: "HIGH",
    cwe: "CWE-90",
    owasp: "A03:2021 Injection",
    description: "Bir parametreye LDAP filtre meta-karakterleri enjekte edildiğinde LDAP hata imzası belirdi; kimlik doğrulama atlatma/veri sızdırma mümkün olabilir.",
    remediation: "LDAP filtrelerinde kullanıcı girdisini kaçırın (RFC 4515) ve parametreli aramalar kullanın.",
    references: ["https://owasp.org/www-community/attacks/LDAP_Injection"],
  }),
  probeCheck("ssrf-metadata", "ssrf-metadata", {
    category: "injection",
    title: "Sunucu Taraflı İstek Sahteciliği (SSRF) — bulut metadata",
    severity: "CRITICAL",
    cwe: "CWE-918",
    owasp: "A10:2021 Server-Side Request Forgery",
    description: "URL-benzeri bir parametre üzerinden bulut metadata servisi (169.254.169.254) içeriği okundu; bu genellikle geçici bulut kimlik bilgilerinin çalınmasına yol açar.",
    remediation: "Dış URL çağrılarını allowlist'e alın, iç/link-local IP aralıklarını (169.254.0.0/16 dahil) reddedin, DNS yeniden bağlamayı engelleyin, IMDSv2'yi zorunlu kılın.",
    references: ["https://portswigger.net/web-security/ssrf"],
  }),
];
