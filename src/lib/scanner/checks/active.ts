// Active injection probes. Every probe is non-destructive and only reports a
// finding on *verified* behaviour (a unique marker reflected unencoded, a
// redirect Location we control, a database error string, an injected response
// header). Results are stashed in ev.probes[checkId] so the injection Checks
// stay pure functions. ev.probes[id] === undefined means "did not run"
// (→ N/A); [] means "ran, clean" (→ PASS); non-empty means findings.
import { httpGet } from "../http";
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

export async function runActiveProbes(ev: Evidence, emit: Emit): Promise<void> {
  const budget = ev.budget;
  const cap = ev.profile === "DEEP" ? 20 : 8;
  const cands = candidates(ev, cap);

  const ids = ["xss-reflected", "open-redirect", "sqli-error", "ssti", "crlf-injection", "path-traversal", "host-header-injection"];
  for (const id of ids) ev.probes[id] = [];

  // Host-header injection is per-target (one probe).
  if (!budget.expired()) {
    const m = marker();
    const res = await httpGet(ev.target, { budget, headers: { Host: `${m}.example.com` }, redirect: "manual" });
    const loc = res.headers["location"] ?? "";
    if (!res.error && (loc.includes(m) || res.body.includes(`${m}.example.com`))) {
      ev.probes["host-header-injection"].push({
        location: ev.target,
        confidence: "firm",
        evidence: `Host başlığı yanıta yansıdı: ${m}.example.com`,
      });
    }
  }

  const REDIRECT_PARAMS = new Set(["next", "url", "redirect", "return", "returnurl", "returnto", "dest", "destination", "target", "r", "u", "goto", "continue", "redirect_uri"]);

  for (const c of cands) {
    if (budget.expired()) break;

    // --- Reflected XSS ---
    {
      const m = marker();
      const payload = `"><svg/onload=${m}>`;
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 4)) u.searchParams.set(p, payload);
      const res = await httpGet(u.toString(), { budget });
      if (!res.error && res.body.includes(payload)) {
        ev.probes["xss-reflected"].push({
          location: u.toString(),
          confidence: "firm",
          evidence: `Payload kodlanmadan yansıdı:\n${payload}`,
          param: c.params[0],
        });
      }
    }

    // --- SQL injection (error-based) ---
    if (!budget.expired()) {
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 4)) u.searchParams.set(p, `'"\`` + "1");
      const res = await httpGet(u.toString(), { budget });
      const err = res.body && SQL_ERRORS.exec(res.body);
      if (!res.error && err) {
        ev.probes["sqli-error"].push({
          location: u.toString(),
          confidence: "firm",
          evidence: `Veritabanı hata imzası: ${err[0]}`,
          param: c.params[0],
        });
      }
    }

    // --- SSTI ---
    if (!budget.expired()) {
      const m = marker();
      const u = new URL(c.url);
      // 7*7 in several template dialects; 's7ntnl' guards against coincidental 49.
      for (const p of c.params.slice(0, 3)) u.searchParams.set(p, `${m}{{7*7}}`);
      const res = await httpGet(u.toString(), { budget });
      if (!res.error && res.body.includes(`${m}49`)) {
        ev.probes["ssti"].push({
          location: u.toString(),
          confidence: "firm",
          evidence: `Şablon ifadesi sunucuda değerlendirildi: {{7*7}} → 49`,
          param: c.params[0],
        });
      }
    }

    // --- Path traversal / LFI ---
    if (!budget.expired()) {
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 3)) u.searchParams.set(p, "../../../../../../etc/passwd");
      const res = await httpGet(u.toString(), { budget });
      if (!res.error && /root:.*:0:0:/.test(res.body)) {
        ev.probes["path-traversal"].push({
          location: u.toString(),
          confidence: "confirmed",
          evidence: "/etc/passwd içeriği yansıdı (root:...:0:0:)",
          param: c.params[0],
        });
      }
    }

    // --- Open redirect ---
    if (!budget.expired()) {
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
      const m = marker();
      const u = new URL(c.url);
      for (const p of c.params.slice(0, 3)) u.searchParams.set(p, `x%0d%0aX-Sentinel:${m}`);
      const res = await httpGet(u.toString(), { budget, redirect: "manual" });
      if (!res.error && (res.headers["x-sentinel"] === m)) {
        ev.probes["crlf-injection"].push({
          location: u.toString(),
          confidence: "confirmed",
          evidence: `Enjekte edilen X-Sentinel başlığı yanıtta göründü.`,
          param: c.params[0],
        });
      }
    }
  }

  const total = ids.reduce((n, id) => n + ev.probes[id].length, 0);
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
];
