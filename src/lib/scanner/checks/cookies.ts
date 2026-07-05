// Per-cookie security checks. The engine collapses multiple outcomes from one
// check into per-cookie findings. Uses the correctly-split Set-Cookie array
// (evidence.root.setCookies) so `Expires=` dates never mis-split.
import type { Check, CheckOutcome, Evidence } from "./types";

const MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie";

interface Cookie {
  raw: string;
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  domain: string | null;
  path: string | null;
  expires: string | null;
  maxAge: number | null;
}

function parse(raw: string): Cookie {
  const parts = raw.split(";").map((p) => p.trim());
  const [name, ...rest] = parts[0].split("=");
  const attrs = parts.slice(1);
  const get = (k: string) => attrs.find((a) => a.toLowerCase().startsWith(k))?.split("=")[1] ?? null;
  return {
    raw,
    name: name.trim(),
    value: rest.join("="),
    secure: attrs.some((a) => /^secure$/i.test(a)),
    httpOnly: attrs.some((a) => /^httponly$/i.test(a)),
    sameSite: get("samesite="),
    domain: get("domain="),
    path: get("path="),
    expires: get("expires="),
    maxAge: get("max-age=") ? Number(get("max-age=")) : null,
  };
}

function cookies(ev: Evidence): Cookie[] {
  const all = [...ev.root.setCookies];
  for (const p of ev.pages) for (const c of p.setCookies) if (!all.includes(c)) all.push(c);
  return all.map(parse);
}

const SESSION_NAMES = /(session|sess|sid|auth|token|jwt|csrf|xsrf|remember|login|user|account)/i;

function perCookie(
  id: string,
  meta: Omit<Check, "evaluate" | "id">,
  predicate: (c: Cookie, ev: Evidence) => boolean,
  evidence: (c: Cookie) => string,
): Check {
  return {
    id,
    ...meta,
    evaluate(ev) {
      const cs = cookies(ev);
      if (cs.length === 0) return null;
      const out: CheckOutcome[] = [];
      let anyApplied = false;
      for (const c of cs) {
        anyApplied = true;
        if (predicate(c, ev)) {
          out.push({ status: "fail", location: ev.root.url, titleSuffix: ` — «${c.name}»`, evidence: evidence(c), confidence: "firm" });
        }
      }
      if (out.length) return out;
      return anyApplied ? { status: "pass" } : null;
    },
  };
}

const isHttps = (ev: Evidence) => ev.root.url.startsWith("https://") || ev.scheme === "https";

export const COOKIE_CHECKS: Check[] = [
  perCookie(
    "cookie-secure-missing",
    {
      category: "cookies",
      title: "Çerezde Secure bayrağı yok",
      severity: "MEDIUM",
      cwe: "CWE-614",
      owasp: "A05:2021 Security Misconfiguration",
      description: "HTTPS sitede Secure olmayan çerez düz HTTP isteğinde açık ağ üzerinden gönderilir.",
      remediation: "Tüm çerezlere Secure ekleyin.",
      references: [MDN],
    },
    (c, ev) => isHttps(ev) && !c.secure,
    (c) => `Set-Cookie: ${c.raw}`,
  ),
  perCookie(
    "cookie-httponly-missing",
    {
      category: "cookies",
      title: "Çerezde HttpOnly bayrağı yok",
      severity: "MEDIUM",
      cwe: "CWE-1004",
      owasp: "A05:2021 Security Misconfiguration",
      description: "HttpOnly olmayan çerez JavaScript ile okunabilir; XSS ile çalınabilir.",
      remediation: "Oturum çerezlerine HttpOnly ekleyin.",
      references: [MDN],
    },
    (c) => !c.httpOnly,
    (c) => `Set-Cookie: ${c.raw}`,
  ),
  perCookie(
    "cookie-samesite-missing",
    {
      category: "cookies",
      title: "Çerezde SameSite bayrağı yok",
      severity: "LOW",
      cwe: "CWE-352",
      owasp: "A05:2021 Security Misconfiguration",
      description: "SameSite belirtilmemiş; CSRF yüzeyi artar (tarayıcı varsayılanı Lax olsa da açıkça belirtmek gerekir).",
      remediation: "SameSite=Lax (veya çapraz-site akış yoksa Strict) ekleyin.",
      references: [MDN],
    },
    (c) => !c.sameSite,
    (c) => `Set-Cookie: ${c.raw}`,
  ),
  perCookie(
    "cookie-samesite-none-insecure",
    {
      category: "cookies",
      title: "SameSite=None çerezi Secure değil",
      severity: "MEDIUM",
      cwe: "CWE-614",
      owasp: "A05:2021 Security Misconfiguration",
      description: "SameSite=None yalnızca Secure ile geçerlidir; aksi halde tarayıcı reddeder ve çerez sızabilir.",
      remediation: "SameSite=None kullanacaksanız Secure de ekleyin.",
      references: [MDN],
    },
    (c) => /none/i.test(c.sameSite ?? "") && !c.secure,
    (c) => `Set-Cookie: ${c.raw}`,
  ),
  perCookie(
    "cookie-host-prefix-violation",
    {
      category: "cookies",
      title: "__Host- çerez öneki kurallarını ihlal ediyor",
      severity: "MEDIUM",
      cwe: "CWE-614",
      owasp: "A05:2021 Security Misconfiguration",
      description: "__Host- önekli çerez Secure olmalı, Path=/ olmalı ve Domain belirtmemelidir; aksi halde tarayıcı önek güvencesini uygulamaz.",
      remediation: "__Host- çerezleri için: Secure; Path=/; (Domain YOK).",
      references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"],
    },
    (c) => c.name.startsWith("__Host-") && (!c.secure || c.domain !== null || c.path !== "/"),
    (c) => `Set-Cookie: ${c.raw}`,
  ),
  perCookie(
    "cookie-secure-prefix-violation",
    {
      category: "cookies",
      title: "__Secure- çerez öneki Secure değil",
      severity: "MEDIUM",
      cwe: "CWE-614",
      owasp: "A05:2021 Security Misconfiguration",
      description: "__Secure- önekli çerez Secure bayrağı taşımalıdır.",
      remediation: "__Secure- çerezlerine Secure ekleyin.",
      references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"],
    },
    (c) => c.name.startsWith("__Secure-") && !c.secure,
    (c) => `Set-Cookie: ${c.raw}`,
  ),
  perCookie(
    "cookie-session-unprotected",
    {
      category: "cookies",
      title: "Oturum benzeri çerez tam korunmuyor",
      severity: "HIGH",
      cwe: "CWE-1004",
      owasp: "A07:2021 Identification and Authentication Failures",
      description: "Adı oturum/kimlik çağrıştıran bir çerez Secure+HttpOnly bayraklarının ikisini birden taşımıyor; oturum ele geçirme riski.",
      remediation: "Oturum çerezlerini Secure; HttpOnly; SameSite=Lax ile ayarlayın.",
      references: [MDN],
    },
    (c, ev) => SESSION_NAMES.test(c.name) && (!(c.httpOnly) || (isHttps(ev) && !c.secure)),
    (c) => `Set-Cookie: ${c.raw}`,
  ),
  perCookie(
    "cookie-broad-domain",
    {
      category: "cookies",
      title: "Çerez üst alan adına (geniş) kapsamlandırılmış",
      severity: "LOW",
      cwe: "CWE-565",
      owasp: "A05:2021 Security Misconfiguration",
      description: "Domain= bir üst alan adına ayarlanmış; çerez tüm alt alan adlarıyla paylaşılır, saldırı yüzeyi artar.",
      remediation: "Domain'i mümkün olan en dar kapsama alın veya belirtmeyin.",
      references: [MDN],
    },
    (c, ev) => {
      if (!c.domain) return false;
      const d = c.domain.replace(/^\./, "").toLowerCase();
      return d !== ev.host && ev.host.endsWith(d) && d.split(".").length <= ev.host.split(".").length - 1;
    },
    (c) => `Set-Cookie: ${c.raw}`,
  ),
];
