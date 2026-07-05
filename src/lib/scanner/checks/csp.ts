// Content-Security-Policy quality analysis — directive by directive. Presence
// of a CSP is not protection; these checks evaluate whether it actually stops
// script injection.
import type { Check, CheckOutcome, Evidence } from "./types";

const CSP_EVAL = "https://csp-evaluator.withgoogle.com/";
const MDN_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy";

function parseCsp(v: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const part of v.split(";")) {
    const toks = part.trim().split(/\s+/).filter(Boolean);
    if (!toks.length) continue;
    out[toks[0].toLowerCase()] = toks.slice(1);
  }
  return out;
}
function csp(ev: Evidence): { dirs: Record<string, string[]>; raw: string } | null {
  const raw = ev.root.headers["content-security-policy"];
  if (!raw) return null;
  return { dirs: parseCsp(raw), raw };
}
function effective(dirs: Record<string, string[]>, name: string): string[] | undefined {
  return dirs[name] ?? dirs["default-src"];
}
const has = (arr: string[] | undefined, tok: string) => !!arr?.some((s) => s.toLowerCase() === tok);
const hasNonceOrHash = (arr: string[] | undefined) =>
  !!arr?.some((s) => /^'(nonce-|sha(256|384|512)-)/i.test(s) || s.toLowerCase() === "'strict-dynamic'");

// A CSP-quality check only runs when a CSP exists.
function cspCheck(id: string, meta: Omit<Check, "evaluate" | "id">, fn: (dirs: Record<string, string[]>, ev: Evidence) => CheckOutcome | null): Check {
  return {
    id,
    ...meta,
    evaluate(ev) {
      const c = csp(ev);
      if (!c) return null;
      return fn(c.dirs, ev);
    },
  };
}

export const CSP_CHECKS: Check[] = [
  {
    id: "csp-missing",
    category: "csp",
    title: "Content-Security-Policy başlığı eksik",
    severity: "MEDIUM",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "CSP tanımlı değil; XSS'e karşı en güçlü tarayıcı savunma katmanı yok.",
    remediation: "Nonce tabanlı sıkı bir CSP tanımlayın: default-src 'self'; script-src 'self' 'nonce-<rastgele>' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'.",
    references: [MDN_CSP],
    evaluate(ev) {
      if (ev.root.headers["content-security-policy"]) return { status: "pass" };
      if (ev.root.headers["content-security-policy-report-only"]) {
        return { status: "fail", severity: "LOW", location: ev.root.url, detail: "Yalnızca Report-Only var; politika zorlanmıyor.", evidence: ev.root.headers["content-security-policy-report-only"] };
      }
      return { status: "fail", location: ev.root.url };
    },
  },
  cspCheck("csp-script-unsafe-inline", {
    category: "csp", title: "CSP script-src 'unsafe-inline' (nonce/hash yok)", severity: "HIGH", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "script-src 'unsafe-inline' içeriyor ve nonce/hash/'strict-dynamic' yok; enjekte edilen inline scriptler çalışabilir, CSP'nin XSS koruması etkisiz.",
    remediation: "'unsafe-inline' yerine 'nonce-<rastgele>' + 'strict-dynamic' kullanın.", references: [CSP_EVAL],
  }, (d, ev) => {
    const s = effective(d, "script-src");
    if (!s) return null;
    return has(s, "'unsafe-inline'") && !hasNonceOrHash(s) ? { status: "fail", location: ev.root.url, evidence: `script-src ${s.join(" ")}` } : { status: "pass" };
  }),
  cspCheck("csp-script-unsafe-eval", {
    category: "csp", title: "CSP script-src 'unsafe-eval'", severity: "MEDIUM", cwe: "CWE-95",
    owasp: "A05:2021 Security Misconfiguration",
    description: "'unsafe-eval' eval()/new Function() gibi dinamik kod çalıştırmaya izin verir; DOM-XSS yüzeyini büyütür.",
    remediation: "'unsafe-eval' kaldırın; eval kullanan kütüphaneleri değiştirin.", references: [CSP_EVAL],
  }, (d, ev) => {
    const s = effective(d, "script-src");
    if (!s) return null;
    return has(s, "'unsafe-eval'") ? { status: "fail", location: ev.root.url, evidence: `script-src ${s.join(" ")}` } : { status: "pass" };
  }),
  cspCheck("csp-script-wildcard", {
    category: "csp", title: "CSP script-src joker (*) veya http: kaynak", severity: "HIGH", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "script-src '*', 'https:' gibi geniş veya 'http:' kaynak içeriyor; herhangi bir host'tan script yüklenebilir.",
    remediation: "Kaynakları 'self' + belirli güvenilir origin'lerle sınırlayın.", references: [CSP_EVAL],
  }, (d, ev) => {
    const s = effective(d, "script-src");
    if (!s) return null;
    return s.some((x) => x === "*" || /^https?:$/i.test(x) || x === "data:") ? { status: "fail", location: ev.root.url, evidence: `script-src ${s.join(" ")}` } : { status: "pass" };
  }),
  cspCheck("csp-object-src", {
    category: "csp", title: "CSP object-src kilitli değil", severity: "MEDIUM", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "object-src 'none' yok; <object>/<embed> ile eklenti tabanlı XSS mümkün olabilir.",
    remediation: "object-src 'none' ekleyin.", references: [CSP_EVAL],
  }, (d, ev) => {
    const o = effective(d, "object-src");
    if (o && has(o, "'none'")) return { status: "pass" };
    return { status: "fail", location: ev.root.url, evidence: ev.root.headers["content-security-policy"] };
  }),
  cspCheck("csp-base-uri", {
    category: "csp", title: "CSP base-uri kısıtlı değil", severity: "LOW", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "base-uri belirtilmemiş; enjekte edilen <base> etiketiyle göreli scriptlerin kaynağı değiştirilebilir.",
    remediation: "base-uri 'self' (veya 'none') ekleyin.", references: [CSP_EVAL],
  }, (d, ev) => (d["base-uri"] ? { status: "pass" } : { status: "fail", location: ev.root.url })),
  cspCheck("csp-frame-ancestors", {
    category: "csp", title: "CSP frame-ancestors yok", severity: "LOW", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "frame-ancestors belirtilmemiş; clickjacking koruması yalnızca eski X-Frame-Options'a bağlı.",
    remediation: "frame-ancestors 'none' (veya güvenilen origin'ler) ekleyin.", references: [MDN_CSP],
  }, (d, ev) => (d["frame-ancestors"] ? { status: "pass" } : { status: "fail", location: ev.root.url })),
  cspCheck("csp-default-src", {
    category: "csp", title: "CSP default-src tanımlı değil", severity: "MEDIUM", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "default-src yok; belirtilmeyen kaynak türleri kısıtlanmaz.",
    remediation: "En azından default-src 'self' tanımlayın.", references: [MDN_CSP],
  }, (d, ev) => (d["default-src"] ? { status: "pass" } : { status: "fail", location: ev.root.url, evidence: ev.root.headers["content-security-policy"] })),
  cspCheck("csp-default-wildcard", {
    category: "csp", title: "CSP default-src joker (*)", severity: "HIGH", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "default-src '*' politikayı büyük ölçüde etkisiz kılar.",
    remediation: "default-src '*' yerine 'self' kullanın.", references: [CSP_EVAL],
  }, (d, ev) => {
    const s = d["default-src"];
    if (!s) return null;
    return s.includes("*") ? { status: "fail", location: ev.root.url, evidence: `default-src ${s.join(" ")}` } : { status: "pass" };
  }),
  cspCheck("csp-form-action", {
    category: "csp", title: "CSP form-action kısıtlı değil", severity: "LOW", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "form-action yok; enjekte edilen form harici bir adrese veri gönderebilir.",
    remediation: "form-action 'self' ekleyin.", references: [MDN_CSP],
  }, (d, ev) => (d["form-action"] ? { status: "pass" } : { status: "fail", location: ev.root.url })),
  cspCheck("csp-style-unsafe-inline", {
    category: "csp", title: "CSP style-src 'unsafe-inline'", severity: "LOW", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "style-src 'unsafe-inline' stil enjeksiyonuna izin verir (düşük risk ama sıkılaştırılabilir).",
    remediation: "Mümkünse stil için de nonce/hash kullanın.", references: [CSP_EVAL],
  }, (d, ev) => {
    const s = effective(d, "style-src");
    if (!s) return null;
    return has(s, "'unsafe-inline'") && !hasNonceOrHash(s) ? { status: "fail", location: ev.root.url, evidence: `style-src ${s.join(" ")}` } : { status: "pass" };
  }),
  cspCheck("csp-upgrade-insecure", {
    category: "csp", title: "CSP upgrade-insecure-requests yok", severity: "INFO", cwe: "CWE-311",
    owasp: "A02:2021 Cryptographic Failures",
    description: "HTTPS sayfada upgrade-insecure-requests yok; eski http:// alt kaynaklar yükseltilmez.",
    remediation: "CSP'ye upgrade-insecure-requests ekleyin.", references: [MDN_CSP],
  }, (d, ev) => {
    if (!ev.root.url.startsWith("https://")) return null;
    return "upgrade-insecure-requests" in d ? { status: "pass" } : { status: "fail", location: ev.root.url };
  }),
  cspCheck("csp-plugin-types-deprecated", {
    category: "csp", title: "CSP plugin-types (kullanımdan kalkmış) kullanılıyor", severity: "INFO", cwe: "CWE-1104",
    owasp: "A05:2021 Security Misconfiguration",
    description: "plugin-types yönergesi kaldırılmıştır; modern tarayıcılar yok sayar.",
    remediation: "plugin-types yerine object-src 'none' kullanın.", references: [MDN_CSP],
  }, (d, ev) => ("plugin-types" in d ? { status: "fail", location: ev.root.url, evidence: `plugin-types ${d["plugin-types"].join(" ")}` } : { status: "pass" })),
  cspCheck("csp-connect-wildcard", {
    category: "csp", title: "CSP connect-src joker (*)", severity: "LOW", cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "connect-src '*' exfiltration (veri sızdırma) hedeflerini kısıtlamaz.",
    remediation: "connect-src'i bilinen API origin'leriyle sınırlayın.", references: [CSP_EVAL],
  }, (d, ev) => {
    const s = d["connect-src"];
    if (!s) return null;
    return s.includes("*") ? { status: "fail", location: ev.root.url, evidence: `connect-src ${s.join(" ")}` } : { status: "pass" };
  }),
];
