// CORS checks over the Origin-reflection probe (ev.cors).
import type { Check, Evidence } from "./types";

const MDN_CORS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS";
const PORTSWIGGER = "https://portswigger.net/web-security/cors";

function cors(ev: Evidence) {
  return ev.cors;
}

export const CORS_CHECKS: Check[] = [
  {
    id: "cors-reflect-credentials",
    category: "cors",
    title: "Tehlikeli CORS: Origin yansıtma + credentials",
    severity: "HIGH",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Sunucu isteğin Origin'ini yansıtırken Access-Control-Allow-Credentials: true gönderiyor. Böylece HERHANGİ bir site, kullanıcının kimlik bilgileriyle API'ye erişip yanıtı okuyabilir.",
    remediation: "Origin'i yansıtmayın; statik bir allowlist kullanın ve credentials'ı yalnızca gerçekten gerekiyorsa açın.",
    references: [PORTSWIGGER],
    evaluate(ev) {
      const c = cors(ev);
      if (!c) return null;
      return c.reflectsOrigin && /true/i.test(c.acac)
        ? { status: "fail", location: ev.target, confidence: "confirmed", evidence: `Origin: ${c.probeOrigin}\nACAO: ${c.acao}\nACAC: ${c.acac}` }
        : { status: "pass" };
    },
  },
  {
    id: "cors-wildcard-credentials",
    category: "cors",
    title: "CORS joker (*) + credentials",
    severity: "HIGH",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "ACAO '*' ile ACAC true birlikte kullanılamaz; kullanılıyorsa yapılandırma hatalı ve tehlikelidir.",
    remediation: "Wildcard ve credentials'ı birlikte kullanmayın; belirli origin'leri allowlist'leyin.",
    references: [MDN_CORS],
    evaluate(ev) {
      const c = cors(ev);
      if (!c) return null;
      return c.wildcard && /true/i.test(c.acac) ? { status: "fail", location: ev.target, confidence: "confirmed", evidence: `ACAO: *\nACAC: ${c.acac}` } : { status: "pass" };
    },
  },
  {
    id: "cors-null-origin",
    category: "cors",
    title: "CORS 'null' origin'e izin veriyor",
    severity: "MEDIUM",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "ACAO 'null' değerine izin veriyor; sandbox'lı iframe'ler ve bazı saldırılar 'null' origin üretebildiği için bu güvenilmez.",
    remediation: "'null' origin'i güvenilir kabul etmeyin.",
    references: [PORTSWIGGER],
    evaluate(ev) {
      const c = cors(ev);
      if (!c) return null;
      return c.allowsNullOrigin ? { status: "fail", location: ev.target, confidence: "firm", evidence: `ACAO: null` } : { status: "pass" };
    },
  },
  {
    id: "cors-wildcard",
    category: "cors",
    title: "CORS herkese açık (ACAO: *)",
    severity: "LOW",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "ACAO '*' herkese okuma erişimi verir. Kimlik gerektirmeyen genel veriler için kabul edilebilir, ancak hassas veriler için değil.",
    remediation: "Yanıt hassas veri içeriyorsa origin'i allowlist'e alın; değilse riski kabul edin.",
    references: [MDN_CORS],
    evaluate(ev) {
      const c = cors(ev);
      if (!c) return null;
      return c.wildcard && !/true/i.test(c.acac) ? { status: "fail", location: ev.target, evidence: `ACAO: *` } : { status: "pass" };
    },
  },
  {
    id: "cors-reflect-no-credentials",
    category: "cors",
    title: "CORS keyfi Origin'i yansıtıyor (credentials'sız)",
    severity: "LOW",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Sunucu herhangi bir Origin'i yansıtıyor. Credentials kapalı olduğu için etkisi sınırlı, ama allowlist olmaması yine de bir zayıflıktır.",
    remediation: "Origin'i statik bir allowlist'e karşı doğrulayın.",
    references: [PORTSWIGGER],
    evaluate(ev) {
      const c = cors(ev);
      if (!c) return null;
      return c.reflectsOrigin && !/true/i.test(c.acac) ? { status: "fail", location: ev.target, evidence: `Origin yansıtıldı: ${c.acao}` } : { status: "pass" };
    },
  },
  {
    id: "cors-reflect-no-vary",
    category: "cors",
    title: "CORS Origin yansıtıyor ama Vary: Origin yok",
    severity: "LOW",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "ACAO dinamik olarak Origin'e göre değişiyor ama 'Vary: Origin' yok; ara önbellekler bir origin'in yanıtını başka bir origin'e sunarak önbellek zehirlenmesine yol açabilir.",
    remediation: "Origin'e göre değişen CORS yanıtlarında 'Vary: Origin' ekleyin.",
    references: [MDN_CORS],
    evaluate(ev) {
      const c = cors(ev);
      if (!c || !c.reflectsOrigin) return null;
      return /origin/i.test(c.vary) ? { status: "pass" } : { status: "fail", location: ev.target, evidence: `Vary: ${c.vary || "(yok)"}` };
    },
  },
];
