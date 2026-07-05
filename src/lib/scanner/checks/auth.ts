// Authentication / session-exposure checks from an unauthenticated view.
import type { Check, Evidence } from "./types";

const OWASP_AUTH = "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html";

function hasPasswordField(ev: Evidence): boolean {
  return /<input[^>]+type\s*=\s*["']?password/i.test(ev.root.body);
}

export const AUTH_CHECKS: Check[] = [
  {
    id: "auth-login-over-http",
    category: "auth-session",
    title: "Giriş formu düz HTTP üzerinde sunuluyor",
    severity: "HIGH",
    cwe: "CWE-319",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Parola alanı içeren bir sayfa HTTPS olmadan sunuluyor; kimlik bilgileri açık ağ üzerinden taşınır ve dinlenebilir.",
    remediation: "Tüm kimlik doğrulama sayfalarını HTTPS'e taşıyın ve HTTP'yi HTTPS'e yönlendirin.",
    references: [OWASP_AUTH],
    evaluate(ev) {
      if (!hasPasswordField(ev)) return null;
      return ev.root.url.startsWith("http://") ? { status: "fail", location: ev.root.url, confidence: "confirmed", evidence: "Parola alanı + http:// sayfa" } : { status: "pass" };
    },
  },
  {
    id: "auth-password-form-get",
    category: "auth-session",
    title: "Parola alanı GET yöntemli formda",
    severity: "HIGH",
    cwe: "CWE-598",
    owasp: "A04:2021 Insecure Design",
    description: "Parola içeren bir form GET kullanıyor; parola URL'ye (query string) yazılır, tarayıcı geçmişine, sunucu loglarına ve Referer başlığına sızar.",
    remediation: "Kimlik doğrulama formlarında POST kullanın.",
    references: [OWASP_AUTH],
    evaluate(ev) {
      if (!ev.forms.length) return null;
      const bad = ev.forms.filter((f) => f.method === "GET" && f.inputs.some((n) => /pass|pwd/i.test(n)));
      return bad.length ? { status: "fail", location: ev.root.url, confidence: "confirmed", evidence: bad.map((f) => f.action).join("\n") } : { status: "pass" };
    },
  },
  {
    id: "auth-basic-over-http",
    category: "auth-session",
    title: "HTTP Basic kimlik doğrulama şifresiz kanalda",
    severity: "HIGH",
    cwe: "CWE-319",
    owasp: "A07:2021 Identification and Authentication Failures",
    description: "Sunucu düz HTTP üzerinde Basic kimlik doğrulama istiyor; kimlik bilgileri base64 ile (şifrelenmeden) taşınır.",
    remediation: "Basic auth'u yalnızca HTTPS üzerinden kullanın; tercihen token/oturum tabanlı kimlik doğrulamaya geçin.",
    references: [OWASP_AUTH],
    evaluate(ev) {
      const wa = ev.root.headers["www-authenticate"] ?? "";
      if (!/basic/i.test(wa)) return null;
      return ev.root.url.startsWith("http://") ? { status: "fail", location: ev.root.url, confidence: "confirmed", evidence: `WWW-Authenticate: ${wa}` } : { status: "pass" };
    },
  },
  {
    id: "auth-token-in-localstorage",
    category: "auth-session",
    title: "Oturum token'ı localStorage'a yazılıyor",
    severity: "LOW",
    cwe: "CWE-922",
    owasp: "A07:2021 Identification and Authentication Failures",
    description: "İstemci JS'i token/jwt'yi localStorage/sessionStorage'a yazıyor gibi görünüyor; localStorage XSS ile okunabildiğinden oturum çalma riskini artırır.",
    remediation: "Oturum token'larını HttpOnly çerezlerde saklayın; hassas token'ları web depolamasına koymayın.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage"],
    confidence: "tentative",
    evaluate(ev) {
      const hit = ev.inlineScripts.find((s) => /(?:local|session)Storage\s*\.\s*setItem\s*\(\s*["'][^"']*(token|jwt|auth|session)/i.test(s));
      return hit ? { status: "fail", location: ev.root.url, confidence: "tentative", evidence: "localStorage.setItem('…token…', …)" } : { status: "pass" };
    },
  },
  {
    id: "auth-login-surface",
    category: "auth-session",
    title: "Kimlik doğrulama yüzeyi tespit edildi",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "A07:2021 Identification and Authentication Failures",
    description: "Sayfada bir parola alanı bulundu (giriş yüzeyi). Bilgilendirme amaçlıdır; brute-force koruması, MFA ve oran sınırlama uygulandığından emin olun.",
    remediation: "Giriş uçlarına oran sınırlama, hesap kilitleme ve MFA ekleyin.",
    references: [OWASP_AUTH],
    evaluate(ev) {
      return hasPasswordField(ev) ? { status: "fail", location: ev.root.url, confidence: "firm", evidence: "type=password alanı mevcut" } : { status: "pass" };
    },
  },
];
