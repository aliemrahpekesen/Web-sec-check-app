// Security-response-header checks. Each concern is one Check that fails on a
// concrete header state and passes when the header is present and correct, so
// the coverage report shows verified-good headers too.
import type { Check, CheckOutcome, Evidence } from "./types";

const MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers";
const OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/";

function H(ev: Evidence): Record<string, string> {
  return ev.root.headers;
}
function isHttps(ev: Evidence): boolean {
  return ev.root.url.startsWith("https://") || ev.scheme === "https";
}

export const HEADER_CHECKS: Check[] = [
  // --- HSTS -----------------------------------------------------------------
  {
    id: "hdr-hsts-missing",
    category: "headers",
    title: "HSTS (Strict-Transport-Security) başlığı eksik",
    severity: "MEDIUM",
    cwe: "CWE-319",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Strict-Transport-Security yok; tarayıcı kullanıcıyı HTTPS'e kilitlemez, ilk istek veya SSL-stripping düz HTTP üzerinden gerçekleşebilir.",
    remediation: "Tüm HTTPS yanıtlarına ekleyin: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    references: [`${MDN}/Strict-Transport-Security`],
    evaluate(ev) {
      if (!isHttps(ev)) return null;
      return H(ev)["strict-transport-security"] ? { status: "pass" } : { status: "fail", location: ev.root.url };
    },
  },
  {
    id: "hdr-hsts-short",
    category: "headers",
    title: "HSTS max-age çok kısa",
    severity: "LOW",
    cwe: "CWE-319",
    owasp: "A05:2021 Security Misconfiguration",
    description: "HSTS max-age 180 günün altında; kilitleme penceresi çok kısa, preload listesine de uygun değil (min 1 yıl gerekir).",
    remediation: "max-age değerini en az 31536000 (1 yıl), tercihen 63072000 (2 yıl) yapın.",
    references: ["https://hstspreload.org/"],
    evaluate(ev) {
      const v = H(ev)["strict-transport-security"];
      if (!v) return null;
      const age = Number(/max-age=(\d+)/i.exec(v)?.[1] ?? "0");
      return age > 0 && age < 15552000 ? { status: "fail", evidence: v, location: ev.root.url } : { status: "pass" };
    },
  },
  {
    id: "hdr-hsts-no-subdomains",
    category: "headers",
    title: "HSTS includeSubDomains yönergesi yok",
    severity: "LOW",
    cwe: "CWE-319",
    owasp: "A05:2021 Security Misconfiguration",
    description: "HSTS var ama includeSubDomains yok; alt alan adları HTTPS'e kilitlenmez.",
    remediation: "Tüm alt alan adları HTTPS destekliyorsa includeSubDomains ekleyin.",
    references: [`${MDN}/Strict-Transport-Security`],
    evaluate(ev) {
      const v = H(ev)["strict-transport-security"];
      if (!v) return null;
      return /includesubdomains/i.test(v) ? { status: "pass" } : { status: "fail", evidence: v, location: ev.root.url };
    },
  },
  {
    id: "hdr-hpkp-present",
    category: "headers",
    title: "Public-Key-Pins (HPKP) kullanılıyor",
    severity: "MEDIUM",
    cwe: "CWE-295",
    owasp: "A05:2021 Security Misconfiguration",
    description: "HPKP kullanımdan kaldırılmıştır ve yanlış yapılandırıldığında siteyi kalıcı olarak erişilemez hale getirebilir (ransom-pinning riski).",
    remediation: "Public-Key-Pins başlığını kaldırın; sertifika bütünlüğü için Certificate Transparency + CAA kullanın.",
    references: [`${MDN}/Public-Key-Pins`],
    evaluate(ev) {
      return H(ev)["public-key-pins"] ? { status: "fail", evidence: H(ev)["public-key-pins"], location: ev.root.url } : { status: "pass" };
    },
  },

  // --- X-Content-Type-Options ----------------------------------------------
  {
    id: "hdr-nosniff-missing",
    category: "headers",
    title: "X-Content-Type-Options: nosniff eksik",
    severity: "LOW",
    cwe: "CWE-693",
    owasp: "A05:2021 Security Misconfiguration",
    description: "nosniff yok; tarayıcı MIME sniffing ile bir dosyayı script olarak çalıştırabilir.",
    remediation: "Tüm yanıtlara ekleyin: X-Content-Type-Options: nosniff",
    references: [`${MDN}/X-Content-Type-Options`],
    evaluate(ev) {
      const v = H(ev)["x-content-type-options"];
      if (!v) return { status: "fail", location: ev.root.url };
      return /nosniff/i.test(v) ? { status: "pass" } : { status: "fail", evidence: v, severity: "LOW", location: ev.root.url, detail: "Başlık var ama değeri 'nosniff' değil." };
    },
  },

  // --- Clickjacking (X-Frame-Options / frame-ancestors) --------------------
  {
    id: "hdr-clickjacking",
    category: "headers",
    title: "Clickjacking koruması eksik",
    severity: "MEDIUM",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Sayfa ne X-Frame-Options ne de CSP frame-ancestors ile korunuyor; görünmez bir iframe içine alınıp kullanıcı kandırılarak tıklatılabilir.",
    remediation: "CSP: frame-ancestors 'none' (modern) + ek olarak X-Frame-Options: DENY (eski tarayıcılar).",
    references: [`${MDN}/X-Frame-Options`],
    evaluate(ev) {
      const h = H(ev);
      const csp = h["content-security-policy"] ?? "";
      if (h["x-frame-options"] || /frame-ancestors/i.test(csp)) return { status: "pass" };
      return { status: "fail", location: ev.root.url };
    },
  },
  {
    id: "hdr-xfo-allow-from",
    category: "headers",
    title: "X-Frame-Options ALLOW-FROM (kullanımdan kalkmış)",
    severity: "LOW",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "ALLOW-FROM çoğu modern tarayıcı tarafından yok sayılır; koruma etkisiz.",
    remediation: "CSP frame-ancestors <origin> kullanın.",
    references: [`${MDN}/X-Frame-Options`],
    evaluate(ev) {
      const v = H(ev)["x-frame-options"];
      if (!v) return null;
      return /allow-from/i.test(v) ? { status: "fail", evidence: v, location: ev.root.url } : { status: "pass" };
    },
  },

  // --- Referrer-Policy ------------------------------------------------------
  {
    id: "hdr-referrer-policy-missing",
    category: "headers",
    title: "Referrer-Policy eksik",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Referrer-Policy yok; URL'lerdeki token/oturum bilgisi Referer üzerinden dış sitelere sızabilir.",
    remediation: "Referrer-Policy: strict-origin-when-cross-origin (veya hassas uygulamalarda no-referrer).",
    references: [`${MDN}/Referrer-Policy`],
    evaluate(ev) {
      return H(ev)["referrer-policy"] ? { status: "pass" } : { status: "fail", location: ev.root.url };
    },
  },
  {
    id: "hdr-referrer-policy-unsafe",
    category: "headers",
    title: "Zayıf Referrer-Policy değeri",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Referrer-Policy 'unsafe-url' veya 'no-referrer-when-downgrade' tam URL'yi (query dahil) dış sitelere sızdırabilir.",
    remediation: "strict-origin-when-cross-origin veya daha katı bir değere geçin.",
    references: [`${MDN}/Referrer-Policy`],
    evaluate(ev) {
      const v = (H(ev)["referrer-policy"] ?? "").toLowerCase();
      if (!v) return null;
      return /unsafe-url|no-referrer-when-downgrade/.test(v) ? { status: "fail", evidence: v, location: ev.root.url } : { status: "pass" };
    },
  },

  // --- Permissions-Policy ---------------------------------------------------
  {
    id: "hdr-permissions-policy-missing",
    category: "headers",
    title: "Permissions-Policy eksik",
    severity: "LOW",
    cwe: "CWE-693",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Permissions-Policy yok; kamera/mikrofon/konum gibi güçlü API'ler varsayılan olarak kısıtlanmamış.",
    remediation: "Kullanmadığınız özellikleri kapatın: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    references: [`${MDN}/Permissions-Policy`],
    evaluate(ev) {
      return H(ev)["permissions-policy"] || H(ev)["feature-policy"] ? { status: "pass" } : { status: "fail", location: ev.root.url };
    },
  },
  {
    id: "hdr-feature-policy-deprecated",
    category: "headers",
    title: "Feature-Policy (kullanımdan kalkmış) kullanılıyor",
    severity: "INFO",
    cwe: "CWE-1104",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Feature-Policy başlığı Permissions-Policy ile değiştirilmiştir.",
    remediation: "Feature-Policy yerine Permissions-Policy kullanın.",
    references: [`${MDN}/Permissions-Policy`],
    evaluate(ev) {
      return H(ev)["feature-policy"] && !H(ev)["permissions-policy"] ? { status: "fail", evidence: H(ev)["feature-policy"], location: ev.root.url } : { status: "pass" };
    },
  },

  // --- Cross-Origin isolation ----------------------------------------------
  {
    id: "hdr-coop-missing",
    category: "headers",
    title: "Cross-Origin-Opener-Policy eksik",
    severity: "LOW",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "COOP yok; pencere referansları üzerinden çapraz-origin saldırıları (XS-Leaks, tabnabbing) mümkün olabilir.",
    remediation: "Cross-Origin-Opener-Policy: same-origin",
    references: [`${MDN}/Cross-Origin-Opener-Policy`],
    evaluate(ev) {
      return H(ev)["cross-origin-opener-policy"] ? { status: "pass" } : { status: "fail", location: ev.root.url };
    },
  },
  {
    id: "hdr-corp-missing",
    category: "headers",
    title: "Cross-Origin-Resource-Policy eksik",
    severity: "INFO",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "CORP yok; kaynak başka origin'lerce gömülebilir (Spectre türü side-channel yüzeyi).",
    remediation: "Cross-Origin-Resource-Policy: same-origin (veya same-site).",
    references: [`${MDN}/Cross-Origin-Resource-Policy`],
    evaluate(ev) {
      return H(ev)["cross-origin-resource-policy"] ? { status: "pass" } : { status: "fail", location: ev.root.url };
    },
  },

  // --- X-XSS-Protection -----------------------------------------------------
  {
    id: "hdr-xss-protection-enabled",
    category: "headers",
    title: "X-XSS-Protection etkin (önerilmez)",
    severity: "LOW",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Eski XSS denetleyicisi (X-XSS-Protection: 1) bazı tarayıcılarda yeni XSS vektörleri açabilir; modern tarayıcılar kaldırdı.",
    remediation: "X-XSS-Protection: 0 yapın ve korumayı CSP ile sağlayın.",
    references: [`${MDN}/X-XSS-Protection`],
    evaluate(ev) {
      const v = H(ev)["x-xss-protection"];
      if (!v) return null;
      return /^\s*1/.test(v) ? { status: "fail", evidence: v, location: ev.root.url } : { status: "pass" };
    },
  },

  // --- Version / tech disclosure via headers -------------------------------
  {
    id: "hdr-server-version",
    category: "headers",
    title: "Server başlığı sürüm ifşa ediyor",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Server başlığı yazılım sürümünü açığa çıkarıyor; hedefe özgü CVE'ler hızla bulunabilir.",
    remediation: "Sürümü gizleyin: nginx 'server_tokens off;', Apache 'ServerTokens Prod'.",
    references: [OWASP_HEADERS],
    evaluate(ev) {
      const v = H(ev)["server"];
      if (!v) return null;
      return /\d/.test(v) ? { status: "fail", evidence: `Server: ${v}`, location: ev.root.url } : { status: "pass" };
    },
  },
  {
    id: "hdr-x-powered-by",
    category: "headers",
    title: "X-Powered-By başlığı teknolojiyi ifşa ediyor",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "X-Powered-By kullanılan teknoloji/sürümü açığa çıkarır.",
    remediation: "Bu başlığı kaldırın (Express: app.disable('x-powered-by'); PHP: expose_php=Off).",
    references: [OWASP_HEADERS],
    evaluate(ev) {
      return H(ev)["x-powered-by"] ? { status: "fail", evidence: `X-Powered-By: ${H(ev)["x-powered-by"]}`, location: ev.root.url } : { status: "pass" };
    },
  },
  {
    id: "hdr-aspnet-version",
    category: "headers",
    title: "X-AspNet-Version ifşası",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: ".NET sürümü açığa çıkıyor.",
    remediation: "web.config: <httpRuntime enableVersionHeader=\"false\" />",
    references: [OWASP_HEADERS],
    evaluate(ev) {
      return H(ev)["x-aspnet-version"] ? { status: "fail", evidence: H(ev)["x-aspnet-version"], location: ev.root.url } : { status: "pass" };
    },
  },
  {
    id: "hdr-aspnetmvc-version",
    category: "headers",
    title: "X-AspNetMvc-Version ifşası",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "ASP.NET MVC sürümü açığa çıkıyor.",
    remediation: "MvcHandler.DisableMvcResponseHeader = true;",
    references: [OWASP_HEADERS],
    evaluate(ev) {
      return H(ev)["x-aspnetmvc-version"] ? { status: "fail", evidence: H(ev)["x-aspnetmvc-version"], location: ev.root.url } : { status: "pass" };
    },
  },
  {
    id: "hdr-x-generator",
    category: "headers",
    title: "X-Generator başlığı teknolojiyi ifşa ediyor",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "X-Generator CMS/oluşturucu bilgisini açığa çıkarır.",
    remediation: "Bu başlığı kaldırın.",
    references: [OWASP_HEADERS],
    evaluate(ev) {
      return H(ev)["x-generator"] ? { status: "fail", evidence: H(ev)["x-generator"], location: ev.root.url } : { status: "pass" };
    },
  },
  {
    id: "hdr-x-runtime",
    category: "headers",
    title: "X-Runtime zamanlama bilgisi sızdırıyor",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "X-Runtime (Rails) sunucu işlem süresini açığa çıkarır; zamanlama saldırılarına yardımcı olabilir ve Rails olduğunu ele verir.",
    remediation: "Rack::Runtime middleware'ini kaldırın.",
    references: [OWASP_HEADERS],
    evaluate(ev) {
      return H(ev)["x-runtime"] ? { status: "fail", evidence: `X-Runtime: ${H(ev)["x-runtime"]}`, location: ev.root.url } : { status: "pass" };
    },
  },
  {
    id: "hdr-via",
    category: "headers",
    title: "Via başlığı proxy/altyapı ifşa ediyor",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Via başlığı ara proxy'leri ve sürümlerini açığa çıkarabilir.",
    remediation: "Proxy yapılandırmasında Via başlığını gizleyin/kaldırın.",
    references: [`${MDN}/Via`],
    evaluate(ev) {
      return H(ev)["via"] ? { status: "fail", evidence: `Via: ${H(ev)["via"]}`, location: ev.root.url } : { status: "pass" };
    },
  },

  // --- Misc -----------------------------------------------------------------
  {
    id: "hdr-permitted-cross-domain",
    category: "headers",
    title: "X-Permitted-Cross-Domain-Policies eksik",
    severity: "INFO",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Adobe (Flash/PDF) çapraz-alan politikasını sınırlayan başlık yok.",
    remediation: "X-Permitted-Cross-Domain-Policies: none",
    references: [OWASP_HEADERS],
    evaluate(ev) {
      return H(ev)["x-permitted-cross-domain-policies"] ? { status: "pass" } : { status: "fail", location: ev.root.url };
    },
  },
  {
    id: "hdr-content-type-charset",
    category: "headers",
    title: "Content-Type charset belirtmiyor",
    severity: "LOW",
    cwe: "CWE-172",
    owasp: "A05:2021 Security Misconfiguration",
    description: "HTML yanıtında charset yok; tarayıcı yanlış kodlama tahmin ederse UTF-7 tarzı XSS'e yol açabilir.",
    remediation: "Content-Type: text/html; charset=utf-8",
    references: [`${MDN}/Content-Type`],
    evaluate(ev) {
      const ct = H(ev)["content-type"] ?? "";
      if (!/text\/html/i.test(ct)) return null;
      return /charset=/i.test(ct) ? { status: "pass" } : { status: "fail", evidence: `Content-Type: ${ct}`, location: ev.root.url };
    },
  },
  {
    id: "hdr-expect-ct-deprecated",
    category: "headers",
    title: "Expect-CT (kullanımdan kalkmış) kullanılıyor",
    severity: "INFO",
    cwe: "CWE-1104",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Expect-CT artık gereksizdir (CT tüm sertifikalar için zorunlu).",
    remediation: "Expect-CT başlığını kaldırın.",
    references: [`${MDN}/Expect-CT`],
    evaluate(ev) {
      return H(ev)["expect-ct"] ? { status: "fail", evidence: H(ev)["expect-ct"], location: ev.root.url } : { status: "pass" };
    },
  },
];
