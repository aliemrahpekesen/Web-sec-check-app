// Vulnerability knowledge base. Each check maps to a severity, CWE/OWASP
// reference, a plain-language description, and a remediation that includes a
// concrete, copy-pasteable example. This is what powers the "how to fix it,
// with examples" requirement of the final report. Both the deterministic
// engine and the Claude dynamic workflow draw remediation text from here so
// findings are consistent regardless of which engine ran.
import type { Severity } from "../types";

export interface KnowledgeEntry {
  title: string;
  severity: Severity;
  cwe?: string;
  owasp?: string;
  description: string;
  remediation: string;
}

export const KB: Record<string, KnowledgeEntry> = {
  "missing-hsts": {
    title: "HTTP Strict Transport Security (HSTS) başlığı eksik",
    severity: "MEDIUM",
    cwe: "CWE-319",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Strict-Transport-Security başlığı yok. Bu başlık olmadan tarayıcı, kullanıcıyı HTTPS'e kilitlemez; ilk istek veya SSL-stripping saldırısı (man-in-the-middle) düz HTTP üzerinden gerçekleşebilir.",
    remediation:
      "Tüm HTTPS yanıtlarına HSTS başlığı ekleyin (en az 6 ay):\n\n" +
      "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n" +
      "Nginx:\n  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n" +
      "Express (helmet):\n  app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));\n\n" +
      "Tüm alt alan adlarının HTTPS desteklediğinden emin olmadan includeSubDomains/preload eklemeyin.",
  },
  "missing-csp": {
    title: "Content-Security-Policy başlığı eksik",
    severity: "MEDIUM",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Content-Security-Policy (CSP) tanımlı değil. CSP, XSS ve veri enjeksiyonu saldırılarına karşı en güçlü tarayıcı tabanlı savunma katmanıdır; yokluğunda enjekte edilen scriptler kısıtlanmadan çalışır.",
    remediation:
      "Sıkı (nonce tabanlı) bir CSP tanımlayın ve gevşek 'unsafe-inline'dan kaçının:\n\n" +
      "  Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<rastgele>'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\n\n" +
      "Her yanıtta yeni bir nonce üretin ve inline scriptlere ekleyin:\n" +
      "  <script nonce=\"<rastgele>\">...</script>\n\n" +
      "Önce Content-Security-Policy-Report-Only ile devreye alıp ihlalleri toplayın, sonra zorunlu moda geçin.",
  },
  "missing-x-content-type-options": {
    title: "X-Content-Type-Options başlığı eksik",
    severity: "LOW",
    cwe: "CWE-693",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "X-Content-Type-Options: nosniff yok. Tarayıcı içerik türünü tahmin ederek (MIME sniffing) bir dosyayı script olarak çalıştırabilir; bu da bazı XSS ve içerik karıştırma saldırılarını mümkün kılar.",
    remediation:
      "Tüm yanıtlara ekleyin:\n\n  X-Content-Type-Options: nosniff\n\n" +
      "Nginx: add_header X-Content-Type-Options \"nosniff\" always;\nExpress: app.use(helmet.noSniff());",
  },
  "missing-x-frame-options": {
    title: "Clickjacking koruması eksik (X-Frame-Options / frame-ancestors)",
    severity: "MEDIUM",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Sayfa, X-Frame-Options veya CSP frame-ancestors yönergesiyle korunmuyor. Saldırgan sayfayı görünmez bir iframe içine alıp kullanıcıyı kandırarak tıklatabilir (clickjacking).",
    remediation:
      "Modern yöntem CSP frame-ancestors'tır:\n\n  Content-Security-Policy: frame-ancestors 'none';\n\n" +
      "Eski tarayıcılar için ek olarak:\n  X-Frame-Options: DENY\n\n" +
      "Sayfanın gömülmesi gerekiyorsa 'none' yerine güvendiğiniz origin'leri listeleyin.",
  },
  "missing-referrer-policy": {
    title: "Referrer-Policy başlığı eksik",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Referrer-Policy tanımlı değil. URL'lerde taşınan token/oturum bilgisi, dış sitelere Referer başlığı üzerinden sızabilir.",
    remediation:
      "Sızıntıyı en aza indiren bir politika belirleyin:\n\n  Referrer-Policy: strict-origin-when-cross-origin\n\n" +
      "Hassas uygulamalarda 'no-referrer' tercih edilebilir.",
  },
  "missing-permissions-policy": {
    title: "Permissions-Policy başlığı eksik",
    severity: "LOW",
    cwe: "CWE-693",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Permissions-Policy yok. Kamera, mikrofon, konum gibi güçlü tarayıcı API'leri varsayılan olarak kısıtlanmamış durumda; bir XSS bunları kötüye kullanabilir.",
    remediation:
      "Kullanmadığınız özellikleri kapatın:\n\n  Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()\n",
  },
  "weak-csp": {
    title: "Zayıf Content-Security-Policy",
    severity: "MEDIUM",
    cwe: "CWE-1021",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "CSP mevcut ancak zayıf yönergeler içeriyor (ör. script-src 'unsafe-inline'/'unsafe-eval', joker '*' kaynak, ya da object-src kilidi yok). Bu durumda enjekte edilen scriptler yine çalışabilir; CSP'nin XSS koruması büyük ölçüde etkisiz kalır.",
    remediation:
      "'unsafe-inline'/'unsafe-eval' yerine nonce/hash + 'strict-dynamic' kullanın ve kaynakları kısıtlayın:\n\n" +
      "  Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<rastgele>' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\n\n" +
      "Her yanıtta yeni nonce üretin. Önce Report-Only ile ölçüp sonra zorunlu moda geçin.",
  },
  "insecure-samesite-none": {
    title: "SameSite=None çerezi Secure bayrağı olmadan",
    severity: "MEDIUM",
    cwe: "CWE-614",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Bir çerez SameSite=None ile ayarlanmış ama Secure bayrağı yok. Modern tarayıcılar SameSite=None çerezleri yalnızca Secure ise kabul eder; aksi halde çerez düz HTTP'de sızabilir ve CSRF korumasını kaybeder.",
    remediation: "SameSite=None kullanıyorsanız Secure'u da ekleyin:\n\n  Set-Cookie: session=...; SameSite=None; Secure; HttpOnly; Path=/\n\n" +
      "Çapraz-site akışı gerekmiyorsa SameSite=Lax veya Strict tercih edin.",
  },
  "tls-untrusted": {
    title: "Geçersiz/güvenilmeyen TLS sertifikası",
    severity: "HIGH",
    cwe: "CWE-295",
    owasp: "A02:2021 Cryptographic Failures",
    description:
      "Sunucunun TLS sertifikası doğrulanamadı (kendinden imzalı, süresi dolmuş, ana bilgisayar adı uyuşmuyor veya bilinmeyen CA). Tarayıcılar bağlantıyı engeller; kullanıcılar uyarıya maruz kalır ve MITM riski artar.",
    remediation:
      "Güvenilir bir CA'dan (ör. Let's Encrypt) geçerli, host adıyla eşleşen bir sertifika kurun ve tam zinciri (fullchain) sunun:\n\n  certbot --nginx -d example.com\n\n" +
      "Otomatik yenilemeyi (certbot renew) etkinleştirin.",
  },
  "sri-missing": {
    title: "Dış scriptlerde Subresource Integrity (SRI) yok",
    severity: "LOW",
    cwe: "CWE-353",
    owasp: "A08:2021 Software and Data Integrity Failures",
    description:
      "Sayfa, başka bir origin'den (ör. CDN) integrity özniteliği olmadan script yüklüyor. CDN ele geçirilir veya değiştirilirse, sayfada keyfi kod çalışabilir.",
    remediation:
      "Dış script/stil etiketlerine SRI hash'i ve crossorigin ekleyin:\n\n" +
      "  <script src=\"https://cdn.example.com/lib.js\"\n          integrity=\"sha384-<hash>\" crossorigin=\"anonymous\"></script>\n\n" +
      "Hash üretimi:  openssl dgst -sha384 -binary lib.js | openssl base64 -A",
  },
  "insecure-cookie": {
    title: "Çerez güvenlik bayrakları eksik (Secure / HttpOnly / SameSite)",
    severity: "MEDIUM",
    cwe: "CWE-614",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Bir veya daha fazla çerezde Secure, HttpOnly veya SameSite bayrağı eksik. HttpOnly olmayan çerezler XSS ile çalınabilir; Secure olmayanlar düz HTTP'de sızar; SameSite olmayanlar CSRF'e açıktır.",
    remediation:
      "Oturum çerezlerini tüm bayraklarla ayarlayın:\n\n" +
      "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/\n\n" +
      "Express: res.cookie('session', v, { secure: true, httpOnly: true, sameSite: 'lax' });\n" +
      "Çapraz-site akışı yoksa SameSite=Strict daha güvenlidir.",
  },
  "no-https": {
    title: "Site HTTPS'e yönlendirmiyor / düz HTTP erişilebilir",
    severity: "HIGH",
    cwe: "CWE-319",
    owasp: "A02:2021 Cryptographic Failures",
    description:
      "Düz HTTP üzerinden gelen istek HTTPS'e yönlendirilmiyor. Trafik şifrelenmeden taşınabilir; kimlik bilgileri ve oturum çerezleri ağda dinlenebilir.",
    remediation:
      "Tüm HTTP trafiğini kalıcı olarak HTTPS'e yönlendirin ve ardından HSTS uygulayın.\n\n" +
      "Nginx:\n  server { listen 80; server_name example.com; return 301 https://$host$request_uri; }\n",
  },
  "tls-expired": {
    title: "TLS sertifikası süresi dolmuş veya yakında dolacak",
    severity: "HIGH",
    cwe: "CWE-298",
    owasp: "A02:2021 Cryptographic Failures",
    description:
      "Sunucunun TLS sertifikası süresi dolmuş ya da çok yakında dolacak. Tarayıcılar bağlantıyı engelleyerek kullanıcıları güvenlik uyarısına maruz bırakır.",
    remediation:
      "Sertifikayı yenileyin ve otomatik yenilemeyi kurun (ör. certbot):\n\n  certbot renew --quiet\n\n" +
      "Yenilemeyi izlemek için sertifika süresi için uyarı (monitoring) ekleyin.",
  },
  "tls-weak": {
    title: "Zayıf TLS yapılandırması",
    severity: "MEDIUM",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description:
      "Sunucu eski protokol sürümlerini (TLS 1.0/1.1) veya zayıf şifre takımlarını destekliyor olabilir. Bu, bağlantının düşürülerek kırılmasını kolaylaştırır.",
    remediation:
      "Yalnızca TLS 1.2+ ve modern şifre takımlarına izin verin (Mozilla 'intermediate' profili).\n\n" +
      "Nginx:\n  ssl_protocols TLSv1.2 TLSv1.3;\n  ssl_prefer_server_ciphers off;\n",
  },
  "server-version-disclosure": {
    title: "Sunucu/teknoloji sürümü ifşa ediliyor",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Server / X-Powered-By gibi başlıklar tam sürüm bilgisini açığa çıkarıyor. Saldırgan bu bilgiyle hedefe özgü bilinen açıkları (CVE) hızla bulabilir.",
    remediation:
      "Sürüm bilgisini gizleyin:\n\nNginx: server_tokens off;\n" +
      "Express: app.disable('x-powered-by');\nApache: ServerTokens Prod  /  ServerSignature Off\n",
  },
  "directory-listing": {
    title: "Dizin listeleme açık",
    severity: "MEDIUM",
    cwe: "CWE-548",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Bir dizin, dosya listesini doğrudan gösteriyor. Yedekler, kaynak kodu veya yapılandırma dosyaları bu yolla keşfedilebilir.",
    remediation:
      "Dizin listelemeyi kapatın:\n\nNginx: autoindex off;\nApache: Options -Indexes\n",
  },
  "sensitive-file-exposed": {
    title: "Hassas dosya/dizin erişilebilir",
    severity: "CRITICAL",
    cwe: "CWE-538",
    owasp: "A01:2021 Broken Access Control",
    description:
      "Gizli kalması gereken bir dosya veya dizin (ör. .env, .git/, yedek dosyası) genel erişime açık. İçinde gizli anahtarlar, veritabanı kimlik bilgileri veya kaynak kodu bulunabilir.",
    remediation:
      "Dosyayı derhal kaldırın/erişimi engelleyin ve içindeki tüm sırları döndürün (rotate).\n\n" +
      "Nginx:\n  location ~ /\\.(env|git) { deny all; return 404; }\n\n" +
      "Sırları ortam değişkenleri veya bir secret manager üzerinden yönetin; depoya koymayın.",
  },
  "mixed-content": {
    title: "Karışık içerik (HTTPS sayfada HTTP kaynak)",
    severity: "MEDIUM",
    cwe: "CWE-311",
    owasp: "A02:2021 Cryptographic Failures",
    description:
      "HTTPS sayfa, düz HTTP üzerinden script/stil/görsel yüklüyor. Bu kaynaklar değiştirilebilir ve sayfanın güvenliğini bozabilir.",
    remediation:
      "Tüm alt kaynakları HTTPS'e taşıyın ve tarayıcıya yükseltme talimatı verin:\n\n" +
      "  Content-Security-Policy: upgrade-insecure-requests\n",
  },
  "reflected-xss": {
    title: "Olası yansıyan XSS (Cross-Site Scripting)",
    severity: "HIGH",
    cwe: "CWE-79",
    owasp: "A03:2021 Injection",
    description:
      "Bir parametreye gönderilen değer, çıktıya kodlanmadan yansıtılıyor. Saldırgan, kurbanın tarayıcısında script çalıştırabilir (oturum çalma, sahte form vb.).",
    remediation:
      "Çıktıyı bağlama göre kodlayın (HTML/attr/JS) ve girdiyi doğrulayın. Şablon motorlarının otomatik kaçışını kapatmayın.\n\n" +
      "  // React zaten kaçış yapar; dangerouslySetInnerHTML kullanmayın\n" +
      "  // Sunucu tarafı: const safe = escapeHtml(userInput)\n\n" +
      "Ek katman olarak nonce tabanlı CSP uygulayın.",
  },
  "open-redirect": {
    title: "Açık yönlendirme (Open Redirect)",
    severity: "MEDIUM",
    cwe: "CWE-601",
    owasp: "A01:2021 Broken Access Control",
    description:
      "Bir parametre, doğrulanmadan harici bir adrese yönlendiriyor. Kimlik avı (phishing) ve OAuth token sızdırma için kötüye kullanılabilir.",
    remediation:
      "Yönlendirme hedefini bir allowlist'e karşı doğrulayın veya yalnızca göreli yollara izin verin.\n\n" +
      "  const allowed = new Set(['/dashboard', '/home']);\n  if (!allowed.has(target)) target = '/';\n",
  },
  "cors-misconfig": {
    title: "Tehlikeli CORS yapılandırması",
    severity: "HIGH",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Access-Control-Allow-Origin yanıtı, isteğin Origin'ini yansıtırken Access-Control-Allow-Credentials: true gönderiyor (veya '*' ile birlikte). Bu, herhangi bir sitenin kimlik bilgileriyle API'ye erişebilmesi anlamına gelir.",
    remediation:
      "Origin'i yansıtmayın; statik bir allowlist kullanın ve yalnızca gerekiyorsa credentials açın.\n\n" +
      "  const allow = new Set(['https://app.example.com']);\n" +
      "  if (allow.has(origin)) res.setHeader('Access-Control-Allow-Origin', origin);\n",
  },
  "outdated-library": {
    title: "Eski/savunmasız istemci kütüphanesi",
    severity: "MEDIUM",
    cwe: "CWE-1104",
    owasp: "A06:2021 Vulnerable and Outdated Components",
    description:
      "Sayfada bilinen açıkları olabilecek eski bir JavaScript kütüphanesi yüklü görünüyor.",
    remediation:
      "Kütüphaneyi güncel sürüme yükseltin ve bağımlılıkları sürekli tarayın:\n\n  npm audit fix\n  npm outdated\n\n" +
      "CI'a otomatik bağımlılık denetimi (ör. Dependabot) ekleyin.",
  },
  "missing-cache-control": {
    title: "Hassas yanıtta önbellek kontrolü eksik",
    severity: "LOW",
    cwe: "CWE-525",
    owasp: "A04:2021 Insecure Design",
    description:
      "Kimlik doğrulamalı/hassas görünen yanıtta Cache-Control yok. Vekil sunucular veya paylaşılan tarayıcı önbelleği hassas içeriği saklayabilir.",
    remediation:
      "Hassas yanıtlarda önbelleği kapatın:\n\n  Cache-Control: no-store\n",
  },
};

export function kbEntry(checkId: string): KnowledgeEntry | undefined {
  return KB[checkId];
}
