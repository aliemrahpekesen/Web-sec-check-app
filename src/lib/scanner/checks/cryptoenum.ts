// TLS protocol/cipher enumeration, HSTS preload eligibility, and subdomain
// takeover detection. These are DEEP-profile enumeration checks (except the
// passive HSTS-preload assessment) driven by the shared evidence snapshot.
//
// Framework-neutral: pure `evaluate` functions over `Evidence`. No side effects.
import type { Check } from "./types";

// --- reference URLs -------------------------------------------------------
const MOZ_TLS = "https://ssl-config.mozilla.org/";
const HSTS_PRELOAD = "https://hstspreload.org/";
const OWASP_TAKEOVER = "https://owasp.org/www-community/attacks/Subdomain_takeover";
const PORTSWIGGER_TAKEOVER = "https://portswigger.net/web-security/dom-based";

// --- helpers --------------------------------------------------------------

// True only when a real protocol/cipher enumeration was performed. Every
// tlsMatrix-backed check MUST return null otherwise (evidence absent).
function matrixTested(ev: {
  tlsMatrix: { tested: boolean } | null;
}): boolean {
  return ev.tlsMatrix != null && ev.tlsMatrix.tested === true;
}

function isHttps(ev: { scheme: string; root: { url: string } }): boolean {
  return ev.scheme === "https" || ev.root.url.startsWith("https://");
}

// --- subdomain-takeover provider table ------------------------------------
// Each entry: a CNAME substring that routes to a takeover-prone provider, plus
// the "dangling" body signatures that provider serves when the target resource
// (page/app/bucket) no longer exists — i.e. a claimable name.
interface TakeoverProvider {
  name: string;
  cname: string; // substring matched against each CNAME in the chain
  signatures: string[]; // dangling-resource body markers (matched lowercased)
}

const TAKEOVER_PROVIDERS: TakeoverProvider[] = [
  { name: "GitHub Pages", cname: "github.io", signatures: ["there isn't a github pages site here", "for root urls (like http://example.com/) you must provide an index.html file"] },
  { name: "Heroku", cname: "herokuapp.com", signatures: ["no such app", "no-such-app", "herokucdn.com/error-pages/no-such-app.html"] },
  { name: "Amazon S3", cname: "s3.amazonaws.com", signatures: ["nosuchbucket", "the specified bucket does not exist"] },
  { name: "Amazon S3 Website", cname: "s3-website", signatures: ["nosuchbucket", "the specified bucket does not exist"] },
  { name: "Azure App Service", cname: "azurewebsites.net", signatures: ["404 web site not found", "error 404 - web app not found"] },
  { name: "Amazon CloudFront", cname: "cloudfront.net", signatures: ["the request could not be satisfied", "error: the request"] },
  { name: "Netlify", cname: "netlify.app", signatures: ["not found - request id"] },
  { name: "Netlify (legacy)", cname: "netlify.com", signatures: ["not found - request id"] },
  { name: "Fastly", cname: "fastly", signatures: ["fastly error: unknown domain"] },
  { name: "Pantheon", cname: "pantheonsite.io", signatures: ["the gods are wise", "404 error unknown site"] },
  { name: "WP Engine", cname: "wpengine.com", signatures: ["the site you were looking for couldn't be found"] },
  { name: "Ghost", cname: "ghost.io", signatures: ["the thing you were looking for is no longer here", "domain error"] },
  { name: "Bitbucket", cname: "bitbucket.io", signatures: ["repository not found", "the page you have requested does not exist"] },
  { name: "Surge.sh", cname: "surge.sh", signatures: ["project not found", "404 - not found"] },
  { name: "Read the Docs", cname: "readthedocs.io", signatures: ["unknown domain", "404 not found"] },
  { name: "Zendesk", cname: "zendesk.com", signatures: ["help center closed", "this help center no longer exists"] },
  { name: "Help Scout", cname: "helpscoutdocs.com", signatures: ["no settings were found for this company"] },
  { name: "Unbounce", cname: "unbounce.com", signatures: ["the requested url was not found on this server"] },
  { name: "Tumblr", cname: "tumblr.com", signatures: ["there's nothing here.", "whatever you were looking for doesn't currently exist at this address"] },
];

interface TakeoverMatch {
  provider: TakeoverProvider;
  cname: string;
  signature?: string; // present only when a dangling signature was observed
}

// Correlate the CNAME chain against the provider table + the fetched root body.
function matchTakeovers(cnames: string[], body: string, status: number): TakeoverMatch[] {
  const lowerBody = body.toLowerCase();
  const out: TakeoverMatch[] = [];
  for (const raw of cnames) {
    const cname = raw.toLowerCase();
    for (const provider of TAKEOVER_PROVIDERS) {
      if (!cname.includes(provider.cname)) continue;
      const hit = provider.signatures.find(
        (sig) => lowerBody.includes(sig) || (status === 404 && lowerBody.includes(sig)),
      );
      out.push({ provider, cname: raw, signature: hit });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------

export const CRYPTO_ENUM_CHECKS: Check[] = [
  // --- TLS protocol enumeration (category "crypto", DEEP-only) -----------
  {
    id: "tlsm-tls10-enabled",
    category: "crypto",
    title: "TLS 1.0 etkin",
    severity: "HIGH",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sunucu TLS 1.0 el sıkışmasını tamamlıyor. TLS 1.0 kullanımdan kaldırıldı (RFC 8996), PCI-DSS tarafından yasaklı ve BEAST/POODLE gibi saldırılara açıktır.",
    remediation: "Sunucu yapılandırmasında TLS 1.0'ı devre dışı bırakın; yalnızca TLS 1.2 ve 1.3'e izin verin (Mozilla 'intermediate' profili).",
    references: [MOZ_TLS],
    profiles: ["DEEP"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!matrixTested(ev)) return null;
      return ev.tlsMatrix!.protocols["TLSv1"] === true
        ? { status: "fail", location: `https://${ev.host}`, evidence: "Protokol: TLSv1.0 el sıkışması başarılı" }
        : { status: "pass" };
    },
  },
  {
    id: "tlsm-tls11-enabled",
    category: "crypto",
    title: "TLS 1.1 etkin",
    severity: "HIGH",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sunucu TLS 1.1 el sıkışmasını tamamlıyor. TLS 1.1 kullanımdan kaldırıldı (RFC 8996) ve modern uyumluluk gereksinimlerini karşılamaz.",
    remediation: "TLS 1.1'i devre dışı bırakın; yalnızca TLS 1.2 ve 1.3'e izin verin.",
    references: [MOZ_TLS],
    profiles: ["DEEP"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!matrixTested(ev)) return null;
      return ev.tlsMatrix!.protocols["TLSv1.1"] === true
        ? { status: "fail", location: `https://${ev.host}`, evidence: "Protokol: TLSv1.1 el sıkışması başarılı" }
        : { status: "pass" };
    },
  },
  {
    id: "tlsm-tls12-enabled",
    category: "crypto",
    title: "TLS 1.2 destekleniyor",
    severity: "INFO",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sunucu TLS 1.2 el sıkışmasını destekliyor. Bu bir güvenlik açığı değil, uyumluluk tespitidir.",
    remediation: "TLS 1.2'yi (TLS 1.3 ile birlikte) korumaya devam edin; daha eski sürümleri kapatın.",
    references: [MOZ_TLS],
    profiles: ["DEEP"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!matrixTested(ev)) return null;
      // Not a finding: report pass on support, null when unsupported.
      return ev.tlsMatrix!.protocols["TLSv1.2"] === true ? { status: "pass" } : null;
    },
  },
  {
    id: "tlsm-tls13-missing",
    category: "crypto",
    title: "TLS 1.3 desteklenmiyor",
    severity: "LOW",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sunucu TLS 1.2 destekliyor ancak TLS 1.3'ü desteklemiyor. TLS 1.3 daha hızlı el sıkışma ve modern, zorunlu ileri gizlilik sağlar.",
    remediation: "Sunucu ve kütüphaneleri güncelleyip TLS 1.3'ü etkinleştirin.",
    references: [MOZ_TLS],
    profiles: ["DEEP"],
    confidence: "firm",
    evaluate(ev) {
      if (!matrixTested(ev)) return null;
      const p = ev.tlsMatrix!.protocols;
      if (p["TLSv1.3"] === true) return { status: "pass" };
      // Only meaningful when 1.2 is present (the "modern-but-no-1.3" case).
      if (p["TLSv1.2"] === true) {
        return { status: "fail", location: `https://${ev.host}`, evidence: "TLSv1.3 el sıkışması başarısız; yalnızca TLSv1.2 destekleniyor" };
      }
      return null;
    },
  },
  {
    id: "tlsm-only-old",
    category: "crypto",
    title: "Yalnızca eski TLS sürümleri (1.0/1.1) destekleniyor",
    severity: "CRITICAL",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sunucu ne TLS 1.2 ne de TLS 1.3'ü destekliyor; yalnızca kullanımdan kaldırılmış TLS 1.0/1.1 sunuluyor. Modern tarayıcılar bağlantıyı reddeder ve iletişim ciddi şekilde zayıftır.",
    remediation: "Acilen TLS 1.2 ve TLS 1.3 desteğini etkinleştirin; eski sürümleri kapatın.",
    references: [MOZ_TLS],
    profiles: ["DEEP"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!matrixTested(ev)) return null;
      const p = ev.tlsMatrix!.protocols;
      const modern = p["TLSv1.2"] === true || p["TLSv1.3"] === true;
      if (modern) return { status: "pass" };
      const old = p["TLSv1"] === true || p["TLSv1.1"] === true;
      // Only fail when *some* handshake succeeded but all were old.
      return old
        ? { status: "fail", location: `https://${ev.host}`, evidence: "Desteklenen protokoller yalnızca TLSv1.0/1.1" }
        : null;
    },
  },
  {
    id: "tlsm-weak-cipher-offered",
    category: "crypto",
    title: "Zayıf şifre paketi sunuluyor",
    severity: "HIGH",
    cwe: "CWE-327",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sunucu zayıf şifre paketleri (RC4, 3DES, NULL veya EXPORT sınıfı) ile el sıkışmayı tamamlıyor. Bu paketler kırılabilir ve şifrelemeyi anlamsız kılar.",
    remediation: "Zayıf şifre paketlerini kaldırın; yalnızca AEAD (AES-GCM, ChaCha20-Poly1305) paketlerine izin verin (Mozilla önerileri).",
    references: [MOZ_TLS],
    profiles: ["DEEP"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!matrixTested(ev)) return null;
      const weak = ev.tlsMatrix!.weakCiphersOffered;
      return weak.length > 0
        ? { status: "fail", location: `https://${ev.host}`, evidence: `Zayıf paketler: ${weak.join(", ")}` }
        : { status: "pass" };
    },
  },
  {
    id: "tlsm-no-forward-secrecy",
    category: "crypto",
    title: "İleri gizlilik (forward secrecy) yok",
    severity: "MEDIUM",
    cwe: "CWE-310",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Modern el sıkışmada ECDHE/DHE anahtar değişimi kullanılmıyor; ileri gizlilik sağlanmıyor. Sunucu özel anahtarı ele geçirilirse geçmiş tüm trafik çözülebilir.",
    remediation: "ECDHE (tercihen) veya DHE tabanlı şifre paketlerini etkinleştirin ve önceliklendirin.",
    references: [MOZ_TLS],
    profiles: ["DEEP"],
    confidence: "firm",
    evaluate(ev) {
      if (!matrixTested(ev)) return null;
      return ev.tlsMatrix!.forwardSecrecy === false
        ? { status: "fail", location: `https://${ev.host}`, evidence: "Modern el sıkışmada ECDHE/DHE paketi görülmedi" }
        : { status: "pass" };
    },
  },

  // --- HSTS preload eligibility (category "headers", all profiles) --------
  {
    id: "hsts-preload-ineligible",
    category: "headers",
    title: "HSTS başlığı preload listesine uygun değil",
    severity: "LOW",
    cwe: "CWE-319",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Strict-Transport-Security başlığı mevcut ancak preload gereksinimlerini karşılamıyor: max-age en az 31536000 (1 yıl) olmalı, includeSubDomains ve preload direktifleri bulunmalıdır. Uygun olmayan başlık hstspreload.org listesine eklenemez.",
    remediation: "Başlığı şu forma getirin: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' ve alan adını hstspreload.org üzerinden gönderin.",
    references: [HSTS_PRELOAD],
    confidence: "firm",
    evaluate(ev) {
      if (!isHttps(ev)) return null;
      const raw = ev.root.headers["strict-transport-security"];
      if (!raw) return null; // no HSTS at all — reported by a separate check.
      const value = raw.toLowerCase();
      const reasons: string[] = [];
      const maxAgeMatch = value.match(/max-age\s*=\s*(\d+)/);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 31536000) reasons.push(`max-age=${maxAge} (< 31536000)`);
      if (!/includesubdomains/.test(value)) reasons.push("includeSubDomains eksik");
      if (!/;\s*preload/.test(value) && !/\bpreload\b/.test(value)) reasons.push("preload direktifi eksik");
      if (reasons.length === 0) return { status: "pass" };
      return { status: "fail", location: ev.root.url, evidence: `HSTS: «${raw}» — ${reasons.join("; ")}` };
    },
  },

  // --- Subdomain takeover (category "dns-email", DEEP-only) ---------------
  {
    id: "takeover-dangling",
    category: "dns-email",
    title: "Askıda kalan CNAME — alt alan adı devralınabilir",
    severity: "HIGH",
    cwe: "CWE-350",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Bir CNAME, devralmaya açık bir sağlayıcıya işaret ediyor ve o sağlayıcının 'kaynak bulunamadı' imzasını döndürüyor. Saldırgan sağlayıcıda ilgili kaynağı (sayfa/uygulama/bucket) oluşturarak alt alan adını ele geçirebilir.",
    remediation: "Kullanılmayan CNAME kaydını DNS'ten kaldırın veya ilgili kaynağı sağlayıcıda yeniden talep edin. Askıda DNS kayıtlarını düzenli olarak denetleyin.",
    references: [OWASP_TAKEOVER],
    profiles: ["DEEP"],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.cnames.length) return null;
      const matches = matchTakeovers(ev.cnames, ev.root.body, ev.root.status);
      if (!matches.length) return null; // no provider-pointing CNAME at all.
      const dangling = matches.filter((m) => m.signature);
      if (!dangling.length) return { status: "pass" }; // provider CNAME but live.
      return dangling.map((m) => ({
        status: "fail" as const,
        location: `https://${ev.host}`,
        confidence: "firm" as const,
        titleSuffix: ` — ${m.provider.name}`,
        evidence: `CNAME «${m.cname}» → ${m.provider.name}; askıda imza: «${m.signature}» (HTTP ${ev.root.status})`,
      }));
    },
  },
  {
    id: "takeover-cname-risky-provider",
    category: "dns-email",
    title: "CNAME devralmaya açık bir sağlayıcıya işaret ediyor",
    severity: "INFO",
    cwe: "CWE-350",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Bir CNAME, geçmişte alt alan adı devralma vakalarıyla ilişkilendirilmiş bir sağlayıcıya işaret ediyor. Şu an askıda bir imza görülmedi, ancak ilgili kaynak silinirse alan adı devralınabilir hale gelir; saldırı yüzeyi olarak izlenmelidir.",
    remediation: "Bu CNAME'in işaret ettiği kaynağın aktif olduğundan emin olun; kaynağı kaldırırken CNAME kaydını da silin.",
    references: [PORTSWIGGER_TAKEOVER],
    profiles: ["DEEP"],
    confidence: "tentative",
    evaluate(ev) {
      if (!ev.cnames.length) return null;
      const matches = matchTakeovers(ev.cnames, ev.root.body, ev.root.status);
      if (!matches.length) return null;
      const informational = matches.filter((m) => !m.signature);
      if (!informational.length) return { status: "pass" }; // all dangling → other check.
      return informational.map((m) => ({
        status: "fail" as const,
        location: `https://${ev.host}`,
        confidence: "tentative" as const,
        titleSuffix: ` — ${m.provider.name}`,
        evidence: `CNAME «${m.cname}» → ${m.provider.name} (devralmaya açık sağlayıcı)`,
      }));
    },
  },
  {
    id: "takeover-multiple-provider-cnames",
    category: "dns-email",
    title: "Birden çok devralmaya açık sağlayıcı CNAME'i",
    severity: "INFO",
    cwe: "CWE-350",
    owasp: "A05:2021 Security Misconfiguration",
    description: "CNAME zincirinde devralmaya açık birden fazla sağlayıcı görülüyor. Uzun/çoklu CNAME zincirleri askıda kalma riskini ve devralma saldırı yüzeyini artırır.",
    remediation: "CNAME zincirini sadeleştirin ve her bağlantının aktif bir kaynağa çözümlendiğini doğrulayın.",
    references: [OWASP_TAKEOVER],
    profiles: ["DEEP"],
    confidence: "tentative",
    evaluate(ev) {
      if (!ev.cnames.length) return null;
      const matches = matchTakeovers(ev.cnames, ev.root.body, ev.root.status);
      const providerNames = Array.from(new Set(matches.map((m) => m.provider.name)));
      if (providerNames.length < 2) return providerNames.length === 1 ? { status: "pass" } : null;
      return {
        status: "fail",
        location: `https://${ev.host}`,
        evidence: `Sağlayıcılar: ${providerNames.join(", ")} (CNAME: ${ev.cnames.join(" → ")})`,
      };
    },
  },
  {
    id: "takeover-long-cname-chain",
    category: "dns-email",
    title: "Uzun CNAME zinciri",
    severity: "INFO",
    cwe: "CWE-350",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Host, üç veya daha fazla halkadan oluşan bir CNAME zinciriyle çözümleniyor. Uzun zincirler yanlış yapılandırma ve askıda kalma olasılığını artırır; ayrıca DNS çözümleme gecikmesi yaratır.",
    remediation: "CNAME zincirini kısaltın; gereksiz aracı kayıtları kaldırın.",
    references: [OWASP_TAKEOVER],
    profiles: ["DEEP"],
    confidence: "tentative",
    evaluate(ev) {
      if (!ev.cnames.length) return null;
      return ev.cnames.length >= 3
        ? { status: "fail", location: ev.host, evidence: `CNAME zinciri (${ev.cnames.length}): ${ev.cnames.join(" → ")}` }
        : { status: "pass" };
    },
  },
  {
    id: "takeover-s3-bucket-dangling",
    category: "dns-email",
    title: "Askıda Amazon S3 bucket CNAME'i",
    severity: "HIGH",
    cwe: "CWE-350",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Bir CNAME Amazon S3'e işaret ediyor ve yanıt gövdesi 'NoSuchBucket' hatası içeriyor. Saldırgan aynı isimli bir S3 bucket oluşturarak alt alan adını devralabilir.",
    remediation: "S3 bucket'ı yeniden oluşturun veya CNAME kaydını silin. Bucket adlarını global olarak ayırtın.",
    references: [OWASP_TAKEOVER],
    profiles: ["DEEP"],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.cnames.length) return null;
      const pointsToS3 = ev.cnames.some((c) => /s3[.-]|amazonaws\.com/i.test(c));
      if (!pointsToS3) return null;
      const body = ev.root.body.toLowerCase();
      const dangling = body.includes("nosuchbucket") || body.includes("the specified bucket does not exist");
      return dangling
        ? { status: "fail", location: `https://${ev.host}`, confidence: "firm", evidence: `S3 CNAME askıda: «NoSuchBucket» (HTTP ${ev.root.status})` }
        : { status: "pass" };
    },
  },
  {
    id: "takeover-github-pages-dangling",
    category: "dns-email",
    title: "Askıda GitHub Pages CNAME'i",
    severity: "HIGH",
    cwe: "CWE-350",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Bir CNAME GitHub Pages'e işaret ediyor ve yanıt 'There isn't a GitHub Pages site here' imzasını içeriyor. Saldırgan bir GitHub deposu + Pages sitesi oluşturarak alt alan adını devralabilir.",
    remediation: "GitHub Pages sitesini yeniden yayınlayın veya CNAME kaydını kaldırın.",
    references: [OWASP_TAKEOVER],
    profiles: ["DEEP"],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.cnames.length) return null;
      const pointsToGh = ev.cnames.some((c) => /github\.io/i.test(c));
      if (!pointsToGh) return null;
      const dangling = ev.root.body.toLowerCase().includes("there isn't a github pages site here");
      return dangling
        ? { status: "fail", location: `https://${ev.host}`, confidence: "firm", evidence: `GitHub Pages CNAME askıda (HTTP ${ev.root.status})` }
        : { status: "pass" };
    },
  },
  {
    id: "takeover-heroku-dangling",
    category: "dns-email",
    title: "Askıda Heroku uygulaması CNAME'i",
    severity: "HIGH",
    cwe: "CWE-350",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Bir CNAME herokuapp.com'a işaret ediyor ve yanıt 'No such app' imzasını içeriyor. Saldırgan aynı isimli bir Heroku uygulaması oluşturarak alt alan adını devralabilir.",
    remediation: "Heroku uygulamasını yeniden oluşturun veya CNAME kaydını kaldırın; uygulama adlarını ayırtın.",
    references: [OWASP_TAKEOVER],
    profiles: ["DEEP"],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.cnames.length) return null;
      const pointsToHeroku = ev.cnames.some((c) => /herokuapp\.com/i.test(c));
      if (!pointsToHeroku) return null;
      const body = ev.root.body.toLowerCase();
      const dangling = body.includes("no such app") || body.includes("no-such-app");
      return dangling
        ? { status: "fail", location: `https://${ev.host}`, confidence: "firm", evidence: `Heroku CNAME askıda: «No such app» (HTTP ${ev.root.status})` }
        : { status: "pass" };
    },
  },
  {
    id: "takeover-azure-dangling",
    category: "dns-email",
    title: "Askıda Azure App Service CNAME'i",
    severity: "HIGH",
    cwe: "CWE-350",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Bir CNAME azurewebsites.net'e işaret ediyor ve yanıt '404 Web Site not found' imzasını içeriyor. Saldırgan aynı isimli bir Azure App Service oluşturarak alt alan adını devralabilir.",
    remediation: "Azure App Service'i yeniden oluşturun veya CNAME kaydını kaldırın.",
    references: [OWASP_TAKEOVER],
    profiles: ["DEEP"],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.cnames.length) return null;
      const pointsToAzure = ev.cnames.some((c) => /azurewebsites\.net/i.test(c));
      if (!pointsToAzure) return null;
      const dangling = ev.root.body.toLowerCase().includes("404 web site not found");
      return dangling
        ? { status: "fail", location: `https://${ev.host}`, confidence: "firm", evidence: `Azure CNAME askıda: «404 Web Site not found» (HTTP ${ev.root.status})` }
        : { status: "pass" };
    },
  },
];
