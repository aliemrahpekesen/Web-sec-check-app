// Technology / version fingerprinting + known-outdated-library checks.
//
// Every check here is category "fingerprint". Detections (server/tech headers,
// CMS/framework signals) fire as INFO/LOW findings when a concrete signal is
// present, and are N/A otherwise. Version-based library checks fire a real
// vulnerability finding ONLY when a version is actually parsed from a script URL
// AND that version is below a known-vulnerable threshold; a present-but-safe
// library PASSES (visible coverage) and an absent library is N/A. Accuracy is
// paramount: nothing fires without raw evidence.
import type { Check } from "./types";

// A minimal structural view of the Evidence fields these checks read. We avoid
// importing the Evidence type to keep this catalog module dependency-light; the
// engine passes the full Evidence object, which is assignable to this shape.
interface Ev {
  target: string;
  host: string;
  origin: string;
  root: {
    headers: Record<string, string>;
    body: string;
    setCookies: string[];
    title: string;
  };
  scripts: string[];
  inlineScripts: string[];
  links: string[];
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

function hdr(ev: Ev, name: string): string | undefined {
  return ev.root.headers[name.toLowerCase()];
}

function bodyHas(ev: Ev, ...needles: string[]): string | null {
  const body = ev.root.body || "";
  const low = body.toLowerCase();
  for (const n of needles) {
    const i = low.indexOf(n.toLowerCase());
    if (i >= 0) return body.slice(Math.max(0, i - 24), i + n.length + 24).replace(/\s+/g, " ").trim();
  }
  return null;
}

function cookieHas(ev: Ev, name: string): string | null {
  const target = name.toLowerCase();
  for (const c of ev.root.setCookies || []) {
    const first = (c.split(";")[0] || "").trim();
    const eq = first.indexOf("=");
    const cname = (eq >= 0 ? first.slice(0, eq) : first).trim().toLowerCase();
    if (cname === target) return first;
  }
  return null;
}

function scriptHas(ev: Ev, needle: string): string | null {
  const low = needle.toLowerCase();
  for (const s of ev.scripts || []) if (s.toLowerCase().includes(low)) return s;
  return null;
}

function linkHas(ev: Ev, needle: string): string | null {
  const low = needle.toLowerCase();
  for (const l of ev.links || []) if (l.toLowerCase().includes(low)) return l;
  return null;
}

// Compare dotted numeric versions: is `a` strictly less than `b`?
function ltVersion(a: number[], b: number[]): boolean {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

// Find the first script URL matching `regex` and extract numeric capture groups
// as a version array. Returns null when no script matches at all.
function findLib(ev: Ev, regex: RegExp): { url: string; version: number[]; raw: string } | null {
  for (const url of ev.scripts || []) {
    const m = regex.exec(url);
    if (m) {
      const version: number[] = [];
      for (let i = 1; i < m.length; i++) {
        const g = m[i];
        if (g !== undefined && /^\d+$/.test(g)) version.push(parseInt(g, 10));
      }
      return { url, version, raw: m[0] };
    }
  }
  return null;
}

function verStr(v: number[]): string {
  return v.length ? v.join(".") : "bilinmiyor";
}

// ---------------------------------------------------------------------------
// Factory 1 — HTTP response-header disclosure (family 1)
// ---------------------------------------------------------------------------

interface HeaderOpts {
  id: string;
  header: string;
  title: string;
  description: string;
  remediation: string;
  references: string[];
  // When true, a value containing a digit is treated as a software VERSION
  // disclosure (LOW); otherwise it is a mere tech-name disclosure (INFO).
  alwaysInfo?: boolean;
}

function headerDisclosure(o: HeaderOpts): Check {
  return {
    id: o.id,
    category: "fingerprint",
    title: o.title,
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: o.description,
    remediation: o.remediation,
    references: o.references,
    confidence: "confirmed",
    evaluate(ev: Ev) {
      const v = hdr(ev, o.header);
      if (v === undefined) return null; // header absent → N/A
      const hasVersion = !o.alwaysInfo && /\d/.test(v);
      return {
        status: "fail",
        severity: hasVersion ? "LOW" : "INFO",
        confidence: "confirmed",
        location: ev.origin,
        titleSuffix: ` — «${v.slice(0, 80)}»`,
        evidence: `${o.header}: ${v}`,
        detail: hasVersion
          ? "Yanıt başlığı yazılım sürümünü ifşa ediyor; saldırganın bilinen açıkları hedeflemesini kolaylaştırır."
          : "Yanıt başlığı kullanılan teknolojiyi ifşa ediyor.",
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Factory 2 — CMS / framework detection (family 2)
// ---------------------------------------------------------------------------

interface DetectOpts {
  id: string;
  title: string;
  description: string;
  remediation: string;
  references: string[];
  severity?: "INFO" | "LOW";
  cwe?: string;
  match(ev: Ev): { evidence: string; location?: string } | null;
}

function detect(o: DetectOpts): Check {
  return {
    id: o.id,
    category: "fingerprint",
    title: o.title,
    severity: o.severity ?? "INFO",
    cwe: o.cwe ?? "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: o.description,
    remediation: o.remediation,
    references: o.references,
    confidence: "firm",
    evaluate(ev: Ev) {
      const r = o.match(ev);
      if (!r) return null;
      return {
        status: "fail",
        severity: o.severity ?? "INFO",
        confidence: "firm",
        location: r.location ?? ev.origin,
        evidence: r.evidence.slice(0, 240),
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Factory 3 — client-library detection + known-vulnerable version tiers
// ---------------------------------------------------------------------------

interface Tier {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  note: string; // e.g. CVE + one-line reason, appended to evidence
  // Fires for any matched version (deprecation/EoL), regardless of number.
  always?: boolean;
  // Fires when a version was parsed and the predicate holds.
  test?: (v: number[]) => boolean;
}

interface LibOpts {
  id: string;
  title: string;
  regex: RegExp; // matched against each ev.scripts URL; numeric groups = version
  description: string;
  remediation: string;
  references: string[];
  cwe?: string;
  owasp?: string;
  // Ordered most-severe first. First matching tier wins. If none match and the
  // library was found, the outcome is PASS (present but not known-vulnerable).
  tiers: Tier[];
}

function libCheck(o: LibOpts): Check {
  return {
    id: o.id,
    category: "fingerprint",
    title: o.title,
    severity: o.tiers[0]?.severity ?? "INFO",
    cwe: o.cwe ?? "CWE-1104",
    owasp: "A06:2021 Vulnerable and Outdated Components",
    description: o.description,
    remediation: o.remediation,
    references: o.references,
    confidence: "firm",
    evaluate(ev: Ev) {
      const found = findLib(ev, o.regex);
      if (!found) return null; // library absent → N/A
      for (const tier of o.tiers) {
        const matched = tier.always
          ? true
          : tier.test !== undefined && found.version.length > 0 && tier.test(found.version);
        if (matched) {
          return {
            status: "fail",
            severity: tier.severity,
            confidence: found.version.length > 0 ? "firm" : "tentative",
            location: found.url,
            evidence: `Tespit: ${found.raw} · sürüm ${verStr(found.version)}\n${tier.note}`,
          };
        }
      }
      return { status: "pass" }; // present but no known-vulnerable/EoL match
    },
  };
}

// A simple "library present" INFO detection (no known-bad version logic).
function libDetect(o: {
  id: string;
  title: string;
  regex: RegExp;
  description: string;
  remediation: string;
  references: string[];
}): Check {
  return libCheck({
    id: o.id,
    title: o.title,
    regex: o.regex,
    description: o.description,
    remediation: o.remediation,
    references: o.references,
    tiers: [{ severity: "INFO", note: "Kütüphane tespit edildi (bilinen kritik sürüm açığı eşleşmedi).", always: true }],
  });
}

// ===========================================================================
// FAMILY 1 — server / tech version-disclosure headers
// ===========================================================================

const HEADER_CHECKS: Check[] = [
  headerDisclosure({
    id: "fp-server-version",
    header: "Server",
    title: "Server başlığı ifşası",
    description: "`Server` yanıt başlığı web sunucusu yazılımını (ve çoğu zaman sürümünü) açığa çıkarır.",
    remediation: "Sunucu bandını gizleyin: Nginx `server_tokens off;`, Apache `ServerTokens Prod` + `ServerSignature Off`.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server"],
  }),
  headerDisclosure({
    id: "fp-x-powered-by",
    header: "X-Powered-By",
    title: "X-Powered-By ifşası",
    description: "`X-Powered-By` çalışma ortamını (PHP, Express, ASP.NET vb.) ve sık sık sürümünü açığa çıkarır.",
    remediation: "Başlığı kaldırın (PHP `expose_php=Off`, Express `app.disable('x-powered-by')`).",
    references: ["https://owasp.org/www-project-secure-headers/"],
  }),
  headerDisclosure({
    id: "fp-x-aspnet-version",
    header: "X-AspNet-Version",
    title: "ASP.NET sürüm ifşası",
    description: "`X-AspNet-Version` çalışan .NET Framework sürümünü açığa çıkarır.",
    remediation: "web.config içinde `<httpRuntime enableVersionHeader=\"false\" />` ayarlayın.",
    references: ["https://learn.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection"],
  }),
  headerDisclosure({
    id: "fp-x-aspnetmvc-version",
    header: "X-AspNetMvc-Version",
    title: "ASP.NET MVC sürüm ifşası",
    description: "`X-AspNetMvc-Version` kullanılan ASP.NET MVC sürümünü açığa çıkarır.",
    remediation: "`MvcHandler.DisableMvcResponseHeader = true;` ile başlığı kapatın.",
    references: ["https://learn.microsoft.com/en-us/aspnet/mvc/"],
  }),
  headerDisclosure({
    id: "fp-x-generator",
    header: "X-Generator",
    title: "X-Generator ifşası",
    description: "`X-Generator` içeriği üreten CMS/aracı (ve sürümünü) açığa çıkarır.",
    remediation: "Sunucu/CMS ayarlarından bu başlığı kaldırın.",
    references: ["https://owasp.org/www-project-secure-headers/"],
  }),
  headerDisclosure({
    id: "fp-x-runtime",
    header: "X-Runtime",
    title: "X-Runtime ifşası (Rails)",
    description: "`X-Runtime` genellikle Ruby on Rails uygulamalarının istek işleme süresini ifşa eder ve teknolojiyi ele verir.",
    remediation: "Rack ara katmanından `Rack::Runtime`'ı kaldırın.",
    references: ["https://api.rubyonrails.org/classes/Rack/Runtime.html"],
    alwaysInfo: true,
  }),
  headerDisclosure({
    id: "fp-x-drupal-cache",
    header: "X-Drupal-Cache",
    title: "X-Drupal-Cache ifşası",
    description: "`X-Drupal-Cache` başlığı sitenin Drupal ile çalıştığını ve önbellek durumunu açığa çıkarır.",
    remediation: "Ters proxy/CDN düzeyinde bu başlığı gizleyin.",
    references: ["https://www.drupal.org/docs/administering-a-drupal-site"],
    alwaysInfo: true,
  }),
  headerDisclosure({
    id: "fp-x-drupal-dynamic-cache",
    header: "X-Drupal-Dynamic-Cache",
    title: "X-Drupal-Dynamic-Cache ifşası",
    description: "`X-Drupal-Dynamic-Cache` sitenin Drupal olduğunu açığa çıkarır.",
    remediation: "Ters proxy/CDN düzeyinde bu başlığı gizleyin.",
    references: ["https://www.drupal.org/docs/administering-a-drupal-site"],
    alwaysInfo: true,
  }),
  headerDisclosure({
    id: "fp-via",
    header: "Via",
    title: "Via başlığı (proxy/CDN) ifşası",
    description: "`Via` başlığı araya giren proxy/CDN yazılımını açığa çıkarır.",
    remediation: "Gerekmiyorsa proxy yapılandırmasından `Via` başlığını kaldırın.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via"],
    alwaysInfo: true,
  }),
  headerDisclosure({
    id: "fp-x-served-by",
    header: "X-Served-By",
    title: "X-Served-By ifşası",
    description: "`X-Served-By` genellikle CDN/önbellek düğüm bilgisini açığa çıkarır (Fastly/Varnish).",
    remediation: "CDN yapılandırmasından bu başlığı kaldırın.",
    references: ["https://developer.fastly.com/reference/http/http-headers/X-Served-By/"],
    alwaysInfo: true,
  }),
  headerDisclosure({
    id: "fp-x-powered-cms",
    header: "X-Powered-CMS",
    title: "X-Powered-CMS ifşası",
    description: "`X-Powered-CMS` kullanılan içerik yönetim sistemini (ve sürümünü) açığa çıkarır.",
    remediation: "Sunucu/CMS yapılandırmasından bu başlığı kaldırın.",
    references: ["https://owasp.org/www-project-secure-headers/"],
  }),
  headerDisclosure({
    id: "fp-liferay-portal",
    header: "Liferay-Portal",
    title: "Liferay-Portal sürüm ifşası",
    description: "`Liferay-Portal` başlığı Liferay Portal ürününü ve tam sürümünü açığa çıkarır.",
    remediation: "portal-ext.properties içinde `web.server.display.node=false` ve tomcat üzerinden başlığı bastırın.",
    references: ["https://liferay.dev/"],
  }),
  headerDisclosure({
    id: "fp-x-varnish",
    header: "X-Varnish",
    title: "X-Varnish ifşası",
    description: "`X-Varnish` başlığı önünde Varnish önbelleği bulunduğunu açığa çıkarır (istek kimliği içerir, sürüm değil).",
    remediation: "VCL içinde `unset resp.http.X-Varnish;` ile başlığı kaldırın.",
    references: ["https://varnish-cache.org/docs/"],
    alwaysInfo: true,
  }),
  headerDisclosure({
    id: "fp-x-backend-server",
    header: "X-Backend-Server",
    title: "X-Backend-Server ifşası",
    description: "`X-Backend-Server` arka uç sunucu adını/örneğini açığa çıkararak iç altyapıyı ele verir.",
    remediation: "Ters proxy yapılandırmasından bu başlığı kaldırın.",
    references: ["https://owasp.org/www-project-secure-headers/"],
    alwaysInfo: true,
  }),
  headerDisclosure({
    id: "fp-x-powered-by-plesk",
    header: "X-Powered-By-Plesk",
    title: "X-Powered-By-Plesk ifşası",
    description: "`X-Powered-By-Plesk` sunucunun Plesk paneliyle yönetildiğini (ve sürümünü) açığa çıkarır.",
    remediation: "Plesk/Apache yapılandırmasından bu başlığı kaldırın.",
    references: ["https://docs.plesk.com/"],
  }),
  headerDisclosure({
    id: "fp-x-ah-environment",
    header: "X-AH-Environment",
    title: "X-AH-Environment ifşası (Acquia)",
    description: "`X-AH-Environment` sitenin Acquia barındırma ortamında (ör. prod/stage) çalıştığını açığa çıkarır.",
    remediation: "Ters proxy düzeyinde bu başlığı gizleyin.",
    references: ["https://docs.acquia.com/"],
    alwaysInfo: true,
  }),
];

// ===========================================================================
// FAMILY 2 — CMS / framework detection
// ===========================================================================

const CMS_CHECKS: Check[] = [
  detect({
    id: "fp-wordpress",
    title: "WordPress tespit edildi",
    description: "İçerik/başlıklarda WordPress imzaları bulundu. Sürüm ve eklenti güncelliği ayrıca denetlenmelidir.",
    remediation: "WordPress çekirdeğini, temaları ve eklentileri güncel tutun; `wp-json` ve `readme.html` ile sürüm ifşasını sınırlayın.",
    references: ["https://wordpress.org/documentation/article/hardening-wordpress/"],
    match(ev) {
      const b = bodyHas(ev, "/wp-content/", "/wp-includes/") || bodyHas(ev, 'name="generator" content="WordPress');
      const s = scriptHas(ev, "/wp-content/") || scriptHas(ev, "/wp-includes/");
      const hit = b || s;
      return hit ? { evidence: `WordPress imzası: ${hit}` } : null;
    },
  }),
  detect({
    id: "fp-drupal",
    title: "Drupal tespit edildi",
    description: "İçerik/başlıklarda Drupal imzaları bulundu.",
    remediation: "Drupal çekirdeğini ve modüllerini güncel tutun; `X-Generator`/`X-Drupal-*` başlıklarını gizleyin.",
    references: ["https://www.drupal.org/docs/security"],
    match(ev) {
      const b = bodyHas(ev, "Drupal.settings", "/sites/default/files", "/core/misc/drupal.js");
      const h = hdr(ev, "x-drupal-cache") || hdr(ev, "x-drupal-dynamic-cache") || hdr(ev, "x-generator");
      if (b) return { evidence: `Drupal imzası: ${b}` };
      if (h && /drupal/i.test(h)) return { evidence: `Drupal başlığı: ${h}` };
      if (hdr(ev, "x-drupal-cache") !== undefined) return { evidence: "X-Drupal-Cache başlığı mevcut" };
      return null;
    },
  }),
  detect({
    id: "fp-joomla",
    title: "Joomla tespit edildi",
    description: "İçerikte Joomla imzaları bulundu.",
    remediation: "Joomla çekirdeğini ve uzantılarını güncel tutun.",
    references: ["https://docs.joomla.org/Security_Checklist"],
    match(ev) {
      const b = bodyHas(ev, "/media/jui/", "/media/system/js/", "content=\"Joomla!") || bodyHas(ev, "Joomla!");
      return b ? { evidence: `Joomla imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-magento",
    title: "Magento tespit edildi",
    description: "İçerikte Magento (Adobe Commerce) imzaları bulundu.",
    remediation: "Magento sürümünü güncel tutun ve güvenlik yamalarını uygulayın.",
    references: ["https://experienceleague.adobe.com/docs/commerce-operations/tools/commerce-services/security-scan.html"],
    match(ev) {
      const b = bodyHas(ev, "/skin/frontend/", "/static/version", "Mage.Cookies", "Magento_") || scriptHas(ev, "mage/");
      return b ? { evidence: `Magento imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-shopify",
    title: "Shopify tespit edildi",
    description: "Kaynak/başlıklarda Shopify imzaları bulundu.",
    remediation: "Shopify barındırılan bir platformdur; tema/uygulama güvenliğini gözden geçirin.",
    references: ["https://shopify.dev/docs/storefronts"],
    match(ev) {
      const s = scriptHas(ev, "cdn.shopify.com");
      if (s) return { evidence: `Shopify CDN: ${s}`, location: s };
      if (hdr(ev, "x-shopid") !== undefined) return { evidence: `X-ShopId: ${hdr(ev, "x-shopid")}` };
      const b = bodyHas(ev, "Shopify.theme", "cdn.shopify.com");
      return b ? { evidence: `Shopify imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-wix",
    title: "Wix tespit edildi",
    description: "Kaynakta Wix imzaları bulundu.",
    remediation: "Wix barındırılan bir platformdur; site ayarlarını gözden geçirin.",
    references: ["https://www.wix.com/"],
    match(ev) {
      const s = scriptHas(ev, "static.parastorage.com") || scriptHas(ev, "wixstatic.com");
      if (s) return { evidence: `Wix kaynağı: ${s}`, location: s };
      const h = hdr(ev, "x-wix-request-id");
      if (h !== undefined) return { evidence: `X-Wix-Request-Id: ${h}` };
      const b = bodyHas(ev, "X-Wix", "wix.com");
      return b ? { evidence: `Wix imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-squarespace",
    title: "Squarespace tespit edildi",
    description: "Kaynakta Squarespace imzaları bulundu.",
    remediation: "Squarespace barındırılan bir platformdur; site ayarlarını gözden geçirin.",
    references: ["https://www.squarespace.com/"],
    match(ev) {
      const s = scriptHas(ev, "static1.squarespace.com") || scriptHas(ev, "squarespace-cdn.com");
      if (s) return { evidence: `Squarespace kaynağı: ${s}`, location: s };
      const b = bodyHas(ev, "squarespace.com", "Static.SQUARESPACE_CONTEXT");
      return b ? { evidence: `Squarespace imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-ghost",
    title: "Ghost tespit edildi",
    description: "Meta generator etiketinde Ghost imzası bulundu.",
    remediation: "Ghost sürümünü güncel tutun.",
    references: ["https://ghost.org/docs/security/"],
    match(ev) {
      const b = bodyHas(ev, 'content="Ghost', "ghost-url", "/ghost/api/");
      return b ? { evidence: `Ghost imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-django",
    title: "Django tespit edildi",
    description: "Çerez/içerik Django imzaları taşıyor.",
    remediation: "Django ve bağımlılıklarını güncel tutun; `DEBUG=False` olduğundan emin olun.",
    references: ["https://docs.djangoproject.com/en/stable/topics/security/"],
    match(ev) {
      const c = cookieHas(ev, "csrftoken") || cookieHas(ev, "django_language");
      if (c) return { evidence: `Django çerezi: ${c}` };
      const b = bodyHas(ev, "csrfmiddlewaretoken", "__admin/");
      return b ? { evidence: `Django imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-laravel",
    title: "Laravel tespit edildi",
    description: "Çerez/başlıklar Laravel imzaları taşıyor.",
    remediation: "Laravel ve bağımlılıklarını güncel tutun; `APP_DEBUG=false` olduğundan emin olun.",
    references: ["https://laravel.com/docs/security"],
    match(ev) {
      const c = cookieHas(ev, "laravel_session") || cookieHas(ev, "XSRF-TOKEN");
      if (c) return { evidence: `Laravel çerezi: ${c}` };
      const p = hdr(ev, "x-powered-by");
      if (p && /php/i.test(p) && cookieHas(ev, "laravel_session")) return { evidence: `Laravel + ${p}` };
      return null;
    },
  }),
  detect({
    id: "fp-rails",
    title: "Ruby on Rails tespit edildi",
    description: "Çerez/başlıklar Rails imzaları taşıyor.",
    remediation: "Rails ve gem bağımlılıklarını güncel tutun.",
    references: ["https://guides.rubyonrails.org/security.html"],
    match(ev) {
      const c = cookieHas(ev, "_session_id");
      if (c) return { evidence: `Rails çerezi: ${c}` };
      if (hdr(ev, "x-runtime") !== undefined && (cookieHas(ev, "request_method") || bodyHas(ev, "csrf-param")))
        return { evidence: "X-Runtime + Rails CSRF meta" };
      return null;
    },
  }),
  detect({
    id: "fp-express",
    title: "Express (Node.js) tespit edildi",
    description: "`X-Powered-By: Express` başlığı bulundu.",
    remediation: "`app.disable('x-powered-by')` ile başlığı kaldırın; Express ve bağımlılıklarını güncel tutun.",
    references: ["https://expressjs.com/en/advanced/best-practice-security.html"],
    match(ev) {
      const p = hdr(ev, "x-powered-by");
      return p && /express/i.test(p) ? { evidence: `X-Powered-By: ${p}` } : null;
    },
  }),
  detect({
    id: "fp-nextjs",
    title: "Next.js tespit edildi",
    description: "Kaynak/başlıklar Next.js imzaları taşıyor.",
    remediation: "Next.js sürümünü güncel tutun.",
    references: ["https://nextjs.org/docs"],
    match(ev) {
      if (hdr(ev, "x-nextjs-cache") !== undefined || hdr(ev, "x-nextjs-prerender") !== undefined)
        return { evidence: "x-nextjs-* başlığı mevcut" };
      const s = scriptHas(ev, "/_next/static/");
      if (s) return { evidence: `Next.js kaynağı: ${s}`, location: s };
      const b = bodyHas(ev, "__NEXT_DATA__", "/_next/");
      return b ? { evidence: `Next.js imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-nuxt",
    title: "Nuxt.js tespit edildi",
    description: "Kaynakta Nuxt imzaları bulundu.",
    remediation: "Nuxt sürümünü güncel tutun.",
    references: ["https://nuxt.com/docs"],
    match(ev) {
      const s = scriptHas(ev, "/_nuxt/");
      if (s) return { evidence: `Nuxt kaynağı: ${s}`, location: s };
      const b = bodyHas(ev, "__NUXT__", "/_nuxt/");
      return b ? { evidence: `Nuxt imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-gatsby",
    title: "Gatsby tespit edildi",
    description: "Kaynakta Gatsby imzaları bulundu.",
    remediation: "Gatsby ve eklentilerini güncel tutun.",
    references: ["https://www.gatsbyjs.com/docs/"],
    match(ev) {
      const b = bodyHas(ev, "___gatsby", "/page-data/", "gatsby-") || scriptHas(ev, "/page-data/");
      return b ? { evidence: `Gatsby imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-aspnet",
    title: "ASP.NET tespit edildi",
    description: "Çerez/uzantılar ASP.NET imzaları taşıyor.",
    remediation: ".NET çalışma zamanını güncel tutun; sürüm ifşa eden başlıkları kapatın.",
    references: ["https://learn.microsoft.com/en-us/aspnet/overview"],
    match(ev) {
      const c = cookieHas(ev, "ASP.NET_SessionId") || cookieHas(ev, ".ASPXAUTH");
      if (c) return { evidence: `ASP.NET çerezi: ${c}` };
      const l = linkHas(ev, ".aspx");
      if (l) return { evidence: `.aspx uzantısı: ${l}`, location: l };
      return null;
    },
  }),
  detect({
    id: "fp-spring",
    title: "Spring / Java tespit edildi",
    description: "`JSESSIONID` çerezi Java (sık sık Spring) tabanlı bir uygulamaya işaret eder.",
    remediation: "Spring/Java bağımlılıklarını güncel tutun; oturum çerezi adını gizlemek riski azaltmaz ama tespiti zorlaştırır.",
    references: ["https://spring.io/security"],
    match(ev) {
      const c = cookieHas(ev, "JSESSIONID");
      return c ? { evidence: `Java oturum çerezi: ${c}` } : null;
    },
  }),
  detect({
    id: "fp-flask",
    title: "Flask / Werkzeug tespit edildi",
    description: "`Server: Werkzeug` başlığı veya Flask oturum çerezi bulundu.",
    remediation: "Üretimde Werkzeug geliştirme sunucusunu kullanmayın; gunicorn/uwsgi ardında çalıştırın.",
    references: ["https://flask.palletsprojects.com/en/stable/deploying/"],
    match(ev) {
      const s = hdr(ev, "server");
      if (s && /werkzeug/i.test(s)) return { evidence: `Server: ${s}` };
      const c = cookieHas(ev, "session");
      if (c && /\./.test(c) && s && /python/i.test(s)) return { evidence: `Flask oturum çerezi + ${s}` };
      return null;
    },
  }),
  detect({
    id: "fp-vercel",
    title: "Vercel barındırma tespit edildi",
    description: "`x-vercel-id` başlığı sitenin Vercel üzerinde barındırıldığını gösterir.",
    remediation: "Bilgilendirme amaçlıdır; Vercel proje güvenlik ayarlarını gözden geçirin.",
    references: ["https://vercel.com/docs"],
    match(ev) {
      const h = hdr(ev, "x-vercel-id");
      return h !== undefined ? { evidence: `x-vercel-id: ${h}` } : null;
    },
  }),
  detect({
    id: "fp-cloudflare",
    title: "Cloudflare tespit edildi",
    description: "`cf-ray` başlığı sitenin Cloudflare ardında olduğunu gösterir.",
    remediation: "Bilgilendirme amaçlıdır; kaynak sunucunun Cloudflare IP aralıkları dışına kapalı olduğundan emin olun.",
    references: ["https://developers.cloudflare.com/fundamentals/"],
    match(ev) {
      const h = hdr(ev, "cf-ray");
      if (h !== undefined) return { evidence: `cf-ray: ${h}` };
      const s = hdr(ev, "server");
      return s && /cloudflare/i.test(s) ? { evidence: `Server: ${s}` } : null;
    },
  }),
  detect({
    id: "fp-typo3",
    title: "TYPO3 tespit edildi",
    description: "İçerikte TYPO3 imzaları bulundu.",
    remediation: "TYPO3 çekirdeğini ve eklentilerini güncel tutun.",
    references: ["https://typo3.org/help/security/"],
    match(ev) {
      const b = bodyHas(ev, "typo3temp/", "typo3conf/", 'content="TYPO3');
      return b ? { evidence: `TYPO3 imzası: ${b}` } : null;
    },
  }),
  detect({
    id: "fp-woocommerce",
    title: "WooCommerce tespit edildi",
    description: "İçerik/çerezler WooCommerce (WordPress e-ticaret) imzaları taşıyor.",
    remediation: "WooCommerce eklentisini ve WordPress çekirdeğini güncel tutun.",
    references: ["https://woocommerce.com/document/security/"],
    match(ev) {
      const b = bodyHas(ev, "woocommerce", "/wp-content/plugins/woocommerce/");
      if (b) return { evidence: `WooCommerce imzası: ${b}` };
      const c = cookieHas(ev, "woocommerce_cart_hash") || cookieHas(ev, "woocommerce_items_in_cart");
      return c ? { evidence: `WooCommerce çerezi: ${c}` } : null;
    },
  }),
];

// ===========================================================================
// FAMILY 3 — client-library detection + known-vulnerable versions
// ===========================================================================

const LIB_CHECKS: Check[] = [
  libCheck({
    id: "fp-jquery-outdated",
    title: "jQuery güncel değil",
    regex: /jquery[-.]?(\d+)\.(\d+)(?:\.(\d+))?(?:\.slim)?(?:\.min)?\.js/i,
    description: "Sayfa eski bir jQuery sürümü yüklüyor. 3.5.0 öncesi sürümler `htmlPrefilter` XSS'ine (CVE-2020-11022/11023), 1.9 öncesi ise ciddi XSS/DOM sorunlarına açıktır.",
    remediation: "jQuery'yi en az 3.5.0 (tercihen en güncel 3.x) sürümüne yükseltin.",
    references: ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"],
    cwe: "CWE-79",
    tiers: [
      { severity: "HIGH", note: "jQuery < 1.9 — bilinen çok sayıda XSS/DOM açığı.", test: (v) => ltVersion(v, [1, 9]) },
      { severity: "MEDIUM", note: "jQuery < 3.5.0 — CVE-2020-11022 / CVE-2020-11023 XSS.", test: (v) => ltVersion(v, [3, 5, 0]) },
    ],
  }),
  libCheck({
    id: "fp-jquery-ui-outdated",
    title: "jQuery UI güncel değil",
    regex: /jquery-ui[-.]?(\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i,
    description: "Eski jQuery UI sürümleri XSS açıklarına sahiptir (ör. datepicker/dialog `title` XSS, CVE-2021-41182/41183/41184).",
    remediation: "jQuery UI'yi 1.13.0 veya üzerine yükseltin.",
    references: ["https://github.com/jquery/jquery-ui/security/advisories"],
    cwe: "CWE-79",
    tiers: [{ severity: "MEDIUM", note: "jQuery UI < 1.13.0 — XSS (CVE-2021-41182/41183/41184).", test: (v) => ltVersion(v, [1, 13, 0]) }],
  }),
  libDetect({
    id: "fp-jquery-migrate",
    title: "jQuery Migrate tespit edildi",
    regex: /jquery-migrate[-.]?(\d+)\.(\d+)(?:\.(\d+))?/i,
    description: "jQuery Migrate varlığı, kaldırılmış eski jQuery API'lerine bağımlılık olduğunu gösterir; bu genelde eski jQuery sürümüyle birlikte gelir.",
    remediation: "Kodu güncel jQuery API'lerine taşıyıp jQuery Migrate'i kaldırın.",
    references: ["https://github.com/jquery/jquery-migrate"],
  }),
  libCheck({
    id: "fp-angularjs-eol",
    title: "AngularJS (1.x) kullanım sonu",
    regex: /angular(?:\.js|js)?[/@-]?(1)\.(\d+)(?:\.(\d+))?/i,
    description: "AngularJS 1.x resmi olarak kullanım sonudur (EoL) ve şablon enjeksiyonu/sandbox kaçışı sınıfı sorunlara açıktır; güvenlik yaması almaz.",
    remediation: "AngularJS 1.x'ten modern bir çerçeveye (Angular 2+, React, Vue) geçiş planlayın.",
    references: ["https://docs.angularjs.org/misc/version-support-status"],
    cwe: "CWE-1104",
    tiers: [{ severity: "MEDIUM", note: "AngularJS 1.x EoL — sandbox kaçışları ve yamalanmayan açıklar.", always: true }],
  }),
  libCheck({
    id: "fp-bootstrap-outdated",
    title: "Bootstrap güncel değil",
    regex: /bootstrap[-.]?(\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.(?:js|css)/i,
    description: "3.4.0 ve 4.3.1 öncesi Bootstrap sürümleri veri özniteliklerinde (data-target/data-container) XSS açıklarına sahiptir (CVE-2018-14041, CVE-2019-8331).",
    remediation: "Bootstrap'i en az 3.4.1 / 4.3.1 (tercihen güncel 5.x) sürümüne yükseltin.",
    references: ["https://github.com/twbs/bootstrap/security/advisories"],
    cwe: "CWE-79",
    tiers: [
      {
        severity: "MEDIUM",
        note: "Bootstrap XSS — 3.4.0 / 4.3.1 öncesi (CVE-2019-8331 vb.).",
        test: (v) => {
          const maj = v[0] ?? 0;
          if (maj < 3) return true;
          if (maj === 3) return ltVersion(v, [3, 4, 0]);
          if (maj === 4) return ltVersion(v, [4, 3, 1]);
          return false;
        },
      },
    ],
  }),
  libCheck({
    id: "fp-lodash-outdated",
    title: "Lodash güncel değil",
    regex: /lodash[-.]?(\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i,
    description: "4.17.12 öncesi Lodash prototip kirlenmesine (prototype pollution) açıktır (CVE-2019-10744).",
    remediation: "Lodash'ı en az 4.17.21 sürümüne yükseltin.",
    references: ["https://github.com/advisories/GHSA-jf85-cpcp-j695"],
    cwe: "CWE-1321",
    tiers: [{ severity: "MEDIUM", note: "Lodash < 4.17.12 — prototype pollution (CVE-2019-10744).", test: (v) => ltVersion(v, [4, 17, 12]) }],
  }),
  libCheck({
    id: "fp-moment-outdated",
    title: "Moment.js (kullanımdan kaldırıldı / güncel değil)",
    regex: /\bmoment(?:-with-locales)?(?:[-.](\d+)\.(\d+)(?:\.(\d+))?)?(?:\.min)?\.js/i,
    description: "Moment.js artık bakım modundadır (yeni proje için önerilmez). 2.29.4 öncesi sürümler ise yol geçişi/ReDoS içerir (CVE-2022-24785, CVE-2022-31129).",
    remediation: "2.29.4+ sürümüne yükseltin veya day.js/date-fns/Luxon gibi bir alternatife geçin.",
    references: ["https://github.com/advisories/GHSA-wc69-rhjr-hc9g"],
    cwe: "CWE-400",
    tiers: [
      { severity: "MEDIUM", note: "Moment.js < 2.29.4 — ReDoS / yol geçişi (CVE-2022-31129, CVE-2022-24785).", test: (v) => ltVersion(v, [2, 29, 4]) },
      { severity: "LOW", note: "Moment.js bakım modunda; yeni geliştirmelerde önerilmez.", always: true },
    ],
  }),
  libCheck({
    id: "fp-handlebars-outdated",
    title: "Handlebars güncel değil",
    regex: /handlebars[-.]?(\d+)\.(\d+)(?:\.(\d+))?(?:\.runtime)?(?:\.min)?\.js/i,
    description: "4.7.7 öncesi Handlebars, prototip kirlenmesi yoluyla uzaktan kod çalıştırmaya (RCE) kadar giden açıklara sahiptir (CVE-2019-19919, CVE-2021-23369).",
    remediation: "Handlebars'ı en az 4.7.7 sürümüne yükseltin.",
    references: ["https://github.com/advisories/GHSA-f2jv-r9rf-7988"],
    cwe: "CWE-1321",
    tiers: [{ severity: "HIGH", note: "Handlebars < 4.7.7 — prototype pollution / RCE (CVE-2021-23369).", test: (v) => ltVersion(v, [4, 7, 7]) }],
  }),
  libCheck({
    id: "fp-vue2-eol",
    title: "Vue 2.x kullanım sonu",
    regex: /vue(?:\.runtime|\.common|\.global|\.esm)?(?:@|[/-])(2)\.(\d+)(?:\.(\d+))?/i,
    description: "Vue 2.x, 2023 sonu itibarıyla kullanım sonudur (EoL) ve artık güvenlik yaması almaz.",
    remediation: "Vue 3'e geçiş planlayın.",
    references: ["https://v2.vuejs.org/eol/"],
    cwe: "CWE-1104",
    tiers: [{ severity: "LOW", note: "Vue 2.x EoL — güvenlik yaması almaz.", always: true }],
  }),
  libCheck({
    id: "fp-underscore-outdated",
    title: "Underscore.js güncel değil",
    regex: /underscore[-.]?(\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i,
    description: "1.12.1/1.13.0 öncesi Underscore.js `_.template` üzerinden keyfi kod çalıştırmaya açıktır (CVE-2021-23358).",
    remediation: "Underscore'u en az 1.13.1 sürümüne yükseltin.",
    references: ["https://github.com/advisories/GHSA-cf4h-3jhx-xvhq"],
    cwe: "CWE-94",
    tiers: [{ severity: "MEDIUM", note: "Underscore < 1.13.0 — keyfi kod çalıştırma (CVE-2021-23358).", test: (v) => ltVersion(v, [1, 13, 0]) }],
  }),
  libCheck({
    id: "fp-dompurify-outdated",
    title: "DOMPurify güncel değil",
    regex: /(?:dompurify|purify)[-.]?(\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i,
    description: "2.4.0 öncesi DOMPurify sürümleri mutasyon-XSS (mXSS) atlatma açıklarına sahiptir; bir XSS sanitizasyon kütüphanesi olduğundan bu doğrudan koruma zafiyetidir.",
    remediation: "DOMPurify'ı en güncel sürüme yükseltin (en az 2.4.0).",
    references: ["https://github.com/cure53/DOMPurify/releases"],
    cwe: "CWE-79",
    tiers: [{ severity: "MEDIUM", note: "DOMPurify < 2.4.0 — mXSS atlatma.", test: (v) => ltVersion(v, [2, 4, 0]) }],
  }),
  libCheck({
    id: "fp-axios-outdated",
    title: "Axios güncel değil",
    regex: /axios[-.]?(\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i,
    description: "0.21.2 öncesi Axios sürümleri SSRF ve ReDoS açıklarına sahiptir (CVE-2020-28168, CVE-2021-3749).",
    remediation: "Axios'u en güncel sürüme yükseltin.",
    references: ["https://github.com/advisories/GHSA-4w2v-q235-vp99"],
    cwe: "CWE-918",
    tiers: [{ severity: "MEDIUM", note: "Axios < 0.21.2 — SSRF / ReDoS (CVE-2020-28168, CVE-2021-3749).", test: (v) => ltVersion(v, [0, 21, 2]) }],
  }),
  libDetect({
    id: "fp-react",
    title: "React tespit edildi",
    regex: /\breact(?:-dom)?(?:@[\d.]+)?(?:\.production|\.development)?(?:\.min)?\.js/i,
    description: "React kütüphanesi tespit edildi. Sürümü ve bağımlılıkları güncel tutulmalıdır.",
    remediation: "React ve react-dom sürümlerini güncel tutun.",
    references: ["https://react.dev/"],
  }),
  libDetect({
    id: "fp-vue3",
    title: "Vue 3 tespit edildi",
    regex: /vue(?:\.runtime|\.global|\.esm-browser)?(?:@|[/-])(3)\.(\d+)/i,
    description: "Vue 3 kütüphanesi tespit edildi.",
    remediation: "Vue 3 sürümünü güncel tutun.",
    references: ["https://vuejs.org/"],
  }),
  libDetect({
    id: "fp-angular",
    title: "Angular (2+) tespit edildi",
    regex: /(?:@angular|zone\.js|polyfills[.-]|runtime[.-][0-9a-f]+)/i,
    description: "Modern Angular (2+) imzaları tespit edildi.",
    remediation: "Angular ve bağımlılıklarını güncel tutun.",
    references: ["https://angular.dev/"],
  }),
  libDetect({
    id: "fp-ember",
    title: "Ember.js tespit edildi",
    regex: /\bember(?:[-.]|@)/i,
    description: "Ember.js kütüphanesi tespit edildi.",
    remediation: "Ember.js sürümünü güncel tutun.",
    references: ["https://emberjs.com/"],
  }),
  libDetect({
    id: "fp-backbone",
    title: "Backbone.js tespit edildi",
    regex: /\bbackbone(?:[-.]|@)/i,
    description: "Backbone.js kütüphanesi tespit edildi.",
    remediation: "Backbone.js sürümünü güncel tutun.",
    references: ["https://backbonejs.org/"],
  }),
  libDetect({
    id: "fp-modernizr",
    title: "Modernizr tespit edildi",
    regex: /modernizr(?:[-.]|@|\.custom|\.min)/i,
    description: "Modernizr özellik-algılama kütüphanesi tespit edildi.",
    remediation: "Yalnızca kullanılan testleri içeren güncel bir Modernizr derlemesi kullanın.",
    references: ["https://modernizr.com/"],
  }),
  libDetect({
    id: "fp-select2",
    title: "Select2 tespit edildi",
    regex: /select2(?:[-.]|@|\.full|\.min)/i,
    description: "Select2 kütüphanesi tespit edildi.",
    remediation: "Select2 sürümünü güncel tutun (eski sürümlerde XSS bildirilmiştir).",
    references: ["https://select2.org/"],
  }),
  libDetect({
    id: "fp-chartjs",
    title: "Chart.js tespit edildi",
    regex: /\bchart(?:\.min)?\.js|chart\.js@|chartjs/i,
    description: "Chart.js kütüphanesi tespit edildi.",
    remediation: "Chart.js sürümünü güncel tutun.",
    references: ["https://www.chartjs.org/"],
  }),
  libDetect({
    id: "fp-threejs",
    title: "three.js tespit edildi",
    regex: /\bthree(?:\.module)?(?:\.min)?\.js|three\.js@/i,
    description: "three.js kütüphanesi tespit edildi.",
    remediation: "three.js sürümünü güncel tutun.",
    references: ["https://threejs.org/"],
  }),
  libDetect({
    id: "fp-d3",
    title: "D3.js tespit edildi",
    regex: /\bd3(?:\.v\d+)?(?:\.min)?\.js|d3js\.org/i,
    description: "D3.js veri görselleştirme kütüphanesi tespit edildi.",
    remediation: "D3.js sürümünü güncel tutun.",
    references: ["https://d3js.org/"],
  }),
];

// ===========================================================================
// FAMILY 4 — HTML meta generator tag
// ===========================================================================

const META_CHECK: Check = {
  id: "fp-meta-generator",
  category: "fingerprint",
  title: "HTML meta generator ifşası",
  severity: "LOW",
  cwe: "CWE-200",
  owasp: "A05:2021 Security Misconfiguration",
  description: "`<meta name=\"generator\">` etiketi içeriği üreten yazılımı ve sık sık sürümünü açığa çıkarır.",
  remediation: "CMS/derleme ayarlarından generator meta etiketini kaldırın (WordPress: `remove_action('wp_head','wp_generator')`).",
  references: ["https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta/name"],
  confidence: "confirmed",
  evaluate(ev: Ev) {
    const body = ev.root.body || "";
    const m = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(body)
      || /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i.exec(body);
    if (!m) return null;
    const content = (m[1] || "").trim();
    if (!content) return null;
    const hasVersion = /\d/.test(content);
    return {
      status: "fail",
      severity: hasVersion ? "LOW" : "INFO",
      confidence: "confirmed",
      location: ev.origin,
      titleSuffix: ` — «${content.slice(0, 80)}»`,
      evidence: `<meta name="generator" content="${content}">`,
    };
  },
};

// ===========================================================================
// FAMILY 5 — exposed build / debug info
// ===========================================================================

const BUILD_CHECKS: Check[] = [
  {
    id: "fp-x-sourcemap",
    category: "fingerprint",
    title: "SourceMap başlığı ifşası",
    severity: "LOW",
    cwe: "CWE-540",
    owasp: "A05:2021 Security Misconfiguration",
    description: "`X-SourceMap` / `SourceMap` yanıt başlığı, kaynak haritasının (source map) yolunu ifşa eder; bu, üretim JS'inin okunabilir kaynak koduna dönüştürülmesini sağlayabilir.",
    remediation: "Üretimde source map yayınlamayın veya erişimini kısıtlayın; `X-SourceMap`/`SourceMap` başlığını kaldırın.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/SourceMap"],
    confidence: "confirmed",
    evaluate(ev: Ev) {
      const v = hdr(ev, "x-sourcemap") ?? hdr(ev, "sourcemap");
      if (v === undefined) return null;
      return { status: "fail", confidence: "confirmed", location: ev.origin, evidence: `SourceMap başlığı: ${v}` };
    },
  },
  {
    id: "fp-sourcemap-comment",
    category: "fingerprint",
    title: "Satır içi script'te sourceMappingURL yorumu",
    severity: "LOW",
    cwe: "CWE-540",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Satır içi bir script içinde `sourceMappingURL=` yorumu bulundu; kaynak haritası erişilebilirse üretim kodu deobfuscate edilebilir.",
    remediation: "Üretim derlemelerinden `//# sourceMappingURL` yorumlarını kaldırın veya harita dosyalarını yayına almayın.",
    references: ["https://developer.chrome.com/docs/devtools/javascript/source-maps"],
    confidence: "firm",
    evaluate(ev: Ev) {
      for (const s of ev.inlineScripts || []) {
        const m = /sourceMappingURL=(\S+)/i.exec(s);
        if (m) return { status: "fail", confidence: "firm", location: ev.origin, evidence: `sourceMappingURL=${(m[1] || "").slice(0, 120)}` };
      }
      return null;
    },
  },
  {
    id: "fp-x-debug-token",
    category: "fingerprint",
    title: "Symfony debug profil ifşası (X-Debug-Token)",
    severity: "MEDIUM",
    cwe: "CWE-489",
    owasp: "A05:2021 Security Misconfiguration",
    description: "`X-Debug-Token` / `X-Debug-Token-Link` başlığı, Symfony hata ayıklama profilleyicisinin (web profiler) üretimde açık olabileceğini gösterir; profiler yapılandırma, sorgu ve ortam bilgisini ifşa edebilir.",
    remediation: "Üretimde `APP_ENV=prod` ve `APP_DEBUG=0` ayarlayın; web profiler'ı yalnızca dev ortamında etkinleştirin.",
    references: ["https://symfony.com/doc/current/profiler.html"],
    confidence: "firm",
    evaluate(ev: Ev) {
      const t = hdr(ev, "x-debug-token") ?? hdr(ev, "x-debug-token-link");
      if (t === undefined) return null;
      return { status: "fail", confidence: "firm", location: ev.origin, evidence: `X-Debug-Token: ${t}` };
    },
  },
];

// ===========================================================================
// Exported catalog
// ===========================================================================

export const FINGERPRINT_CHECKS: Check[] = [
  ...HEADER_CHECKS,
  ...CMS_CHECKS,
  ...LIB_CHECKS,
  META_CHECK,
  ...BUILD_CHECKS,
];
