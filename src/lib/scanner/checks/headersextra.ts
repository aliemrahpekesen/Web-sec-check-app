// Extra header-hygiene and email/DNS checks that complement the primary
// header (headers.ts) and DNS (dns.ts) catalogs. These cover lower-severity
// hardening and detection signals that are still worth surfacing but were not
// part of the core header/email posture. Every check is a pure function over
// the collected Evidence: it fails only on a concrete observed state, passes
// when the relevant control is present and healthy, and returns null when the
// check does not apply to this response.
import type { Check } from "./types";

const MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers";

export const HEADERS_EXTRA_CHECKS: Check[] = [
  // --- Cross-origin isolation ------------------------------------------------
  {
    id: "hx-coep-missing",
    category: "headers",
    title: "Cross-Origin-Embedder-Policy başlığı yok",
    severity: "INFO",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Cross-Origin-Embedder-Policy yok; siteniz çapraz-köken izolasyonu (crossOriginIsolated) gerektiren güçlü API'leri (SharedArrayBuffer, yüksek çözünürlüklü zamanlayıcılar) kullanamaz.",
    remediation: "İzolasyon gerekiyorsa yanıtlara Cross-Origin-Embedder-Policy: require-corp (veya credentialless) ekleyin ve COOP ile birlikte kullanın.",
    references: [`${MDN}/Cross-Origin-Embedder-Policy`],
    evaluate(ev) {
      return ev.root.headers["cross-origin-embedder-policy"]
        ? { status: "pass" }
        : { status: "fail", location: ev.root.url };
    },
  },
  {
    id: "hx-origin-agent-cluster",
    category: "headers",
    title: "Origin-Agent-Cluster başlığı yok",
    severity: "INFO",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Origin-Agent-Cluster yok; tarayıcı bu kökeni kaynak-anahtarlı bir ajan kümesine izole etmeyi garanti etmez, aynı-site kökenler bellek/kaynak paylaşabilir.",
    remediation: "İzolasyon isteniyorsa yanıtlara Origin-Agent-Cluster: ?1 ekleyin.",
    references: [`${MDN}/Origin-Agent-Cluster`],
    evaluate(ev) {
      return ev.root.headers["origin-agent-cluster"]
        ? { status: "pass" }
        : { status: "fail", location: ev.root.url };
    },
  },

  // --- Timing / CORS exposure ------------------------------------------------
  {
    id: "hx-timing-allow-origin-wildcard",
    category: "headers",
    title: "Timing-Allow-Origin joker (*) değeri",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Timing-Allow-Origin: * herhangi bir kökene Resource Timing API üzerinden ayrıntılı yükleme zamanlaması bilgisi sızdırır; yan-kanal ve kullanıcı ölçümü için istismar edilebilir.",
    remediation: "Timing-Allow-Origin'i yalnızca güvenilen kökenlerle sınırlayın; joker (*) kullanmayın.",
    references: [`${MDN}/Timing-Allow-Origin`],
    evaluate(ev) {
      const v = ev.root.headers["timing-allow-origin"];
      if (!v) return null;
      return v.trim() === "*"
        ? { status: "fail", evidence: `Timing-Allow-Origin: ${v}`, location: ev.root.url }
        : { status: "pass" };
    },
  },
  {
    id: "hx-acao-expose-wildcard",
    category: "headers",
    title: "Access-Control-Expose-Headers joker (*) değeri",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Access-Control-Expose-Headers: * çapraz-köken betiklere tüm yanıt başlıklarını okuma izni verir; hassas veya iç başlıklar istemci JavaScript'ine açılabilir.",
    remediation: "Yalnızca gerekli başlıkları açıkça listeleyin; joker (*) yerine belirli başlık adlarını kullanın.",
    references: [`${MDN}/Access-Control-Expose-Headers`],
    evaluate(ev) {
      const v = ev.root.headers["access-control-expose-headers"];
      if (!v) return null;
      return v.trim() === "*"
        ? { status: "fail", evidence: `Access-Control-Expose-Headers: ${v}`, location: ev.root.url }
        : { status: "pass" };
    },
  },
  {
    id: "hx-acac-without-acao",
    category: "headers",
    title: "Access-Control-Allow-Credentials var ama Allow-Origin yok",
    severity: "LOW",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Access-Control-Allow-Credentials: true gönderiliyor ancak Access-Control-Allow-Origin yok; CORS yapılandırması tutarsız, kimlik bilgili çapraz-köken erişim için hatalı/kararsız bir durumdur.",
    remediation: "Kimlik bilgisi paylaşımı gerekiyorsa Access-Control-Allow-Origin'i tek ve belirli bir kökene ayarlayın; gerekmiyorsa Allow-Credentials başlığını kaldırın.",
    references: [`${MDN}/Access-Control-Allow-Credentials`],
    evaluate(ev) {
      const cred = ev.root.headers["access-control-allow-credentials"];
      if (!cred || cred.trim().toLowerCase() !== "true") return null;
      return ev.root.headers["access-control-allow-origin"]
        ? { status: "pass" }
        : { status: "fail", evidence: "Access-Control-Allow-Credentials: true (Access-Control-Allow-Origin yok)", location: ev.root.url };
    },
  },
  {
    id: "hx-access-control-allow-headers-wildcard",
    category: "headers",
    title: "Access-Control-Allow-Headers joker (*) değeri",
    severity: "LOW",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Access-Control-Allow-Headers: * çapraz-köken isteklerde herhangi bir istek başlığına izin verir; CORS istek yüzeyini gereğinden fazla genişletir (ve Authorization gibi başlıkları joker kapsamaz, yanlış güvenlik hissi verir).",
    remediation: "İzin verilen istek başlıklarını açıkça listeleyin; joker (*) yerine yalnızca gerekli başlık adlarını belirtin.",
    references: [`${MDN}/Access-Control-Allow-Headers`],
    evaluate(ev) {
      const v = ev.root.headers["access-control-allow-headers"];
      if (!v) return null;
      return v.trim() === "*"
        ? { status: "fail", evidence: `Access-Control-Allow-Headers: ${v}`, location: ev.root.url }
        : { status: "pass" };
    },
  },

  // --- Reporting / observability signals (detection) -------------------------
  {
    id: "hx-nel-present",
    category: "headers",
    title: "NEL (Network Error Logging) yapılandırılmış",
    severity: "INFO",
    description: "NEL başlığı mevcut; ağ hataları tarayıcı tarafından toplanıp bir uç noktaya raporlanıyor. Bilgilendirme amaçlıdır, raporlama uç noktasının güvenilir olduğunu doğrulayın.",
    remediation: "NEL raporlarının yalnızca sizin denetlediğiniz güvenli bir uç noktaya gittiğinden emin olun; hassas URL/istek verisi sızdırmayın.",
    references: [`${MDN}/NEL`],
    evaluate(ev) {
      return ev.root.headers["nel"]
        ? { status: "fail", evidence: `NEL: ${ev.root.headers["nel"].slice(0, 200)}`, location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-report-to",
    category: "headers",
    title: "Report-To raporlama uç noktası tanımlı",
    severity: "INFO",
    description: "Report-To başlığı mevcut; CSP/NEL gibi ihlaller bir raporlama grubuna gönderiliyor. Bilgilendirme amaçlıdır.",
    remediation: "Report-To uç noktalarının güvenilir olduğunu ve raporların hassas veri sızdırmadığını doğrulayın; eski Report-To yerine yeni Reporting-Endpoints'e geçmeyi değerlendirin.",
    references: [`${MDN}/Reporting-Endpoints`],
    evaluate(ev) {
      return ev.root.headers["report-to"]
        ? { status: "fail", evidence: `Report-To: ${ev.root.headers["report-to"].slice(0, 200)}`, location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-x-dns-prefetch-control",
    category: "headers",
    title: "X-DNS-Prefetch-Control açık (on)",
    severity: "INFO",
    cwe: "CWE-200",
    description: "X-DNS-Prefetch-Control: on; tarayıcı sayfadaki bağlantılar için önceden DNS çözümlemesi yapar. Bu, kullanıcının bir bağlantıya tıklamadan önce üçüncü taraf alan adlarına DNS sorgusu sızdırabilir (gizlilik).",
    remediation: "Gizlilik hassasiyeti olan sayfalarda X-DNS-Prefetch-Control: off kullanmayı değerlendirin.",
    references: [`${MDN}/X-DNS-Prefetch-Control`],
    evaluate(ev) {
      const v = ev.root.headers["x-dns-prefetch-control"];
      if (!v) return null;
      return v.trim().toLowerCase() === "on"
        ? { status: "fail", evidence: `X-DNS-Prefetch-Control: ${v}`, location: ev.root.url }
        : { status: "pass" };
    },
  },
  {
    id: "hx-document-policy",
    category: "headers",
    title: "Document-Policy başlığı kullanılıyor",
    severity: "INFO",
    description: "Document-Policy başlığı mevcut; belge düzeyinde özellik kısıtlamaları uygulanıyor. Bilgilendirme amaçlı tespit, yapılandırmanın amacınıza uygunluğunu doğrulayın.",
    remediation: "Document-Policy yönergelerinin beklenen kısıtlamaları uyguladığını gözden geçirin.",
    references: ["https://wicg.github.io/document-policy/"],
    evaluate(ev) {
      return ev.root.headers["document-policy"]
        ? { status: "fail", evidence: `Document-Policy: ${ev.root.headers["document-policy"].slice(0, 200)}`, location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-permissions-policy-report-only",
    category: "headers",
    title: "Permissions-Policy-Report-Only kullanılıyor",
    severity: "INFO",
    description: "Permissions-Policy-Report-Only başlığı mevcut; politika yalnızca raporlanıyor, uygulanmıyor. Bir geçiş/izleme aşaması olarak beklenmedikse zorunlu Permissions-Policy'ye geçilmelidir.",
    remediation: "Politikayı doğruladıktan sonra Permissions-Policy-Report-Only yerine zorunlu Permissions-Policy başlığını yayınlayın.",
    references: [`${MDN}/Permissions-Policy`],
    evaluate(ev) {
      return ev.root.headers["permissions-policy-report-only"]
        ? { status: "fail", evidence: "Permissions-Policy-Report-Only mevcut (uygulanmıyor)", location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-server-timing",
    category: "headers",
    title: "Server-Timing başlığı ifşa ediliyor",
    severity: "INFO",
    cwe: "CWE-200",
    description: "Server-Timing başlığı mevcut; arka uç işlem/DB/önbellek zamanlamalarını istemciye açar. Üretimde saldırganlara backend mimarisi ve yan-kanal zamanlama bilgisi sağlayabilir.",
    remediation: "Üretimde Server-Timing başlığını kaldırın veya yalnızca yetkili/geliştirme ortamlarıyla sınırlayın.",
    references: [`${MDN}/Server-Timing`],
    evaluate(ev) {
      return ev.root.headers["server-timing"]
        ? { status: "fail", evidence: `Server-Timing: ${ev.root.headers["server-timing"].slice(0, 200)}`, location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-etag-inode",
    category: "headers",
    title: "ETag inode tabanlı görünüyor (Apache FileETag)",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "ETag değeri inode-boyut-mtime biçiminde (Apache varsayılan FileETag); sunucu inode numarasını ve dosya zaman damgasını sızdırır, ayrıca yük dengeli sunucularda önbellek tutarsızlığına yol açar.",
    remediation: "Apache'de 'FileETag MTime Size' (veya 'FileETag None') ayarlayarak inode bileşenini kaldırın.",
    references: ["https://httpd.apache.org/docs/current/mod/core.html#fileetag"],
    evaluate(ev) {
      const v = ev.root.headers["etag"];
      if (!v) return null;
      return /^"?\d+-\d+-\d+/.test(v.trim())
        ? { status: "fail", evidence: `ETag: ${v}`, location: ev.root.url }
        : { status: "pass" };
    },
  },
  {
    id: "hx-x-cache",
    category: "headers",
    title: "X-Cache / X-Cache-Hits önbellek katmanını ifşa ediyor",
    severity: "INFO",
    cwe: "CWE-200",
    description: "X-Cache (veya X-Cache-Hits) başlığı mevcut; önünüzde bir önbellek/CDN katmanı (Varnish, CloudFront vb.) bulunduğunu ve isabet durumunu açığa çıkarır. Saldırganlara altyapı parmak izi verir.",
    remediation: "Üretimde X-Cache/X-Cache-Hits gibi hata ayıklama başlıklarını dış yanıtlardan çıkarın.",
    references: [`${MDN}/X-Cache`],
    evaluate(ev) {
      const hit = ev.root.headers["x-cache"] ?? ev.root.headers["x-cache-hits"];
      return hit
        ? { status: "fail", evidence: `X-Cache: ${hit.slice(0, 120)}`, location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-set-cookie-count",
    category: "headers",
    title: "Tek yanıtta aşırı sayıda Set-Cookie",
    severity: "LOW",
    cwe: "CWE-200",
    description: "Tek bir yanıtta 8'den fazla Set-Cookie başlığı gönderiliyor; aşırı çerez kullanımı takip/telemetri yoğunluğuna, gizlilik sorunlarına ve gereksiz istek başlığı şişkinliğine işaret eder.",
    remediation: "Çerez sayısını en aza indirin; oturum dışı verileri sunucu tarafı depolamaya taşıyın, üçüncü taraf/izleme çerezlerini gözden geçirin.",
    references: [`${MDN}/Set-Cookie`],
    evaluate(ev) {
      const n = ev.root.setCookies.length;
      if (n === 0) return null;
      return n > 8
        ? { status: "fail", evidence: `${n} adet Set-Cookie başlığı`, location: ev.root.url }
        : { status: "pass" };
    },
  },
  {
    id: "hx-content-dpr",
    category: "headers",
    title: "Content-DPR istemci ipuçları yanıtı",
    severity: "INFO",
    description: "Content-DPR yanıt başlığı mevcut; istemci ipuçları (client hints) tabanlı içerik uyarlaması kullanılıyor. Bilgilendirme amaçlı tespit.",
    remediation: "İstemci ipuçlarının yalnızca gerekli olduğunda ve güvenilir kökenlerle paylaşıldığını doğrulayın.",
    references: [`${MDN}/Content-DPR`],
    evaluate(ev) {
      return ev.root.headers["content-dpr"]
        ? { status: "fail", evidence: `Content-DPR: ${ev.root.headers["content-dpr"]}`, location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-accept-ch",
    category: "headers",
    title: "Accept-CH istemci ipuçları talep ediliyor",
    severity: "INFO",
    cwe: "CWE-200",
    description: "Accept-CH başlığı mevcut; sunucu tarayıcıdan cihaz/ağ istemci ipuçları (client hints) istiyor. Bazı ipuçları pasif parmak izi yüzeyini genişletebilir (gizlilik).",
    remediation: "Yalnızca gerçekten ihtiyaç duyulan istemci ipuçlarını talep edin; yüksek-entropili ipuçlarını gereksiz yere istemeyin.",
    references: [`${MDN}/Accept-CH`],
    evaluate(ev) {
      return ev.root.headers["accept-ch"]
        ? { status: "fail", evidence: `Accept-CH: ${ev.root.headers["accept-ch"].slice(0, 200)}`, location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-strict-transport-on-http",
    category: "headers",
    title: "HSTS başlığı düz HTTP yanıtında gönderiliyor",
    severity: "LOW",
    cwe: "CWE-319",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Strict-Transport-Security düz HTTP (http://) üzerinden döndürülüyor; tarayıcılar güvensiz bağlantıda gelen HSTS başlığını yok sayar, dolayısıyla bu koruma etkisizdir ve yanlış güvenlik hissi verir.",
    remediation: "HSTS'i yalnızca HTTPS yanıtlarında gönderin; düz HTTP isteklerini önce HTTPS'e yönlendirin.",
    references: ["https://datatracker.ietf.org/doc/html/rfc6797#section-7.2"],
    evaluate(ev) {
      if (!ev.root.url.startsWith("http://")) return null;
      return ev.root.headers["strict-transport-security"]
        ? { status: "fail", evidence: `HTTP yanıtında Strict-Transport-Security: ${ev.root.headers["strict-transport-security"]}`, location: ev.root.url }
        : { status: "pass" };
    },
  },
  {
    id: "hx-x-frame-and-csp-both",
    category: "headers",
    title: "Clickjacking için derinlemesine savunma (XFO + CSP frame-ancestors)",
    severity: "INFO",
    description: "Hem X-Frame-Options hem de CSP frame-ancestors mevcut; çerçeveleme koruması derinlemesine savunma ile uygulanmış. Bu olumlu bir bulgudur.",
    remediation: "İki başlığın da aynı çerçeveleme politikasını yansıttığından emin olun (uyumsuzlukta CSP frame-ancestors modern tarayıcılarda önceliklidir).",
    references: [`${MDN}/Content-Security-Policy/frame-ancestors`],
    evaluate(ev) {
      const xfo = ev.root.headers["x-frame-options"];
      const csp = ev.root.headers["content-security-policy"];
      if (!xfo || !csp) return null;
      return /frame-ancestors/i.test(csp)
        ? { status: "pass" }
        : null;
    },
  },
  {
    id: "hx-cache-control-immutable-html",
    category: "headers",
    title: "HTML yanıtında Cache-Control: immutable",
    severity: "LOW",
    cwe: "CWE-525",
    owasp: "A05:2021 Security Misconfiguration",
    description: "HTML belgesi Cache-Control içinde immutable ile işaretlenmiş; tarayıcı içeriği doğrulama yapmadan yeniden kullanır. HTML için bu, kullanıcıların güncellenmiş/yamalı içeriği alamamasına ve bayat sayfa gösterimine yol açar.",
    remediation: "immutable yalnızca sürümlü statik varlıklar (hash'li JS/CSS) için kullanılmalıdır; HTML belgelerinde no-cache veya kısa max-age tercih edin.",
    references: [`${MDN}/Cache-Control`],
    evaluate(ev) {
      const ct = ev.root.contentType || ev.root.headers["content-type"] || "";
      if (!/text\/html/i.test(ct)) return null;
      const cc = ev.root.headers["cache-control"];
      if (!cc) return null;
      return /immutable/i.test(cc)
        ? { status: "fail", evidence: `Cache-Control: ${cc}`, location: ev.root.url }
        : { status: "pass" };
    },
  },
  {
    id: "hx-x-content-security-policy-legacy",
    category: "headers",
    title: "Eski/deprecated CSP başlığı (X-Content-Security-Policy / X-WebKit-CSP)",
    severity: "INFO",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Kullanımdan kaldırılmış X-Content-Security-Policy veya X-WebKit-CSP başlığı gönderiliyor; modern tarayıcılar bunları yok sayar. Yalnızca bu eski başlıklara güveniliyorsa CSP koruması etkisizdir.",
    remediation: "Eski başlıkları kaldırıp standart Content-Security-Policy başlığını kullanın.",
    references: [`${MDN}/Content-Security-Policy`],
    evaluate(ev) {
      const legacy = ev.root.headers["x-content-security-policy"] ?? ev.root.headers["x-webkit-csp"];
      return legacy
        ? { status: "fail", evidence: "Eski CSP başlığı kullanılıyor (X-Content-Security-Policy / X-WebKit-CSP)", location: ev.root.url }
        : null;
    },
  },
  {
    id: "hx-pragma-no-cache-only",
    category: "headers",
    title: "Pragma: no-cache modern Cache-Control olmadan",
    severity: "INFO",
    cwe: "CWE-525",
    description: "Pragma: no-cache gönderiliyor ancak modern bir Cache-Control başlığı yok; Pragma yalnızca HTTP/1.0 için geçerli ve tutarsız bir denetimdir, HTTP/1.1 istemcileri/ara sunucular önbelleklemeyi Cache-Control'e göre yapar.",
    remediation: "Önbelleklemeyi denetlemek için açık bir Cache-Control (örn. no-store, no-cache) başlığı ekleyin; yalnızca Pragma'ya güvenmeyin.",
    references: [`${MDN}/Pragma`],
    evaluate(ev) {
      const pragma = ev.root.headers["pragma"];
      if (!pragma || !/no-cache/i.test(pragma)) return null;
      return ev.root.headers["cache-control"]
        ? { status: "pass" }
        : { status: "fail", evidence: `Pragma: ${pragma} (Cache-Control yok)`, location: ev.root.url };
    },
  },

  // --- Email / DNS extras ----------------------------------------------------
  {
    id: "ex-tls-rpt",
    category: "dns-email",
    title: "TLS-RPT (SMTP TLS raporlama) kaydı yok",
    severity: "LOW",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Alan adının MX kaydı var ancak TXT kayıtları arasında bir TLSRPTv1 (SMTP TLS Reporting) kaydı bulunamadı; e-posta aktarımında TLS başarısızlıkları ve indirgeme saldırıları hakkında rapor alamazsınız.",
    remediation: "_smtp._tls.<alan> altına bir TXT kaydı ekleyin: v=TLSRPTv1; rua=mailto:tlsrpt@<alan>",
    references: ["https://datatracker.ietf.org/doc/html/rfc8460"],
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.mx.length === 0) return null;
      const hasTlsRpt = ev.dns.txt.some((t) => t.trim().toLowerCase().startsWith("v=tlsrptv1"));
      return hasTlsRpt
        ? { status: "pass" }
        : { status: "fail", evidence: `${ev.dns.mx.length} MX kaydı var, TLSRPTv1 TXT kaydı yok`, location: ev.host };
    },
  },
  {
    id: "ex-bimi",
    category: "dns-email",
    title: "BIMI eklenebilir (DMARC uygulaması hazır)",
    severity: "INFO",
    confidence: "tentative",
    description: "DMARC politikanız reject/quarantine olduğundan alan adınız BIMI (Brand Indicators for Message Identification) için uygundur; ancak BIMI seçici-özel bir DNS kaydıdır ve mevcut TXT verisinden doğrudan tespit edilemez. Bu yalnızca bir fırsat işaretidir.",
    remediation: "Marka logosunu doğrulanmış gönderenlerde göstermek için default._bimi.<alan> altına bir BIMI TXT kaydı (v=BIMI1; l=...; a=...) eklemeyi değerlendirin.",
    references: ["https://datatracker.ietf.org/doc/html/draft-brand-indicators-for-message-identification"],
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      const dmarc = ev.dns.dmarc;
      if (!dmarc) return null;
      const enforced = /p=\s*(reject|quarantine)/i.test(dmarc);
      if (!enforced) return null;
      const hasBimi = ev.dns.txt.some((t) => t.trim().toLowerCase().startsWith("v=bimi1"));
      if (hasBimi) return { status: "pass" };
      return { status: "fail", confidence: "tentative", evidence: "DMARC uygulanıyor; BIMI TXT kaydı tespit edilmedi (seçici-özel olduğundan kesin değildir)", location: ev.host };
    },
  },
  {
    id: "ex-spf-redirect",
    category: "dns-email",
    title: "SPF redirect= ile devrediliyor",
    severity: "INFO",
    description: "SPF kaydı redirect= modifikatörü içeriyor; SPF politikası başka bir alan adına devredilmiş. Bilgilendirme amaçlıdır — devredilen alanın politikasının beklediğiniz kadar sıkı olduğunu doğrulayın.",
    remediation: "redirect= ile işaret edilen alanın SPF politikasını gözden geçirin; 'all' mekanizması ile birlikte kullanmayın (redirect yalnızca eşleşme olmadığında geçerlidir).",
    references: ["https://datatracker.ietf.org/doc/html/rfc7208#section-6.1"],
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      const spf = ev.dns.spf;
      if (!spf) return null;
      return /redirect=/i.test(spf)
        ? { status: "fail", evidence: spf, location: ev.host }
        : { status: "pass" };
    },
  },
  {
    id: "ex-dmarc-sp-explicit-none",
    category: "dns-email",
    title: "DMARC sp=none — alt alan adları korumasız",
    severity: "MEDIUM",
    cwe: "CWE-16",
    owasp: "A05:2021 Security Misconfiguration",
    description: "DMARC kaydında açıkça sp=none belirtilmiş; ana alan adı için politika ne olursa olsun alt alan adları için hiçbir DMARC yaptırımı uygulanmaz. Saldırganlar var olmayan alt alan adlarından sizin adınıza sahte e-posta gönderebilir.",
    remediation: "DMARC kaydında sp= değerini quarantine veya reject yapın (veya alt politika ana p= ile aynı olsun diye sp'yi kaldırın).",
    references: ["https://datatracker.ietf.org/doc/html/rfc7489#section-6.3"],
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      const dmarc = ev.dns.dmarc;
      if (!dmarc) return null;
      return /sp=\s*none/i.test(dmarc)
        ? { status: "fail", evidence: dmarc, location: ev.host }
        : { status: "pass" };
    },
  },
  {
    id: "ex-spf-all-double",
    category: "dns-email",
    title: "SPF hem redirect= hem 'all' mekanizması içeriyor (çakışma)",
    severity: "LOW",
    owasp: "A05:2021 Security Misconfiguration",
    description: "SPF kaydı hem bir redirect= modifikatörü hem de bir 'all' mekanizması içeriyor; RFC 7208'e göre bir 'all' mekanizması varsa redirect= hiçbir zaman değerlendirilmez. Bu, devretme niyetinin sessizce göz ardı edilmesine yol açan bir yapılandırma çakışmasıdır.",
    remediation: "Devretme isteniyorsa 'all' mekanizmasını kaldırın; aksi halde redirect= yerine include: kullanın ve tek bir 'all' ile bitirin.",
    references: ["https://datatracker.ietf.org/doc/html/rfc7208#section-6.1"],
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      const spf = ev.dns.spf;
      if (!spf) return null;
      const hasRedirect = /redirect=/i.test(spf);
      const hasAll = /[-~+?]all\b/i.test(spf) || /\ball\b/i.test(spf);
      return hasRedirect && hasAll
        ? { status: "fail", evidence: spf, location: ev.host }
        : { status: "pass" };
    },
  },
];
