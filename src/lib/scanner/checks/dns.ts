// DNS & e-posta güvenliği kontrol kataloğu (kategori: "dns-email").
//
// Bu modüldeki tüm kontroller SADECE `ev.dns` (DnsEvidence), `ev.host` ve
// `ev.target` üzerinden çalışan SAF fonksiyonlardır — ağ isteği yapmazlar.
// Kanıt tek seferde toplanır (resolver) ve buradaki her kontrol o anlık
// görüntü üzerinde değerlendirilir.
//
// TEMEL KURAL: `ev.dns.resolved === false` ise alan adı çözülememiştir; bu
// durumda DNS'e dair hiçbir şey iddia edemeyiz, bu yüzden HER kontrol `null`
// (N/A) döner. Bir kontrol yalnızca somut kanıt varken "fail" üretir,
// uygulanıp temiz çıktığında "pass" döner, ilgisizse `null`.
import type { Check } from "./types";

// ---------------------------------------------------------------------------
// Yardımcı ayrıştırıcılar (dışa aktarılmaz; bu dosyaya özeldir).
// ---------------------------------------------------------------------------

type AllQualifier = "+" | "-" | "~" | "?";

// SPF'nin sonundaki `all` mekanizmasının niteleyicisini döndürür.
// Niteleyicisiz `all` varsayılan olarak `+all` demektir (RFC7208 §5.1).
// `all` mekanizması hiç yoksa null döner.
function spfAllQualifier(spf: string): AllQualifier | null {
  const m = spf.match(/(^|\s)([+\-~?]?)all(\s|$)/i);
  if (!m) return null;
  const q = m[2];
  return (q === "" ? "+" : (q as AllQualifier));
}

// SPF içindeki DNS-lookup üreten `include:` mekanizması sayısı.
function spfIncludeCount(spf: string): number {
  const m = spf.match(/include:/gi);
  return m ? m.length : 0;
}

// DMARC etiket değeri ayrıştırıcı (örn. tag="p" → "reject").
function dmarcTag(dmarc: string, tag: string): string | undefined {
  const m = dmarc.match(new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;\\s]+)`, "i"));
  return m ? m[1].toLowerCase() : undefined;
}

// DMARC/politika güç sıralaması: none < quarantine < reject.
function policyStrength(p: string | undefined): number {
  switch (p) {
    case "reject":
      return 3;
    case "quarantine":
      return 2;
    case "none":
      return 1;
    default:
      return 0;
  }
}

// Bir host'un kayıt edilebilir (registrable) alan adına kaba yaklaşım:
// son iki etiket. NS çeşitliliği için "aynı sağlayıcı mı" sezgisinde yeterli.
function registrable(host: string): string {
  const parts = host.replace(/\.$/, "").toLowerCase().split(".");
  if (parts.length <= 2) return parts.join(".");
  return parts.slice(-2).join(".");
}

const RFC7208 = "https://datatracker.ietf.org/doc/html/rfc7208";
const RFC7489 = "https://datatracker.ietf.org/doc/html/rfc7489";
const RFC6376 = "https://datatracker.ietf.org/doc/html/rfc6376";
const RFC8461 = "https://datatracker.ietf.org/doc/html/rfc8461";
const RFC8659 = "https://datatracker.ietf.org/doc/html/rfc8659";

// ---------------------------------------------------------------------------

export const DNS_EMAIL_CHECKS: Check[] = [
  // ----------------------------- Çözümleme --------------------------------
  {
    id: "dns-resolution",
    category: "dns-email",
    title: "DNS çözümlemesi",
    severity: "INFO",
    cwe: "CWE-16",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Alan adının DNS'te çözülebildiğini ve en az bir A/AAAA kaydına sahip olduğunu doğrular. " +
      "Diğer DNS kontrollerinin çalışabilmesi için temel gerekliliktir.",
    remediation:
      "Alan adı çözülemiyorsa yetkili ad sunucularınızı (NS) ve bölge (zone) yapılandırmanızı denetleyin.",
    references: ["https://developer.mozilla.org/en-US/docs/Glossary/DNS"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      const total = ev.dns.a.length + ev.dns.aaaa.length;
      if (total === 0) return null;
      return { status: "pass" };
    },
  },

  // ------------------------------- SPF ------------------------------------
  {
    id: "dns-spf-missing",
    category: "dns-email",
    title: "SPF kaydı yok",
    severity: "HIGH",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "SPF (Sender Policy Framework), alan adınız adına hangi sunucuların e-posta gönderebileceğini " +
      "belirtir. SPF olmadan saldırganlar alan adınızı taklit ederek (spoofing) sahte e-posta gönderebilir.",
    remediation:
      "Bir `v=spf1` TXT kaydı yayınlayın. Örnek: `v=spf1 include:_spf.google.com -all`. " +
      "Yalnızca meşru gönderen sunucularınızı listeleyip `-all` ile bitirin.",
    references: [RFC7208],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.spf) return { status: "pass" };
      if (ev.dns.txtResolved === false) return null; // TXT lookup failed → can't conclude "missing"
      if (ev.dns.mx.length > 0) {
        return {
          status: "fail",
          severity: "HIGH",
          confidence: "confirmed",
          evidence: `MX kayıtları mevcut (${ev.dns.mx.length}) fakat hiçbir «v=spf1» TXT kaydı bulunamadı.`,
        };
      }
      return {
        status: "fail",
        severity: "LOW",
        confidence: "firm",
        evidence:
          "MX kaydı yok; yine de bu alan adının e-posta gönderiminde kötüye kullanılmasını önlemek için `v=spf1 -all` yayınlanması önerilir.",
      };
    },
  },
  {
    id: "dns-spf-all-plus",
    category: "dns-email",
    title: "SPF «+all» — herkese izin veriyor",
    severity: "HIGH",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "SPF kaydı `+all` (veya niteleyicisiz `all`) ile bitiyor; bu, İNTERNETTEKİ HERHANGİ bir sunucunun " +
      "alan adınız adına e-posta göndermesini SPF açısından geçerli kılar ve SPF'yi tamamen etkisiz bırakır.",
    remediation: "`+all`/`all` ifadesini `-all` (hardfail) ile değiştirin.",
    references: [RFC7208],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.spf) return null;
      const q = spfAllQualifier(ev.dns.spf);
      if (q !== "+") return null;
      return {
        status: "fail",
        severity: "HIGH",
        confidence: "confirmed",
        evidence: `SPF: «${ev.dns.spf}» — «all» niteleyicisi «+» (herkese izin).`,
      };
    },
  },
  {
    id: "dns-spf-all-neutral",
    category: "dns-email",
    title: "SPF «?all» — nötr (koruma yok)",
    severity: "MEDIUM",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "SPF kaydı `?all` (neutral) ile bitiyor. Nötr politika, eşleşmeyen göndericiler için hiçbir yorum " +
      "yapılmamasını söyler; pratikte spoofing'e karşı koruma sağlamaz.",
    remediation: "`?all` yerine `-all` (hardfail) veya en azından `~all` (softfail) kullanın.",
    references: [RFC7208],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.spf) return null;
      const q = spfAllQualifier(ev.dns.spf);
      if (q !== "?") return null;
      return {
        status: "fail",
        severity: "MEDIUM",
        confidence: "confirmed",
        evidence: `SPF: «${ev.dns.spf}» — «all» niteleyicisi «?» (nötr).`,
      };
    },
  },
  {
    id: "dns-spf-all-softfail",
    category: "dns-email",
    title: "SPF «~all» — softfail",
    severity: "INFO",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "SPF kaydı `~all` (softfail) ile bitiyor. Kabul edilebilir bir yapılandırmadır: eşleşmeyen postalar " +
      "genelde şüpheli işaretlenir ama reddedilmez.",
    remediation:
      "Tam koruma için gönderen altyapınızı doğruladıktan sonra `~all` yerine `-all` (hardfail) kullanmayı değerlendirin.",
    references: [RFC7208],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.spf) return null;
      const q = spfAllQualifier(ev.dns.spf);
      if (q !== "~") return null;
      return {
        status: "pass",
        detail: `SPF softfail (~all) kullanılıyor: «${ev.dns.spf}». Kabul edilebilir; -all daha güvenlidir.`,
      };
    },
  },
  {
    id: "dns-spf-hardfail",
    category: "dns-email",
    title: "SPF «-all» — hardfail (en güçlü)",
    severity: "INFO",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "SPF kaydı `-all` (hardfail) ile bitiyor. Listelenmemiş gönderenlerin reddedilmesini söyleyen en güçlü " +
      "SPF politikasıdır ve doğrulanmış iyi yapılandırma olarak kaydedilir.",
    remediation: "Değişiklik gerekmiyor; gönderen listenizi güncel tutun.",
    references: [RFC7208],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.spf) return null;
      const q = spfAllQualifier(ev.dns.spf);
      if (q !== "-") return null;
      return { status: "pass" };
    },
  },
  {
    id: "dns-spf-all-missing",
    category: "dns-email",
    title: "SPF «all» mekanizması yok",
    severity: "MEDIUM",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "SPF kaydı mevcut fakat sonlandırıcı bir `all` mekanizması (ör. `-all`, `~all`) içermiyor ve bir " +
      "`redirect=` de yok. Belirsiz sonlanan SPF, alıcı sunucularda tutarsız değerlendirilir.",
    remediation: "SPF kaydını açık bir `-all` veya `~all` ile sonlandırın.",
    references: [RFC7208],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.spf) return null;
      const hasAll = spfAllQualifier(ev.dns.spf) !== null;
      const hasRedirect = /redirect=/i.test(ev.dns.spf);
      if (hasAll || hasRedirect) return { status: "pass" };
      return {
        status: "fail",
        severity: "MEDIUM",
        confidence: "firm",
        evidence: `SPF: «${ev.dns.spf}» — sonlandırıcı «all» mekanizması ve «redirect=» yok.`,
      };
    },
  },
  {
    id: "dns-spf-lookup-limit",
    category: "dns-email",
    title: "SPF DNS-lookup sınırı riski",
    severity: "MEDIUM",
    cwe: "CWE-400",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "RFC7208, SPF değerlendirmesi sırasında en fazla 10 DNS sorgusuna izin verir. Çok sayıda `include:` " +
      "bu sınırı aşarak SPF'nin «permerror» ile başarısız olmasına ve meşru postaların düşmesine yol açar.",
    remediation:
      "`include:` sayısını azaltın; SPF'yi düzleştirin (flattening) veya kullanılmayan gönderenleri kaldırın.",
    references: [RFC7208],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.spf) return null;
      const includes = spfIncludeCount(ev.dns.spf);
      if (includes > 10) {
        return {
          status: "fail",
          severity: "MEDIUM",
          confidence: "firm",
          evidence: `SPF ${includes} adet «include:» içeriyor (RFC7208 10-lookup sınırı aşılıyor).`,
        };
      }
      return { status: "pass" };
    },
  },
  {
    id: "dns-spf-ptr",
    category: "dns-email",
    title: "SPF «ptr» mekanizması (kullanımdan kalkmış)",
    severity: "LOW",
    cwe: "CWE-16",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "SPF kaydı `ptr` mekanizması kullanıyor. RFC7208 bu mekanizmayı yavaş ve güvenilmez olduğu için " +
      "KULLANMAMANIZI tavsiye eder; bazı alıcılar tarafından yok sayılır.",
    remediation: "`ptr` yerine `ip4:`/`ip6:` veya `include:` mekanizmalarını kullanın.",
    references: [RFC7208],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.spf) return null;
      if (/(^|\s)[+\-~?]?ptr(\b|:)/i.test(ev.dns.spf)) {
        return {
          status: "fail",
          severity: "LOW",
          confidence: "confirmed",
          evidence: `SPF: «${ev.dns.spf}» — kullanımdan kalkmış «ptr» mekanizması içeriyor.`,
        };
      }
      return { status: "pass" };
    },
  },
  {
    id: "dns-spf-multiple",
    category: "dns-email",
    title: "Birden fazla SPF kaydı",
    severity: "MEDIUM",
    cwe: "CWE-16",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Bir alan adında birden fazla `v=spf1` TXT kaydı bulunması RFC7208'e aykırıdır ve SPF'nin " +
      "«permerror» ile başarısız olmasına neden olur; SPF fiilen devre dışı kalır.",
    remediation: "Tüm gönderen kaynaklarını TEK bir `v=spf1` kaydında birleştirin.",
    references: [RFC7208],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      const spfRecords = ev.dns.txt.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
      if (spfRecords.length > 1) {
        return {
          status: "fail",
          severity: "MEDIUM",
          confidence: "confirmed",
          evidence: `${spfRecords.length} adet «v=spf1» TXT kaydı bulundu; yalnızca bir tane olmalı.`,
        };
      }
      if (spfRecords.length === 1) return { status: "pass" };
      return null;
    },
  },

  // ------------------------------- DMARC ----------------------------------
  {
    id: "dns-dmarc-missing",
    category: "dns-email",
    title: "DMARC kaydı yok",
    severity: "HIGH",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "DMARC, SPF/DKIM sonuçlarına göre sahte postalara ne yapılacağını (izle/karantina/reddet) tanımlar ve " +
      "raporlama sağlar. DMARC olmadan spoofing'e karşı uygulanabilir bir politika yoktur.",
    remediation:
      "`_dmarc` alt alan adında bir TXT kaydı yayınlayın: `v=DMARC1; p=reject; rua=mailto:dmarc@ornek.com`. " +
      "`p=none` ile başlayıp raporları izleyerek `p=reject`'e ilerleyin.",
    references: [RFC7489],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.dmarc) return { status: "pass" };
      if (ev.dns.txtResolved === false) return null; // DNS TXT flaky → can't conclude "missing"
      // DMARC yalnızca posta gönderen/alan bir alan için anlamlı; MX veya SPF yoksa da öneririz.
      const relevant = ev.dns.mx.length > 0 || Boolean(ev.dns.spf);
      return {
        status: "fail",
        severity: relevant ? "HIGH" : "LOW",
        confidence: "confirmed",
        evidence: relevant
          ? "MX/SPF mevcut fakat «_dmarc» TXT kaydı (v=DMARC1) bulunamadı."
          : "«_dmarc» TXT kaydı yok; spoofing'i önlemek için yine de yayınlanması önerilir.",
      };
    },
  },
  {
    id: "dns-dmarc-policy-none",
    category: "dns-email",
    title: "DMARC «p=none» — yalnızca izleme",
    severity: "MEDIUM",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "DMARC politikası `p=none`. Bu yalnızca izleme (monitoring) modudur: sahte postalar raporlanır ama " +
      "engellenmez. Uygulanabilir bir koruma sağlamaz.",
    remediation:
      "Raporları inceleyip meşru göndericileri hizaladıktan sonra `p=quarantine`, ardından `p=reject`'e geçin.",
    references: [RFC7489],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.dmarc) return null;
      const p = ev.dns.dmarcPolicy ?? dmarcTag(ev.dns.dmarc, "p");
      if (p === "none") {
        return {
          status: "fail",
          severity: "MEDIUM",
          confidence: "confirmed",
          evidence: `DMARC: «${ev.dns.dmarc}» — p=none (yalnızca izleme).`,
        };
      }
      if (p === "quarantine" || p === "reject") return { status: "pass" };
      return null;
    },
  },
  {
    id: "dns-dmarc-policy-quarantine",
    category: "dns-email",
    title: "DMARC «p=quarantine»",
    severity: "INFO",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "DMARC politikası `p=quarantine`. Sahte postalar spam/karantinaya yönlendirilir. İyi bir seviyedir " +
      "ancak en güçlü koruma `p=reject`'tir.",
    remediation: "Raporlarda yanlış-pozitif olmadığını doğruladıktan sonra `p=reject`'e yükseltin.",
    references: [RFC7489],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.dmarc) return null;
      const p = ev.dns.dmarcPolicy ?? dmarcTag(ev.dns.dmarc, "p");
      if (p === "quarantine") {
        return {
          status: "fail",
          severity: "INFO",
          confidence: "confirmed",
          evidence: `DMARC: «${ev.dns.dmarc}» — p=quarantine.`,
        };
      }
      return null;
    },
  },
  {
    id: "dns-dmarc-policy-reject",
    category: "dns-email",
    title: "DMARC «p=reject» (en güçlü)",
    severity: "INFO",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "DMARC politikası `p=reject`. Doğrulamayı geçemeyen postalar reddedilir; alan adı taklidi için en güçlü " +
      "korumadır ve doğrulanmış iyi yapılandırma olarak kaydedilir.",
    remediation: "Değişiklik gerekmiyor; DMARC raporlarını izlemeye devam edin.",
    references: [RFC7489],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.dmarc) return null;
      const p = ev.dns.dmarcPolicy ?? dmarcTag(ev.dns.dmarc, "p");
      if (p === "reject") return { status: "pass" };
      return null;
    },
  },
  {
    id: "dns-dmarc-rua-missing",
    category: "dns-email",
    title: "DMARC toplu rapor adresi (rua) yok",
    severity: "LOW",
    cwe: "CWE-778",
    owasp: "A09:2021 Security Logging and Monitoring Failures",
    description:
      "DMARC kaydında `rua=` (toplu/aggregate rapor) adresi tanımlı değil. Rapor almadan, spoofing " +
      "denemelerini ve SPF/DKIM hizalama sorunlarını göremezsiniz.",
    remediation: "DMARC kaydına `rua=mailto:dmarc@ornek.com` ekleyin ve raporları düzenli inceleyin.",
    references: [RFC7489],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.dmarc) return null;
      if (dmarcTag(ev.dns.dmarc, "rua")) return { status: "pass" };
      return {
        status: "fail",
        severity: "LOW",
        confidence: "firm",
        evidence: `DMARC: «${ev.dns.dmarc}» — «rua=» toplu rapor adresi tanımlı değil.`,
      };
    },
  },
  {
    id: "dns-dmarc-ruf-missing",
    category: "dns-email",
    title: "DMARC adli rapor adresi (ruf) yok",
    severity: "INFO",
    cwe: "CWE-778",
    owasp: "A09:2021 Security Logging and Monitoring Failures",
    description:
      "DMARC kaydında `ruf=` (adli/forensic rapor) adresi yok. İsteğe bağlıdır; olay başına ayrıntılı örnek " +
      "sağlar ama gizlilik nedeniyle her zaman tercih edilmez.",
    remediation:
      "Ayrıntılı olay incelemesi isterseniz `ruf=mailto:...` ekleyin; kişisel veri içerebileceğini unutmayın.",
    references: [RFC7489],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.dmarc) return null;
      if (dmarcTag(ev.dns.dmarc, "ruf")) return { status: "pass" };
      return {
        status: "fail",
        severity: "INFO",
        confidence: "firm",
        evidence: `DMARC: «${ev.dns.dmarc}» — «ruf=» adli rapor adresi tanımlı değil (opsiyonel).`,
      };
    },
  },
  {
    id: "dns-dmarc-subdomain-policy",
    category: "dns-email",
    title: "DMARC alt alan politikası (sp) daha zayıf",
    severity: "MEDIUM",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "DMARC kaydındaki `sp=` (alt alan politikası) ana `p=` politikasından daha zayıf. Saldırganlar korumasız " +
      "alt alan adlarını (ör. rastgele.ornek.com) kullanarak spoofing yapabilir.",
    remediation: "`sp=`'yi `p=` ile aynı güçte (örn. `sp=reject`) ayarlayın veya `sp=` etiketini kaldırın.",
    references: [RFC7489],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.dmarc) return null;
      const sp = dmarcTag(ev.dns.dmarc, "sp");
      if (!sp) return null; // sp yoksa p miras alınır — sorun yok
      const p = ev.dns.dmarcPolicy ?? dmarcTag(ev.dns.dmarc, "p");
      if (policyStrength(sp) < policyStrength(p)) {
        return {
          status: "fail",
          severity: "MEDIUM",
          confidence: "firm",
          evidence: `DMARC: p=${p ?? "?"} fakat sp=${sp} (alt alan politikası daha zayıf).`,
        };
      }
      return { status: "pass" };
    },
  },
  {
    id: "dns-dmarc-pct",
    category: "dns-email",
    title: "DMARC «pct» %100'den küçük",
    severity: "LOW",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "DMARC `pct=` değeri %100'den küçük; politika postaların yalnızca bir kısmına uygulanıyor. Kalan yüzde " +
      "için koruma yoktur ve saldırganlar filtreyi atlayabilir.",
    remediation: "Geçiş tamamlandığında `pct` değerini 100'e çıkarın (veya etiketi kaldırın; varsayılan 100'dür).",
    references: [RFC7489],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.dmarc) return null;
      const pctRaw = dmarcTag(ev.dns.dmarc, "pct");
      if (pctRaw === undefined) return { status: "pass" }; // varsayılan 100
      const pct = Number.parseInt(pctRaw, 10);
      if (Number.isFinite(pct) && pct < 100) {
        return {
          status: "fail",
          severity: "LOW",
          confidence: "firm",
          evidence: `DMARC: «${ev.dns.dmarc}» — pct=${pct} (%100'den küçük; kısmi uygulama).`,
        };
      }
      return { status: "pass" };
    },
  },
  {
    id: "dns-dmarc-relaxed-alignment",
    category: "dns-email",
    title: "DMARC gevşek hizalama (adkim/aspf=r)",
    severity: "INFO",
    cwe: "CWE-290",
    owasp: "A07:2021 Identification and Authentication Failures",
    description:
      "DMARC hizalaması `adkim=r` ve/veya `aspf=r` (relaxed) ile gevşek. Kabul edilebilir bir varsayılandır " +
      "ancak katı hizalama (`s`) alt alan adı bazlı taklit denemelerini daha iyi engeller.",
    remediation:
      "Alt alan hizalama saldırılarına karşı sıkılaştırmak için `adkim=s; aspf=s` kullanmayı değerlendirin.",
    references: [RFC7489],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved || !ev.dns.dmarc) return null;
      const adkim = dmarcTag(ev.dns.dmarc, "adkim") ?? "r";
      const aspf = dmarcTag(ev.dns.dmarc, "aspf") ?? "r";
      if (adkim === "r" || aspf === "r") {
        return {
          status: "fail",
          severity: "INFO",
          confidence: "firm",
          evidence: `DMARC hizalama: adkim=${adkim}, aspf=${aspf} (gevşek).`,
        };
      }
      return { status: "pass" };
    },
  },

  // -------------------------------- DKIM ----------------------------------
  {
    id: "dns-dkim-presence",
    category: "dns-email",
    title: "DKIM doğrulanamadı",
    severity: "INFO",
    cwe: "CWE-345",
    owasp: "A08:2021 Software and Data Integrity Failures",
    description:
      "DKIM, giden postaları kriptografik olarak imzalayarak bütünlüğü ve kaynağı doğrular. Seçici (selector) " +
      "adları alana özgü olduğundan pasif olarak kesin tespit edilemez; bu not yalnızca yaygın seçicilerde " +
      "kayıt bulunamadığını belirtir (kesin değildir).",
    remediation:
      "Posta sağlayıcınızın DKIM anahtarını yayınlayın ve giden postaları imzalayın; seçicinin " +
      "`<selector>._domainkey.<alan>` altında çözüldüğünü doğrulayın.",
    references: [RFC6376],
    confidence: "tentative",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.mx.length === 0) return null; // posta yoksa DKIM anlamsız
      if (ev.dns.dkimHint === true) return { status: "pass" };
      if (ev.dns.dkimHint === false) {
        return {
          status: "fail",
          severity: "INFO",
          confidence: "tentative",
          evidence:
            "Yaygın DKIM seçici sorgularında kayıt bulunamadı; DKIM yapılandırılmamış olabilir (pasif tespit, kesin değil).",
        };
      }
      return null; // ipucu yok — iddia etmiyoruz
    },
  },

  // ------------------------------ MTA-STS ---------------------------------
  {
    id: "dns-mta-sts",
    category: "dns-email",
    title: "MTA-STS yok",
    severity: "LOW",
    cwe: "CWE-319",
    owasp: "A02:2021 Cryptographic Failures",
    description:
      "MTA-STS, gelen posta sunucularına TLS zorunluluğu getirerek e-posta aktarımını düşürme (downgrade) ve " +
      "ortadaki adam (MITM) saldırılarına karşı korur. Tanımlı olmaması aktarım şifrelemesini opsiyonel bırakır.",
    remediation:
      "`_mta-sts.<alan>` TXT kaydını ve `https://mta-sts.<alan>/.well-known/mta-sts.txt` politikasını yayınlayın (mode: enforce).",
    references: [RFC8461],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.mx.length === 0) return null;
      if (ev.dns.mtaSts) return { status: "pass" };
      return {
        status: "fail",
        severity: "LOW",
        confidence: "firm",
        evidence: "MX mevcut fakat MTA-STS (`_mta-sts` TXT) tespit edilmedi.",
      };
    },
  },

  // --------------------------- DNS hijyeni --------------------------------
  {
    id: "dns-caa-missing",
    category: "dns-email",
    title: "CAA kaydı yok",
    severity: "LOW",
    cwe: "CWE-295",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "CAA (Certification Authority Authorization) kaydı, hangi sertifika otoritelerinin (CA) alan adınıza " +
      "sertifika kesebileceğini kısıtlar. Kayıt yoksa HERHANGİ bir CA sertifika kesebilir; hatalı/kötü niyetli " +
      "sertifika ihraç riski artar.",
    remediation:
      "Bir CAA kaydı yayınlayın: `0 issue \"letsencrypt.org\"` gibi. Yalnızca kullandığınız CA'ları listeleyin.",
    references: [RFC8659],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.caa.length > 0) return { status: "pass" };
      return {
        status: "fail",
        severity: "LOW",
        confidence: "confirmed",
        evidence: "Alan adında CAA kaydı bulunamadı; herhangi bir CA sertifika kesebilir.",
      };
    },
  },
  {
    id: "dns-caa-present",
    category: "dns-email",
    title: "CAA kaydı mevcut",
    severity: "INFO",
    cwe: "CWE-295",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Alan adı, sertifika ihracını yetkili CA'larla sınırlayan bir CAA kaydına sahip. Doğrulanmış iyi " +
      "yapılandırma olarak kaydedilir.",
    remediation: "Kullandığınız CA'lar değiştikçe CAA kaydını güncel tutun.",
    references: [RFC8659],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.caa.length > 0) return { status: "pass" };
      return null;
    },
  },
  {
    id: "dns-caa-iodef",
    category: "dns-email",
    title: "CAA «iodef» olay bildirimi yok",
    severity: "INFO",
    cwe: "CWE-778",
    owasp: "A09:2021 Security Logging and Monitoring Failures",
    description:
      "CAA kaydı var ancak `iodef` (olay bildirim) adresi tanımlı değil. `iodef`, politika ihlali içeren bir " +
      "sertifika ihraç denemesinde CA'nın sizi uyarmasını sağlar.",
    remediation: "CAA kaydına `0 iodef \"mailto:security@ornek.com\"` ekleyin.",
    references: [RFC8659],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.caa.length === 0) return null; // caa yoksa dns-caa-missing kapsıyor
      const hasIodef = ev.dns.caa.some((r) => /iodef/i.test(r));
      if (hasIodef) return { status: "pass" };
      return {
        status: "fail",
        severity: "INFO",
        confidence: "firm",
        evidence: "CAA kaydı mevcut fakat «iodef» olay bildirim adresi tanımlı değil.",
      };
    },
  },
  {
    id: "dns-ipv6-missing",
    category: "dns-email",
    title: "IPv6 (AAAA) kaydı yok",
    severity: "INFO",
    cwe: "CWE-16",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Alan adının AAAA (IPv6) kaydı yok. Bu bir güvenlik açığı DEĞİLDİR; yalnızca IPv6 istemcileri için " +
      "erişilebilirliği ve gelecek uyumluluğu etkileyen bilgilendirici bir tespittir.",
    remediation: "IPv6 desteği istiyorsanız altyapınız için AAAA kayıtları yayınlayın.",
    references: ["https://developer.mozilla.org/en-US/docs/Glossary/IPv6"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.aaaa.length > 0) return { status: "pass" };
      if (ev.dns.a.length === 0) return null; // hiç adres yoksa dns-resolution kapsıyor
      return {
        status: "fail",
        severity: "INFO",
        confidence: "confirmed",
        evidence: "AAAA (IPv6) kaydı bulunamadı; yalnızca IPv4 üzerinden erişilebilir.",
      };
    },
  },
  {
    id: "dns-txt-verification-tokens",
    category: "dns-email",
    title: "TXT doğrulama belirteçleri açığa çıkmış",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "A01:2021 Broken Access Control",
    description:
      "TXT kayıtları, kullandığınız üçüncü taraf hizmetleri açığa çıkaran doğrulama belirteçleri içeriyor " +
      "(ör. google-site-verification, ms=, facebook-domain-verification). Tek başına açık değildir ama " +
      "saldırgana kullandığınız SaaS yığını hakkında keşif bilgisi verir.",
    remediation:
      "Artık kullanılmayan doğrulama belirteçlerini kaldırın; yalnızca aktif olanları tutun.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/DNS/Guide/TXT_records"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      const tokenRe = /(google-site-verification|facebook-domain-verification|^ms=|apple-domain-verification|_?globalsign-domain-verification|pinterest|stripe-verification|atlassian-domain-verification|docusign|adobe-idp-site-verification)/i;
      const hits = ev.dns.txt.filter((t) => tokenRe.test(t.trim()));
      if (hits.length === 0) return { status: "pass" };
      return {
        status: "fail",
        severity: "INFO",
        confidence: "confirmed",
        evidence: `Doğrulama belirteçleri: ${hits.slice(0, 8).map((h) => `«${h.slice(0, 60)}»`).join(", ")}`,
      };
    },
  },
  {
    id: "dns-txt-secret-leak",
    category: "dns-email",
    title: "TXT kaydında sır sızıntısı",
    severity: "MEDIUM",
    cwe: "CWE-312",
    owasp: "A02:2021 Cryptographic Failures",
    description:
      "Bir TXT kaydı sır gibi görünen içerik barındırıyor (ör. `key=`, `secret`, `password`, `api_key`, " +
      "`token=`). DNS herkese açıktır; buraya konan gizli değerler doğrudan ifşa olmuş demektir.",
    remediation:
      "Sırrı DNS'ten derhal kaldırın ve DÖNDÜRÜN (rotate). Gizli değerleri bir secret manager'da saklayın.",
    references: ["https://cwe.mitre.org/data/definitions/312.html"],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      const safeRe = /^(v=spf1|v=dmarc1|v=dkim1|google-site-verification|facebook-domain-verification|ms=|apple-domain-verification|_domainkey)/i;
      const secretRe = /(password|passwd|secret|api[_-]?key|\bkey=|token=|access[_-]?key|private[_-]?key|aws_)/i;
      const hits = ev.dns.txt.filter((t) => {
        const v = t.trim();
        return !safeRe.test(v) && secretRe.test(v);
      });
      if (hits.length === 0) return { status: "pass" };
      return {
        status: "fail",
        severity: "MEDIUM",
        confidence: "firm",
        evidence: `Sır içerebilecek TXT: ${hits.slice(0, 5).map((h) => `«${h.slice(0, 80)}»`).join(", ")}`,
      };
    },
  },
  {
    id: "dns-txt-count",
    category: "dns-email",
    title: "Aşırı sayıda TXT kaydı",
    severity: "INFO",
    cwe: "CWE-16",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Alan adında çok sayıda TXT kaydı var. Bu bir açık değildir ama biriken eski/kullanılmayan kayıtlar " +
      "hijyen sorunudur, DNS yanıtını şişirir ve keşif yüzeyini artırır.",
    remediation: "Kullanılmayan doğrulama/eski TXT kayıtlarını temizleyin.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/DNS/Guide/TXT_records"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.txt.length === 0) return null;
      if (ev.dns.txt.length > 15) {
        return {
          status: "fail",
          severity: "INFO",
          confidence: "confirmed",
          evidence: `${ev.dns.txt.length} adet TXT kaydı bulundu; eski kayıtları temizleyin.`,
        };
      }
      return { status: "pass" };
    },
  },
  {
    id: "dns-ns-single",
    category: "dns-email",
    title: "Tek NS kaydı — tek hata noktası",
    severity: "LOW",
    cwe: "CWE-1188",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Alan adı yalnızca tek bir ad sunucusu (NS) ile yetkilendirilmiş. Tek NS bir kullanılabilirlik/dayanıklılık " +
      "zafiyetidir: o sunucu düşerse alan adı tamamen çözülemez hale gelir.",
    remediation: "En az iki (tercihen coğrafi olarak dağıtık) yetkili ad sunucusu yapılandırın.",
    references: ["https://datatracker.ietf.org/doc/html/rfc2182"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.ns.length === 0) return null;
      if (ev.dns.ns.length === 1) {
        return {
          status: "fail",
          severity: "LOW",
          confidence: "confirmed",
          evidence: `Yalnızca 1 NS kaydı: «${ev.dns.ns[0]}».`,
        };
      }
      return { status: "pass" };
    },
  },
  {
    id: "dns-ns-diversity",
    category: "dns-email",
    title: "NS sağlayıcı çeşitliliği yok",
    severity: "INFO",
    cwe: "CWE-1188",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Tüm ad sunucuları aynı üst alan adı/sağlayıcı altında. Birden fazla NS olsa da hepsi tek sağlayıcıya " +
      "bağlıysa, o sağlayıcıda yaşanan kesinti alan adınızı komple çözülemez bırakabilir.",
    remediation: "Ad sunucularınızı iki farklı DNS sağlayıcısına yayarak dayanıklılığı artırmayı değerlendirin.",
    references: ["https://datatracker.ietf.org/doc/html/rfc2182"],
    confidence: "firm",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.ns.length < 2) return null; // tek NS'i dns-ns-single kapsıyor
      const providers = new Set(ev.dns.ns.map((n) => registrable(n)));
      if (providers.size === 1) {
        return {
          status: "fail",
          severity: "INFO",
          confidence: "firm",
          evidence: `${ev.dns.ns.length} NS kaydının tamamı tek sağlayıcıda: «${[...providers][0]}».`,
        };
      }
      return { status: "pass" };
    },
  },
  {
    id: "dns-mx-configured",
    category: "dns-email",
    title: "MX (posta) yapılandırması",
    severity: "INFO",
    cwe: "CWE-16",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Alan adının MX kaydı olup olmadığını tespit eder. MX yoksa alan adı e-posta almaz; bu bilgilendirici bir " +
      "tespittir ve SPF/DKIM/DMARC beklentilerini bağlamlandırır.",
    remediation:
      "E-posta almayan alan adları için `null MX` (`0 .`) ve `v=spf1 -all` yayınlayarak taklit riskini azaltın.",
    references: ["https://datatracker.ietf.org/doc/html/rfc7505"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.mx.length > 0) return { status: "pass" };
      return {
        status: "fail",
        severity: "INFO",
        confidence: "confirmed",
        evidence: "MX kaydı yok — bu alan adı e-posta almıyor görünüyor.",
      };
    },
  },
  {
    id: "dns-mx-redundancy",
    category: "dns-email",
    title: "Yedek MX kaydı yok",
    severity: "INFO",
    cwe: "CWE-1188",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Yalnızca tek bir MX kaydı var. Yedek MX olmadan, birincil posta sunucusu kısa süreli kesinti yaşadığında " +
      "gelen e-postalar gecikebilir veya reddedilebilir (kullanılabilirlik zafiyeti).",
    remediation: "Farklı öncelikli (priority) en az bir yedek MX kaydı ekleyin.",
    references: ["https://datatracker.ietf.org/doc/html/rfc5321"],
    confidence: "confirmed",
    evaluate(ev) {
      if (!ev.dns.resolved) return null;
      if (ev.dns.mx.length === 0) return null; // dns-mx-configured kapsıyor
      if (ev.dns.mx.length === 1) {
        return {
          status: "fail",
          severity: "INFO",
          confidence: "confirmed",
          evidence: `Yalnızca 1 MX kaydı: «${ev.dns.mx[0]}». Yedek MX önerilir.`,
        };
      }
      return { status: "pass" };
    },
  },
];
