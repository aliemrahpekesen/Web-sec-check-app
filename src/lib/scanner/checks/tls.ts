// TLS certificate + cryptographic-strength checks over the deep-TLS evidence.
import type { Check, Evidence } from "./types";

const SSLLABS = "https://www.ssllabs.com/ssltest/";
const MOZ_TLS = "https://ssl-config.mozilla.org/";

function tlsReady(ev: Evidence): boolean {
  return ev.tls.reachable && !ev.tls.error;
}

export const TLS_CHECKS: Check[] = [
  {
    id: "tls-untrusted",
    category: "tls",
    title: "Geçersiz / güvenilmeyen TLS sertifikası",
    severity: "HIGH",
    cwe: "CWE-295",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sertifika zinciri doğrulanamadı; tarayıcılar bağlantıyı engeller ve MITM riski artar.",
    remediation: "Güvenilir bir CA'dan (ör. Let's Encrypt) geçerli, tam zincirli (fullchain) bir sertifika kurun.",
    references: [SSLLABS],
    evaluate(ev) {
      if (!tlsReady(ev)) return null;
      const err = ev.tls.authorizationError;
      // Reported separately: expiry, self-signed, hostname mismatch.
      if (ev.tls.authorized === false && err && !/expired|self.?signed|altname|does not match/i.test(err)) {
        return { status: "fail", location: `https://${ev.host}`, confidence: "confirmed", evidence: `authorizationError: ${err}` };
      }
      return ev.tls.authorized ? { status: "pass" } : null;
    },
  },
  {
    id: "tls-self-signed",
    category: "tls",
    title: "Kendinden imzalı TLS sertifikası",
    severity: "HIGH",
    cwe: "CWE-295",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sertifika kendinden imzalı; hiçbir güvenilir CA doğrulamıyor.",
    remediation: "Güvenilir bir CA sertifikası kullanın.",
    references: [SSLLABS],
    evaluate(ev) {
      if (!tlsReady(ev)) return null;
      const err = ev.tls.authorizationError ?? "";
      if (ev.tls.selfSigned || /self.?signed/i.test(err)) {
        return { status: "fail", location: `https://${ev.host}`, confidence: "confirmed", evidence: err || `issuer=subject=${ev.tls.subjectCN}` };
      }
      return { status: "pass" };
    },
  },
  {
    id: "tls-hostname-mismatch",
    category: "tls",
    title: "Sertifika ana bilgisayar adıyla eşleşmiyor",
    severity: "HIGH",
    cwe: "CWE-297",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sunucu sertifikası bu host adını kapsamıyor; tarayıcı güvenlik uyarısı gösterir.",
    remediation: "Sertifikanın CN/SAN alanına doğru host adını ekleyin.",
    references: [SSLLABS],
    evaluate(ev) {
      if (!tlsReady(ev)) return null;
      const err = ev.tls.authorizationError ?? "";
      return /altname|does not match/i.test(err) ? { status: "fail", location: `https://${ev.host}`, confidence: "confirmed", evidence: err } : { status: "pass" };
    },
  },
  {
    id: "tls-expired",
    category: "tls",
    title: "TLS sertifikasının süresi dolmuş",
    severity: "HIGH",
    cwe: "CWE-298",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sertifika geçerlilik süresi bitmiş; tarayıcılar bağlantıyı engeller.",
    remediation: "Sertifikayı yenileyin ve otomatik yenilemeyi (certbot renew) kurun.",
    references: [SSLLABS],
    evaluate(ev) {
      if (!tlsReady(ev) || ev.tls.daysToExpiry === undefined) return null;
      return ev.tls.daysToExpiry < 0
        ? { status: "fail", location: `https://${ev.host}`, confidence: "confirmed", evidence: `Bitiş: ${ev.tls.validTo} (${-ev.tls.daysToExpiry} gün önce)` }
        : { status: "pass" };
    },
  },
  {
    id: "tls-expiring-soon",
    category: "tls",
    title: "TLS sertifikası çok yakında dolacak",
    severity: "MEDIUM",
    cwe: "CWE-298",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sertifika 14 günden az bir sürede dolacak.",
    remediation: "Sertifikayı hemen yenileyin; otomatik yenileme ve süre izleme (monitoring) ekleyin.",
    references: [SSLLABS],
    evaluate(ev) {
      const d = ev.tls.daysToExpiry;
      if (!tlsReady(ev) || d === undefined) return null;
      return d >= 0 && d < 14 ? { status: "fail", location: `https://${ev.host}`, evidence: `${d} gün kaldı (${ev.tls.validTo})` } : { status: "pass" };
    },
  },
  {
    id: "tls-protocol-deprecated",
    category: "tls",
    title: "Kullanımdan kalkmış TLS/SSL protokolü",
    severity: "HIGH",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sunucu TLS 1.0/1.1 veya SSLv3 ile el sıkışabiliyor; bu protokoller kırılabilir (POODLE, BEAST).",
    remediation: "Yalnızca TLS 1.2+ etkinleştirin (Mozilla 'intermediate' profili).",
    references: [MOZ_TLS],
    evaluate(ev) {
      const p = ev.tls.protocol;
      if (!tlsReady(ev) || !p) return null;
      return /^(SSLv|TLSv1\.?0?$|TLSv1\.1)/i.test(p) && p !== "TLSv1.2" && p !== "TLSv1.3"
        ? { status: "fail", location: `https://${ev.host}`, evidence: `Müzakere edilen protokol: ${p}` }
        : { status: "pass" };
    },
  },
  {
    id: "tls-not-1-3",
    category: "tls",
    title: "TLS 1.3 desteklenmiyor (yalnızca 1.2)",
    severity: "INFO",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Bağlantı TLS 1.2 ile kuruldu; TLS 1.3 daha hızlı ve daha güvenlidir.",
    remediation: "Sunucuda TLS 1.3 desteğini etkinleştirin.",
    references: [MOZ_TLS],
    evaluate(ev) {
      const p = ev.tls.protocol;
      if (!tlsReady(ev) || !p) return null;
      return p === "TLSv1.2" ? { status: "fail", location: `https://${ev.host}`, evidence: p } : { status: "pass" };
    },
  },
  {
    id: "crypto-weak-cipher",
    category: "crypto",
    title: "Zayıf şifre takımı (cipher) müzakere edildi",
    severity: "HIGH",
    cwe: "CWE-327",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Bağlantı zayıf/kırılmış bir şifre takımı kullanıyor (RC4/3DES/DES/EXPORT/NULL/MD5).",
    remediation: "Yalnızca modern AEAD şifre takımlarına (AES-GCM, ChaCha20-Poly1305) izin verin.",
    references: [MOZ_TLS],
    evaluate(ev) {
      const c = ev.tls.cipherName;
      if (!tlsReady(ev) || !c) return null;
      return /RC4|3DES|DES-|EXPORT|NULL|MD5|_CBC_.*SHA$/i.test(c) ? { status: "fail", location: `https://${ev.host}`, evidence: `Cipher: ${c}` } : { status: "pass" };
    },
  },
  {
    id: "crypto-cipher-bits",
    category: "crypto",
    title: "Şifreleme anahtar gücü 128 bitin altında",
    severity: "HIGH",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Müzakere edilen simetrik şifreleme 128 bitten zayıf.",
    remediation: "En az 128-bit AEAD şifreleme kullanın.",
    references: [MOZ_TLS],
    evaluate(ev) {
      const b = ev.tls.cipherBits;
      if (!tlsReady(ev) || !b) return null;
      return b < 128 ? { status: "fail", location: `https://${ev.host}`, evidence: `${b} bit (${ev.tls.cipherName})` } : { status: "pass" };
    },
  },
  {
    id: "crypto-weak-key",
    category: "crypto",
    title: "Sertifika anahtarı zayıf (RSA < 2048 bit)",
    severity: "HIGH",
    cwe: "CWE-326",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sertifikanın açık anahtarı 2048 bitten kısa; brute-force'a karşı yetersiz.",
    remediation: "En az 2048-bit RSA veya 256-bit ECDSA anahtar kullanın.",
    references: [MOZ_TLS],
    evaluate(ev) {
      const k = ev.tls.keyBits;
      if (!tlsReady(ev) || !k) return null;
      // ECDSA keys report small bit counts (256/384) but are strong — only flag RSA-range small keys.
      return k > 0 && k < 2048 && k >= 512 ? { status: "fail", location: `https://${ev.host}`, evidence: `${k} bit anahtar` } : { status: "pass" };
    },
  },
  {
    id: "crypto-weak-signature",
    category: "crypto",
    title: "Zayıf sertifika imza algoritması (SHA-1/MD5)",
    severity: "MEDIUM",
    cwe: "CWE-328",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sertifika SHA-1 veya MD5 ile imzalanmış; bunlar çakışma saldırılarına karşı kırılmıştır.",
    remediation: "SHA-256+ ile imzalanmış bir sertifika alın.",
    references: [SSLLABS],
    evaluate(ev) {
      const s = ev.tls.sigAlg;
      if (!tlsReady(ev) || !s) return null;
      return /sha1|md5/i.test(s) ? { status: "fail", location: `https://${ev.host}`, evidence: `sigAlg: ${s}` } : { status: "pass" };
    },
  },
  {
    id: "tls-long-validity",
    category: "tls",
    title: "Sertifika geçerlilik süresi çok uzun (>398 gün)",
    severity: "LOW",
    cwe: "CWE-295",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Sertifika 398 günden uzun geçerli; CA/Browser Forum kurallarına aykırı ve iptal edilmiş anahtar riskini uzatır.",
    remediation: "Kısa ömürlü (≤398 gün, tercihen 90 gün) sertifikalar kullanın ve otomatik yenileyin.",
    references: ["https://cabforum.org/"],
    evaluate(ev) {
      if (!tlsReady(ev) || !ev.tls.validFrom || !ev.tls.validTo) return null;
      const days = (new Date(ev.tls.validTo).getTime() - new Date(ev.tls.validFrom).getTime()) / 86_400_000;
      return days > 398 ? { status: "fail", location: `https://${ev.host}`, evidence: `${Math.round(days)} gün geçerli` } : { status: "pass" };
    },
  },
  {
    id: "tls-wildcard-cert",
    category: "tls",
    title: "Joker (wildcard) sertifika kullanılıyor",
    severity: "INFO",
    cwe: "CWE-295",
    owasp: "A02:2021 Cryptographic Failures",
    description: "Wildcard sertifika (*.example.com) tüm alt alan adlarını kapsar; bir alt alanın özel anahtarı sızarsa tümü etkilenir.",
    remediation: "Mümkünse alt alan adı başına ayrı sertifika kullanın; wildcard anahtarını sıkı koruyun.",
    references: [SSLLABS],
    evaluate(ev) {
      if (!tlsReady(ev)) return null;
      const wild = ev.tls.subjectCN?.includes("*") || ev.tls.altNames?.some((a) => a.includes("*"));
      return wild ? { status: "fail", location: `https://${ev.host}`, evidence: `CN=${ev.tls.subjectCN} SAN=${ev.tls.san ?? ""}` } : { status: "pass" };
    },
  },
];
