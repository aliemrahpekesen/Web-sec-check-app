// Caching of sensitive responses.
import type { Check, Evidence } from "./types";

const MDN_CACHE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control";

function sensitive(ev: Evidence): boolean {
  return ev.root.setCookies.length > 0 || /<input[^>]+type\s*=\s*["']?password/i.test(ev.root.body);
}

export const CACHE_CHECKS: Check[] = [
  {
    id: "cache-sensitive-no-store",
    category: "cache",
    title: "Hassas yanıtta önbellek engellenmemiş",
    severity: "LOW",
    cwe: "CWE-525",
    owasp: "A04:2021 Insecure Design",
    description: "Oturum çerezi veya parola alanı içeren bir yanıtta Cache-Control: no-store/private yok; paylaşılan önbellekler veya tarayıcı geçmişi hassas içeriği saklayabilir.",
    remediation: "Hassas yanıtlarda: Cache-Control: no-store (veya en azından private).",
    references: [MDN_CACHE],
    evaluate(ev) {
      if (!sensitive(ev)) return null;
      const cc = ev.root.headers["cache-control"] ?? "";
      return /no-store|private/i.test(cc) ? { status: "pass" } : { status: "fail", location: ev.root.url, evidence: cc ? `Cache-Control: ${cc}` : "Cache-Control yok" };
    },
  },
  {
    id: "cache-authenticated-public",
    category: "cache",
    title: "Kimliklendirilmiş yanıt public olarak önbelleklenebiliyor",
    severity: "MEDIUM",
    cwe: "CWE-525",
    owasp: "A04:2021 Insecure Design",
    description: "Set-Cookie taşıyan yanıt Cache-Control: public (veya s-maxage) içeriyor; bir CDN/proxy, bir kullanıcının kişisel yanıtını başkasına sunabilir.",
    remediation: "Kimliklendirilmiş yanıtlarda public/s-maxage kullanmayın; no-store veya private uygulayın.",
    references: [MDN_CACHE],
    evaluate(ev) {
      if (ev.root.setCookies.length === 0) return null;
      const cc = (ev.root.headers["cache-control"] ?? "").toLowerCase();
      return /\bpublic\b|s-maxage/.test(cc) ? { status: "fail", location: ev.root.url, confidence: "firm", evidence: `Set-Cookie + Cache-Control: ${cc}` } : { status: "pass" };
    },
  },
  {
    id: "cache-vary-cookie-missing",
    category: "cache",
    title: "Çerezle değişen yanıtta Vary: Cookie yok",
    severity: "LOW",
    cwe: "CWE-525",
    owasp: "A04:2021 Insecure Design",
    description: "Yanıt Set-Cookie döndürüyor ve önbelleklenebilir görünüyor ama Vary: Cookie yok; kullanıcıya özel içerik yanlış paylaşılabilir.",
    remediation: "Çereze bağlı yanıtlarda Vary: Cookie ekleyin veya önbelleği tamamen kapatın.",
    references: [MDN_CACHE],
    evaluate(ev) {
      if (ev.root.setCookies.length === 0) return null;
      const cc = (ev.root.headers["cache-control"] ?? "").toLowerCase();
      if (/no-store|private/.test(cc)) return { status: "pass" }; // not cacheable anyway
      const vary = (ev.root.headers["vary"] ?? "").toLowerCase();
      return /cookie/.test(vary) ? { status: "pass" } : { status: "fail", location: ev.root.url, evidence: `Vary: ${ev.root.headers["vary"] ?? "(yok)"}` };
    },
  },
];
