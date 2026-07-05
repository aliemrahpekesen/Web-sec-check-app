// One disclosure check per catalogued sensitive path. A check fails only when
// the path returned a real file (200 + content sanity, and the optional content
// signature matched) — so a soft-404 or SPA catch-all never produces a false
// positive. When the path was probed and absent, the check PASSES (visible
// coverage); when the profile didn't probe it, it's N/A.
import { SENSITIVE_PATHS } from "./data/paths";
import type { Check } from "./types";

function slug(path: string): string {
  return path.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase().slice(0, 48);
}

export const DISCLOSURE_CHECKS: Check[] = SENSITIVE_PATHS.map((sig, i): Check => {
  const info = sig.severity === "INFO";
  return {
    id: `disclosure-${i}-${slug(sig.path)}`,
    category: "disclosure",
    title: info ? `Tespit: ${sig.title}` : `Hassas dosya erişilebilir: ${sig.title}`,
    severity: sig.severity,
    cwe: info ? "CWE-200" : "CWE-538",
    owasp: info ? "A05:2021 Security Misconfiguration" : "A01:2021 Broken Access Control",
    description: info
      ? `«${sig.path}» genel erişime açık. Tek başına bir açık olmayabilir ama saldırgana bilgi/saldırı yüzeyi sağlar.`
      : `Gizli kalması gereken bir dosya/dizin («${sig.path}») genel erişime açık. İçinde gizli anahtarlar, kimlik bilgileri veya kaynak kodu bulunabilir.`,
    remediation: info
      ? `Gerekmiyorsa kaldırın; gerekiyorsa içeriğinin hassas bilgi sızdırmadığından emin olun.`
      : `Dosyayı derhal kaldırın/erişimini engelleyin ve içindeki TÜM sırları döndürün (rotate).\n\n` +
        `Nginx:\n  location ~ /\\.(git|env|svn|hg|bzr|htpasswd) { deny all; return 404; }\n` +
        `Yedek/dump dosyalarını web köküne koymayın; sırları bir secret manager ile yönetin.`,
    references: ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const probe = ev.paths[sig.path];
      if (probe === undefined) return null; // not probed at this profile/budget
      if (probe.exists) {
        // A 200 HTML response for a path with no content signature can't be
        // confirmed as a real leaked file — it may be the app's own page (e.g.
        // a framework route or a username that maps to a profile). Downgrade to
        // a low-confidence hint instead of a false-alarming high finding.
        const unconfirmed = !sig.sig && /text\/html/i.test(probe.contentType);
        return {
          status: "fail",
          location: `${ev.origin}${sig.path}`,
          confidence: unconfirmed ? "tentative" : "confirmed",
          severity: unconfirmed && sig.severity !== "INFO" ? "LOW" : undefined,
          detail: unconfirmed
            ? "İçerik imzası olmadan HTML yanıt döndü; bu gerçek bir sızıntı yerine bir uygulama sayfası da olabilir. Elle doğrulayın."
            : undefined,
          evidence: `HTTP ${probe.status} · ${probe.contentType || "?"} · ${probe.length} bayt\nÖrnek: ${probe.snippet}`,
        };
      }
      return { status: "pass" };
    },
  };
});
