// Content checks over HTML/JS bodies: leaked secrets, SRI, mixed content,
// insecure forms, and information disclosure. Secret patterns are chosen for
// high precision (structured token shapes), and evidence is redacted.
import type { Check, CheckOutcome, Confidence, Evidence, Severity } from "./types";

const OWASP_SECRETS = "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password";

interface Body {
  text: string;
  where: string;
}
function bodies(ev: Evidence): Body[] {
  const out: Body[] = [{ text: ev.root.body, where: ev.root.url }];
  for (const s of ev.inlineScripts) out.push({ text: s, where: `${ev.root.url} (inline script)` });
  for (const p of ev.pages) if (p.url !== ev.root.url && p.body) out.push({ text: p.body, where: p.url });
  return out.slice(0, 40);
}
function redact(s: string): string {
  if (s.length <= 12) return s.slice(0, 3) + "…";
  return s.slice(0, 6) + "…" + s.slice(-4);
}

// --- Secret patterns ---------------------------------------------------------

interface SecretSig {
  id: string;
  title: string;
  severity: Severity;
  re: RegExp;
  confidence?: Confidence;
  ref?: string;
}

const SECRETS: SecretSig[] = [
  { id: "aws-akid", title: "AWS Access Key ID", severity: "HIGH", re: /\bAKIA[0-9A-Z]{16}\b/, confidence: "firm" },
  { id: "aws-secret", title: "AWS Secret Access Key (bağlamlı)", severity: "CRITICAL", re: /aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+]{40}["']?/i, confidence: "firm" },
  { id: "gcp-apikey", title: "Google API anahtarı", severity: "HIGH", re: /\bAIza[0-9A-Za-z_\-]{35}\b/, confidence: "firm" },
  { id: "gcp-oauth", title: "Google OAuth erişim token'ı", severity: "HIGH", re: /\bya29\.[0-9A-Za-z_\-]{20,}/, confidence: "firm" },
  { id: "github-token", title: "GitHub token", severity: "HIGH", re: /\b(gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b/, confidence: "confirmed" },
  { id: "gitlab-pat", title: "GitLab kişisel erişim token'ı", severity: "HIGH", re: /\bglpat-[0-9A-Za-z_\-]{20}\b/, confidence: "confirmed" },
  { id: "npm-token", title: "npm token", severity: "HIGH", re: /\bnpm_[0-9A-Za-z]{36}\b/, confidence: "confirmed" },
  { id: "slack-token", title: "Slack token", severity: "HIGH", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, confidence: "firm" },
  { id: "slack-webhook", title: "Slack webhook URL'si", severity: "MEDIUM", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/, confidence: "confirmed" },
  { id: "stripe-live", title: "Stripe canlı gizli anahtarı", severity: "CRITICAL", re: /\bsk_live_[0-9A-Za-z]{24,}\b/, confidence: "confirmed" },
  { id: "stripe-restricted", title: "Stripe kısıtlı anahtarı", severity: "HIGH", re: /\brk_live_[0-9A-Za-z]{24,}\b/, confidence: "confirmed" },
  { id: "sendgrid", title: "SendGrid API anahtarı", severity: "HIGH", re: /\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b/, confidence: "confirmed" },
  { id: "mailgun", title: "Mailgun API anahtarı", severity: "MEDIUM", re: /\bkey-[0-9a-f]{32}\b/, confidence: "firm" },
  { id: "twilio-sk", title: "Twilio API anahtarı", severity: "MEDIUM", re: /\bSK[0-9a-fA-F]{32}\b/, confidence: "firm" },
  { id: "square", title: "Square erişim token'ı", severity: "HIGH", re: /\bsq0atp-[0-9A-Za-z_\-]{22}\b/, confidence: "confirmed" },
  { id: "braintree", title: "Braintree/PayPal production token", severity: "HIGH", re: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/, confidence: "confirmed" },
  { id: "facebook", title: "Facebook erişim token'ı", severity: "MEDIUM", re: /\bEAACEdEose0cBA[0-9A-Za-z]+/, confidence: "firm" },
  { id: "private-key", title: "Özel anahtar bloğu (PEM)", severity: "CRITICAL", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, confidence: "confirmed" },
  { id: "jwt", title: "JWT sayfada gömülü", severity: "MEDIUM", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, confidence: "firm" },
  { id: "mongodb-uri", title: "MongoDB bağlantı dizesi", severity: "HIGH", re: /mongodb(?:\+srv)?:\/\/[^\s"'<>]+:[^\s"'<>@]+@[^\s"'<>]+/, confidence: "confirmed" },
  { id: "sql-uri", title: "SQL bağlantı dizesi (kimlikli)", severity: "HIGH", re: /\b(?:postgres(?:ql)?|mysql|mariadb):\/\/[^\s:"'<>]+:[^\s@"'<>]+@[^\s"'<>]+/, confidence: "confirmed" },
  { id: "basic-auth-url", title: "URL içinde gömülü kimlik bilgisi", severity: "MEDIUM", re: /\bhttps?:\/\/[^/\s:@"'<>]+:[^/\s:@"'<>]+@[^\s"'<>]+/, confidence: "firm" },
  { id: "generic-apikey", title: "Kaynakta olası gömülü sır (anahtar/parola atama)", severity: "MEDIUM", re: /["']?(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-!@#$%^&*+/]{16,}["']/i, confidence: "tentative" },
  { id: "firebase-fcm", title: "Firebase Cloud Messaging sunucu anahtarı", severity: "MEDIUM", re: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/, confidence: "firm" },
];

function secretCheck(sig: SecretSig): Check {
  return {
    id: `secret-${sig.id}`,
    category: "content",
    title: `Sır sızıntısı: ${sig.title}`,
    severity: sig.severity,
    cwe: "CWE-798",
    owasp: "A07:2021 Identification and Authentication Failures",
    description: `İstemciye sunulan HTML/JS içeriğinde ${sig.title} kalıbı bulundu. Bu, sabit kodlanmış bir sırdır ve derhal iptal edilmelidir.`,
    remediation: "Sırrı kaynaktan kaldırın ve HEMEN döndürün (rotate). İstemci tarafına sır koymayın; gizli değerleri sunucu tarafında tutun.",
    references: [sig.ref ?? OWASP_SECRETS],
    confidence: sig.confidence ?? "firm",
    evaluate(ev) {
      const out: CheckOutcome[] = [];
      const seen = new Set<string>();
      for (const b of bodies(ev)) {
        const m = sig.re.exec(b.text);
        if (m && !seen.has(b.where)) {
          seen.add(b.where);
          out.push({ status: "fail", location: b.where, confidence: sig.confidence ?? "firm", evidence: `Eşleşme: ${redact(m[0])}` });
        }
      }
      return out.length ? out : { status: "pass" };
    },
  };
}

// --- Non-secret content checks ----------------------------------------------

const OTHER: Check[] = [
  {
    id: "content-sri-missing",
    category: "content",
    title: "Dış scriptlerde Subresource Integrity (SRI) yok",
    severity: "LOW",
    cwe: "CWE-353",
    owasp: "A08:2021 Software and Data Integrity Failures",
    description: "Başka origin'den (CDN) integrity özniteliği olmadan script yükleniyor; CDN değiştirilirse keyfi kod çalışabilir.",
    remediation: "Dış script/stil etiketlerine integrity + crossorigin ekleyin. Hash: openssl dgst -sha384 -binary lib.js | openssl base64 -A",
    references: ["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
    evaluate(ev) {
      let origin: string;
      try {
        origin = new URL(ev.root.url).origin;
      } catch {
        return null;
      }
      const tags = ev.root.body.match(/<script\b[^>]*\bsrc\s*=\s*["'][^"']+["'][^>]*>/gi) ?? [];
      const bad: string[] = [];
      for (const t of tags) {
        const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(t)?.[1];
        if (!src) continue;
        let abs: URL;
        try {
          abs = new URL(src, ev.root.url);
        } catch {
          continue;
        }
        if (abs.origin === origin) continue;
        if (/\bintegrity\s*=/i.test(t)) continue;
        bad.push(abs.toString());
        if (bad.length >= 8) break;
      }
      if (!bad.length) return { status: "pass" };
      return { status: "fail", location: ev.root.url, evidence: bad.join("\n") };
    },
  },
  {
    id: "content-mixed-active",
    category: "content",
    title: "Aktif karışık içerik (HTTPS sayfada HTTP script/stil)",
    severity: "MEDIUM",
    cwe: "CWE-311",
    owasp: "A02:2021 Cryptographic Failures",
    description: "HTTPS sayfa, düz HTTP üzerinden script/stil yüklüyor; bu kaynaklar değiştirilebilir ve sayfayı ele geçirebilir. Tarayıcılar genellikle bunları engeller.",
    remediation: "Tüm alt kaynakları HTTPS'e taşıyın; CSP: upgrade-insecure-requests ekleyin.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
    evaluate(ev) {
      if (!ev.root.url.startsWith("https://") || !ev.root.body) return null;
      const m = [...ev.root.body.matchAll(/<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)].map((x) => x[1]).slice(0, 8);
      return m.length ? { status: "fail", location: ev.root.url, evidence: m.join("\n"), confidence: "confirmed" } : { status: "pass" };
    },
  },
  {
    id: "content-mixed-passive",
    category: "content",
    title: "Pasif karışık içerik (HTTPS sayfada HTTP görsel/medya)",
    severity: "LOW",
    cwe: "CWE-311",
    owasp: "A02:2021 Cryptographic Failures",
    description: "HTTPS sayfa düz HTTP üzerinden görsel/medya yüklüyor; gizlilik/bütünlük sızıntısı ve 'güvenli değil' uyarısı riski.",
    remediation: "Görsel/medya kaynaklarını HTTPS'e taşıyın.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
    evaluate(ev) {
      if (!ev.root.url.startsWith("https://") || !ev.root.body) return null;
      const m = [...ev.root.body.matchAll(/<(?:img|video|audio|source)\b[^>]*\bsrc\s*=\s*["'](http:\/\/[^"']+)["']/gi)].map((x) => x[1]).slice(0, 8);
      return m.length ? { status: "fail", location: ev.root.url, evidence: m.join("\n") } : { status: "pass" };
    },
  },
  {
    id: "content-form-insecure-action",
    category: "content",
    title: "Form verisini düz HTTP'ye gönderiyor",
    severity: "MEDIUM",
    cwe: "CWE-319",
    owasp: "A02:2021 Cryptographic Failures",
    description: "HTTPS sayfadaki bir form, action'ı http:// olan bir adrese veri gönderiyor; veriler şifresiz taşınır.",
    remediation: "Form action'larını HTTPS yapın.",
    references: ["https://developer.mozilla.org/en-US/docs/Learn/Forms/Sending_and_retrieving_form_data"],
    evaluate(ev) {
      if (!ev.root.url.startsWith("https://")) return null;
      const bad = ev.forms.filter((f) => /^http:\/\//i.test(f.action));
      return bad.length ? { status: "fail", location: ev.root.url, evidence: bad.map((f) => `${f.method} ${f.action}`).join("\n"), confidence: "confirmed" } : { status: "pass" };
    },
  },
  {
    id: "content-form-external-action",
    category: "content",
    title: "Form verisini üçüncü taraf origin'e gönderiyor",
    severity: "LOW",
    cwe: "CWE-346",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Bir form, verisini farklı bir origin'e gönderiyor; kasıtlı değilse veri sızıntısı riski.",
    remediation: "Form hedeflerini doğrulayın; CSP form-action ile kısıtlayın.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action"],
    evaluate(ev) {
      let origin: string;
      try {
        origin = new URL(ev.root.url).origin;
      } catch {
        return null;
      }
      const ext = ev.forms.filter((f) => {
        try {
          return new URL(f.action, ev.root.url).origin !== origin && /^https?:/.test(f.action);
        } catch {
          return false;
        }
      });
      return ext.length ? { status: "fail", location: ev.root.url, evidence: ext.map((f) => f.action).slice(0, 5).join("\n") } : { status: "pass" };
    },
  },
  {
    id: "content-form-no-csrf",
    category: "content",
    title: "POST formunda görünür CSRF token'ı yok",
    severity: "LOW",
    cwe: "CWE-352",
    owasp: "A01:2021 Broken Access Control",
    description: "Bir POST formu, isimlerinde csrf/token/authenticity içeren gizli bir alan taşımıyor. CSRF koruması sunucu/çerez tarafında olabilir; bu düşük güvenilirlikli bir ipucudur.",
    remediation: "Durum değiştiren formlarda CSRF token'ı kullanın veya SameSite çerez + origin doğrulaması uygulayın.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    confidence: "tentative",
    evaluate(ev) {
      const posts = ev.forms.filter((f) => f.method === "POST");
      if (!posts.length) return null;
      const noToken = posts.filter((f) => !f.inputs.some((n) => /csrf|token|authenticity|nonce|_token/i.test(n)));
      return noToken.length ? { status: "fail", location: ev.root.url, confidence: "tentative", evidence: `${noToken.length}/${posts.length} POST formunda token adı görünmüyor.` } : { status: "pass" };
    },
  },
  {
    id: "content-target-blank-noopener",
    category: "content",
    title: "target=_blank bağlantılarında rel=noopener yok",
    severity: "LOW",
    cwe: "CWE-1022",
    owasp: "A05:2021 Security Misconfiguration",
    description: "target=\"_blank\" ile açılan ve rel=noopener taşımayan bağlantılar, açılan sayfaya window.opener üzerinden erişim vererek tabnabbing'e yol açabilir.",
    remediation: "target=\"_blank\" bağlantılarına rel=\"noopener noreferrer\" ekleyin.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#security_and_privacy"],
    evaluate(ev) {
      const anchors = ev.root.body.match(/<a\b[^>]*target\s*=\s*["']?_blank[^>]*>/gi) ?? [];
      const bad = anchors.filter((a) => !/rel\s*=\s*["'][^"']*noopener/i.test(a));
      return bad.length ? { status: "fail", location: ev.root.url, evidence: `${bad.length} bağlantı`, severity: "LOW" } : anchors.length ? { status: "pass" } : null;
    },
  },
  {
    id: "content-sourcemap-ref",
    category: "content",
    title: "Kaynak haritası (sourceMappingURL) referansı",
    severity: "LOW",
    cwe: "CWE-540",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Sayfa/JS bir sourceMappingURL içeriyor; kaynak haritaları orijinal (minify edilmemiş) kaynak kodunu ve yorumları açığa çıkarabilir.",
    remediation: "Üretimde kaynak haritalarını yayınlamayın veya erişimi kısıtlayın.",
    references: ["https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map"],
    evaluate(ev) {
      for (const b of bodies(ev)) {
        const m = /\/\/[#@]\s*sourceMappingURL=(\S+)/.exec(b.text);
        if (m) return { status: "fail", location: b.where, evidence: m[0].slice(0, 120) };
      }
      return { status: "pass" };
    },
  },
  {
    id: "content-html-comment-leak",
    category: "content",
    title: "HTML yorumlarında hassas ipuçları",
    severity: "INFO",
    cwe: "CWE-615",
    owasp: "A05:2021 Security Misconfiguration",
    description: "HTML yorumları TODO/FIXME/parola/anahtar/iç bilgi gibi hassas ipuçları içeriyor olabilir.",
    remediation: "Üretim çıktısından geliştirici yorumlarını temizleyin.",
    references: ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"],
    evaluate(ev) {
      const comments = ev.root.body.match(/<!--([\s\S]*?)-->/g) ?? [];
      const hit = comments.find((c) => /(TODO|FIXME|password|passwd|secret|api[_-]?key|internal|debug|staging|localhost|BUG)/i.test(c));
      return hit ? { status: "fail", location: ev.root.url, evidence: hit.slice(0, 160), confidence: "tentative" } : { status: "pass" };
    },
  },
  {
    id: "content-email-disclosure",
    category: "content",
    title: "Sayfada e-posta adresi ifşası",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Sayfada düz metin e-posta adres(ler)i bulundu; spam/oltalama hedeflemesi için toplanabilir.",
    remediation: "E-postaları gizleyin (JS ile birleştirme, iletişim formu) veya bunu kabul edilebilir kabul edin.",
    references: ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_sent_data"],
    evaluate(ev) {
      const emails = [...ev.root.body.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)].map((m) => m[0]).filter((e) => !/@(example|sentry|w3\.org|schema\.org)/i.test(e));
      const uniq = [...new Set(emails)].slice(0, 5);
      return uniq.length ? { status: "fail", location: ev.root.url, evidence: uniq.join(", ") } : { status: "pass" };
    },
  },
  {
    id: "content-autocomplete-cc",
    category: "content",
    title: "Hassas alanlarda otomatik tamamlama kapatılmamış",
    severity: "INFO",
    cwe: "CWE-522",
    owasp: "A07:2021 Identification and Authentication Failures",
    description: "Kredi kartı benzeri alanlarda autocomplete=off yok; paylaşılan cihazlarda hassas veriler önbelleğe alınabilir (bağlama göre kabul edilebilir).",
    remediation: "Gerçekten hassas alanlarda autocomplete davranışını gözden geçirin.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/autocomplete"],
    confidence: "tentative",
    evaluate(ev) {
      const inputs = ev.root.body.match(/<input\b[^>]*\b(?:name|id)\s*=\s*["'][^"']*(?:card|cc-number|cvv|ccv|creditcard)[^"']*["'][^>]*>/gi) ?? [];
      const bad = inputs.filter((i) => !/autocomplete\s*=\s*["']?(off|cc-)/i.test(i));
      return bad.length ? { status: "fail", location: ev.root.url, confidence: "tentative", evidence: `${bad.length} alan` } : inputs.length ? { status: "pass" } : null;
    },
  },
];

export const CONTENT_CHECKS: Check[] = [...SECRETS.map(secretCheck), ...OTHER];
