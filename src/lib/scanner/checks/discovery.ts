// Active-discovery checks over GraphQL introspection and robots.txt mining.
import type { Check } from "./types";

export const DISCOVERY_CHECKS: Check[] = [
  {
    id: "api-graphql-introspection",
    category: "api",
    title: "GraphQL introspection açık",
    severity: "MEDIUM",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "GraphQL uç noktası introspection sorgularına yanıt veriyor; saldırgan tüm şemayı (tüm tipler, alanlar, mutasyonlar) çıkarabilir ve saldırı yüzeyini haritalayabilir.",
    remediation: "Üretimde introspection'ı kapatın; sorgu derinliği/karmaşıklık sınırı ve kimlik doğrulama uygulayın.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      if (!ev.graphql) return null;
      return ev.graphql.introspectionEnabled
        ? { status: "fail", location: ev.graphql.endpoint, confidence: "confirmed", evidence: "introspection sorgusu şema döndürdü (__schema)." }
        : { status: "pass" };
    },
  },
  {
    id: "api-graphql-endpoint",
    category: "api",
    title: "GraphQL uç noktası tespit edildi",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "Erişilebilir bir GraphQL uç noktası bulundu. Bilgilendirme amaçlıdır; oran sınırlama, sorgu maliyeti sınırı ve yetkilendirme uygulandığından emin olun.",
    remediation: "GraphQL uçlarında derinlik/karmaşıklık sınırı, oran sınırlama ve alan bazlı yetkilendirme uygulayın.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      if (!ev.graphql) return null;
      return { status: "fail", location: ev.graphql.endpoint, confidence: "firm", evidence: `Uç nokta: ${ev.graphql.endpoint}` };
    },
  },
  {
    id: "disclosure-robots-accessible",
    category: "disclosure",
    title: "robots.txt ile gizlenen yol(lar) herkese açık",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description: "robots.txt'te Disallow ile 'gizlenen' yollar aslında kimlik doğrulama olmadan erişilebilir. robots.txt bir erişim kontrolü değildir; saldırganlar için hedef listesidir.",
    remediation: "Hassas yolları robots.txt'e güvenerek değil, gerçek erişim kontrolüyle (kimlik doğrulama/yetkilendirme) koruyun.",
    references: ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      if (ev.robotsDisallow.length === 0) return { status: "pass" };
      return {
        status: "fail",
        location: `${ev.origin}/robots.txt`,
        confidence: "confirmed",
        evidence: `robots.txt'te gizlenip erişilebilen yollar:\n${ev.robotsDisallow.slice(0, 15).map((p) => ev.origin + p).join("\n")}`,
      };
    },
  },
];
