// API surface + HTTP-configuration checks.
//
// Framework-neutral catalog module: shared by the Next runtime and the
// standalone worker. Every check is a PURE function of the collected Evidence
// snapshot — it fires a "fail" only on concrete evidence, returns "pass" when it
// was applicable and clean, and "null" when it does not apply (so coverage
// counters stay honest and false positives stay out of the report).
import type { Check } from "./types";

// Derive the evidence/page shapes from the Check contract so this file imports
// ONLY `Check` (per module rules) yet stays fully typed under strict tsc.
type Ev = Parameters<Check["evaluate"]>[0];
type Page = Ev["root"];

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

function pagesOf(ev: Ev): Page[] {
  return [ev.root, ...ev.pages];
}

function isJsonPage(p: Page): boolean {
  const ct = (p.contentType || p.headers["content-type"] || "").toLowerCase();
  if (ct.includes("json")) return true;
  const b = (p.body || "").trimStart().slice(0, 1);
  return b === "{" || b === "[";
}

function looksLikeJsonBody(body: string): boolean {
  const t = (body || "").trimStart();
  if (!(t.startsWith("{") || t.startsWith("["))) return false;
  if (/<html[\s>]/i.test(t.slice(0, 400))) return false;
  return /"\s*:/.test(t.slice(0, 2000));
}

// Scan page bodies with a predicate; return the first hit with a snippet.
function scanBodies(
  ev: Ev,
  fn: (body: string, page: Page) => string | null,
): { page: Page; sample: string } | null {
  for (const p of pagesOf(ev)) {
    const s = fn(p.body || "", p);
    if (s) return { page: p, sample: s.slice(0, 220) };
  }
  return null;
}

// Context window around a literal needle inside a body.
function ctx(body: string, needle: string): string | null {
  const i = body.indexOf(needle);
  if (i < 0) return null;
  return body.slice(Math.max(0, i - 24), i + 160).replace(/\s+/g, " ").trim();
}

// Context window around a regex match inside a body.
function reCtx(body: string, re: RegExp): string | null {
  const m = re.exec(body);
  if (!m) return null;
  const i = m.index;
  return body.slice(Math.max(0, i - 24), i + 160).replace(/\s+/g, " ").trim();
}

function methodsFromAllow(allow: string): string[] {
  return allow
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
}

// ---------------------------------------------------------------------------
// API_CHECKS — category "api"
// ---------------------------------------------------------------------------

// Swagger/OpenAPI documentation paths → one detection check each.
const OPENAPI_PATHS: { path: string; label: string }[] = [
  { path: "/swagger.json", label: "Swagger tanımı (swagger.json)" },
  { path: "/openapi.json", label: "OpenAPI tanımı (openapi.json)" },
  { path: "/swagger-ui.html", label: "Swagger UI arayüzü" },
  { path: "/api-docs", label: "API dokümantasyonu (api-docs)" },
  { path: "/v2/api-docs", label: "Springfox API tanımı (v2/api-docs)" },
];

const OPENAPI_CHECKS: Check[] = OPENAPI_PATHS.map(({ path, label }): Check => ({
  id: `api-openapi-${path.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "")}`,
  category: "api",
  title: `API dokümantasyonu erişilebilir: ${label}`,
  severity: "LOW",
  cwe: "CWE-200",
  owasp: "API9:2023 Improper Inventory Management",
  description:
    `«${path}» genel erişime açık. Makine/insan tarafından okunabilir API tanımı; tüm ` +
    `uç noktaları, parametreleri ve şemayı ifşa ederek saldırı yüzeyini genişletir.`,
  remediation:
    `Üretim ortamında API tanımını ve etkileşimli arayüzü (Swagger UI vb.) kimlik ` +
    `doğrulaması arkasına alın veya tamamen devre dışı bırakın. Yalnızca dahili ağdan erişilebilir yapın.`,
  references: ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
  profiles: ["STANDARD", "DEEP"],
  evaluate(ev) {
    const probe = ev.paths[path];
    if (probe === undefined) return null;
    if (probe.exists) {
      return {
        status: "fail",
        location: `${ev.origin}${path}`,
        confidence: "confirmed",
        evidence: `HTTP ${probe.status} · ${probe.contentType || "?"} · ${probe.length} bayt`,
      };
    }
    return { status: "pass" };
  },
}));

export const API_CHECKS: Check[] = [
  // 1) GraphQL endpoint exposed (+ introspection escalation).
  {
    id: "api-graphql-endpoint",
    category: "api",
    title: "GraphQL uç noktası erişilebilir",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "API9:2023 Improper Inventory Management",
    description:
      "«/graphql» genel erişime açık. Tek başına açık olmayabilir; ancak introspection " +
      "açıksa saldırgan tüm şemayı (tipler, alanlar, mutation'lar) haritalayabilir.",
    remediation:
      "Üretimde GraphQL introspection'ı kapatın, alan öneri (field suggestion) mesajlarını " +
      "devre dışı bırakın, sorgu derinliği/karmaşıklık limiti ve kimlik doğrulaması ekleyin.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const probe = ev.paths["/graphql"];
      if (probe === undefined) return null;
      if (!probe.exists) return { status: "pass" };
      const snip = probe.snippet || "";
      const introspection = /__schema|"types"|"__type"/.test(snip);
      return {
        status: "fail",
        location: `${ev.origin}/graphql`,
        confidence: "confirmed",
        severity: introspection ? "MEDIUM" : "INFO",
        titleSuffix: introspection ? " — introspection açık" : undefined,
        detail: introspection
          ? "Yanıt introspection şema verisi içeriyor; şema tümüyle okunabilir."
          : undefined,
        evidence: `HTTP ${probe.status} · ${probe.contentType || "?"}\nÖrnek: ${snip.slice(0, 160)}`,
      };
    },
  },

  // 2) GraphiQL / playground exposed.
  {
    id: "api-graphiql-playground",
    category: "api",
    title: "GraphiQL / GraphQL Playground erişilebilir",
    severity: "MEDIUM",
    cwe: "CWE-200",
    owasp: "API9:2023 Improper Inventory Management",
    description:
      "«/graphiql» etkileşimli GraphQL arayüzü genel erişime açık. Saldırgana şemayı keşfetme " +
      "ve doğrudan sorgu çalıştırma imkânı sunar.",
    remediation:
      "Etkileşimli GraphQL arayüzlerini (GraphiQL, Playground, Apollo Sandbox) üretimde kapatın.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const probe = ev.paths["/graphiql"];
      if (probe === undefined) return null;
      if (!probe.exists) return { status: "pass" };
      return {
        status: "fail",
        location: `${ev.origin}/graphiql`,
        confidence: "confirmed",
        evidence: `HTTP ${probe.status} · ${probe.contentType || "?"} · ${probe.length} bayt`,
      };
    },
  },

  // 3-7) Swagger/OpenAPI documentation paths.
  ...OPENAPI_CHECKS,

  // 8) Verbose JSON error / stack trace.
  {
    id: "api-verbose-json-stacktrace",
    category: "api",
    title: "API yanıtında yığın izi / ayrıntılı hata",
    severity: "MEDIUM",
    cwe: "CWE-209",
    owasp: "API8:2023 Security Misconfiguration",
    description:
      "JSON API yanıtı bir yığın izi (stack trace) veya iç hata ayrıntısı içeriyor. Sunucu " +
      "içi yollar, kütüphane sürümleri ve iç yapı ifşa olur.",
    remediation:
      "Üretimde ayrıntılı hataları kapatın; istemciye yalnızca genel bir hata kimliği/mesajı " +
      "döndürün, tam izi yalnızca sunucu loglarına yazın.",
    references: ["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const hit = scanBodies(ev, (body, page) => {
        if (!isJsonPage(page)) return null;
        const sigs = ['"stack":', "at Object.<anonymous>", "Traceback (most recent call last)"];
        for (const s of sigs) {
          const c = ctx(body, s);
          if (c) return c;
        }
        const re = /\b(com\.[a-z0-9.]+Exception|[A-Za-z]+Exception:)\b/;
        return reCtx(body, re);
      });
      if (!hit) return null;
      return {
        status: "fail",
        location: hit.page.url,
        confidence: "firm",
        evidence: hit.sample,
      };
    },
  },

  // 9) CORS wildcard on a JSON endpoint.
  {
    id: "api-cors-wildcard-json",
    category: "api",
    title: "JSON uç noktasında Access-Control-Allow-Origin: *",
    severity: "LOW",
    cwe: "CWE-942",
    owasp: "API8:2023 Security Misconfiguration",
    description:
      "Bir JSON API yanıtı «Access-Control-Allow-Origin: *» ile herhangi bir kökenin okumasına " +
      "izin veriyor. Kimlik doğrulaması olmayan ama hassas veri döndüren uç noktalar için risklidir.",
    remediation:
      "Yanıtları yalnızca güvenilen kökenlere açın; genel kart (*) yerine izin verilenler " +
      "listesiyle Origin doğrulaması yapın. Kimlik bilgisi taşıyan yanıtlarda * kullanmayın.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      for (const p of pagesOf(ev)) {
        if (!isJsonPage(p)) continue;
        if ((p.headers["access-control-allow-origin"] || "").trim() === "*") {
          return {
            status: "fail",
            location: p.url,
            confidence: "confirmed",
            evidence: "Access-Control-Allow-Origin: *  (JSON yanıtı)",
          };
        }
      }
      return { status: "pass" };
    },
  },

  // 10) CORS wildcard together with credentials.
  {
    id: "api-cors-credentials-wildcard",
    category: "api",
    title: "CORS: kimlik bilgisiyle birlikte joker köken",
    severity: "HIGH",
    cwe: "CWE-942",
    owasp: "API8:2023 Security Misconfiguration",
    description:
      "Yanıt aynı anda «Access-Control-Allow-Origin: *» ve «Access-Control-Allow-Credentials: true» " +
      "gönderiyor (ya da kökeni yansıtırken kimlik bilgisine izin veriyor). Bu, oturum çerezleriyle " +
      "başka kökenlerden kimliği doğrulanmış istekleri okumaya açar.",
    remediation:
      "Kimlik bilgisi (credentials) gerektiren yanıtlarda joker köken KULLANMAYIN; tek ve doğrulanmış " +
      "bir Origin yansıtın ve izin verilenler listesiyle sınırlayın.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      for (const p of pagesOf(ev)) {
        const acao = (p.headers["access-control-allow-origin"] || "").trim();
        const creds = (p.headers["access-control-allow-credentials"] || "").trim().toLowerCase();
        if (creds === "true" && (acao === "*" || (acao !== "" && acao.toLowerCase() !== "null"))) {
          return {
            status: "fail",
            location: p.url,
            confidence: acao === "*" ? "confirmed" : "firm",
            evidence: `Access-Control-Allow-Origin: ${acao} · Access-Control-Allow-Credentials: true`,
          };
        }
      }
      return { status: "pass" };
    },
  },

  // 11) CORS Access-Control-Allow-Origin: null.
  {
    id: "api-cors-acao-null",
    category: "api",
    title: "CORS: Access-Control-Allow-Origin: null",
    severity: "MEDIUM",
    cwe: "CWE-942",
    owasp: "API8:2023 Security Misconfiguration",
    description:
      "«Access-Control-Allow-Origin: null» ayarı sandbox'lı iframe'ler ve bazı yerel bağlamlar " +
      "tarafından taklit edilebilir; saldırgan «null» köken üreterek yanıtı okuyabilir.",
    remediation:
      "«null» köken değerini asla izinli listeye almayın; kökenleri açıkça doğrulayın.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      for (const p of pagesOf(ev)) {
        if ((p.headers["access-control-allow-origin"] || "").trim().toLowerCase() === "null") {
          return {
            status: "fail",
            location: p.url,
            confidence: "confirmed",
            evidence: "Access-Control-Allow-Origin: null",
          };
        }
      }
      return { status: "pass" };
    },
  },

  // 12) JSON-looking body without a JSON content-type.
  {
    id: "api-missing-json-content-type",
    category: "api",
    title: "JSON gövde için eksik/yanlış Content-Type",
    severity: "LOW",
    cwe: "CWE-436",
    owasp: "API8:2023 Security Misconfiguration",
    description:
      "Yanıt gövdesi JSON gibi görünüyor ama Content-Type başlığı «application/json» değil. " +
      "İçeriğin tarayıcıda yanlış yorumlanmasına ve (bazı durumlarda) içerik-türü sniff'lemesine yol açabilir.",
    remediation:
      "JSON yanıtlarını «Content-Type: application/json; charset=utf-8» ile ve " +
      "«X-Content-Type-Options: nosniff» başlığıyla sunun.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const p = ev.root;
      const ct = (p.contentType || p.headers["content-type"] || "").toLowerCase();
      if (ct.includes("json")) return { status: "pass" };
      if (!looksLikeJsonBody(p.body || "")) return null;
      return {
        status: "fail",
        location: p.url,
        confidence: "firm",
        evidence: `Content-Type: ${ct || "(yok)"} · gövde JSON görünümlü`,
      };
    },
  },

  // 13) WSDL / WADL / RSDL service description exposure.
  {
    id: "api-wsdl-wadl-exposure",
    category: "api",
    title: "SOAP/REST servis tanımı erişilebilir (WSDL/WADL)",
    severity: "LOW",
    cwe: "CWE-200",
    owasp: "API9:2023 Improper Inventory Management",
    description:
      "Bir WSDL/WADL/RSDL servis tanımı genel erişime açık. Tüm operasyonları, tipleri ve uç " +
      "noktaları ifşa ederek saldırı yüzeyini genişletir.",
    remediation:
      "Servis tanım dosyalarını üretimde yayınlamayın veya kimlik doğrulaması arkasına alın.",
    references: ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const keys = Object.keys(ev.paths).filter((k) => /\.(wsdl|wadl|rsdl)(\?|$)/i.test(k));
      if (keys.length === 0) return null;
      for (const k of keys) {
        const probe = ev.paths[k];
        if (probe.exists) {
          return {
            status: "fail",
            location: `${ev.origin}${k}`,
            confidence: "confirmed",
            evidence: `HTTP ${probe.status} · ${probe.contentType || "?"} · ${probe.length} bayt`,
          };
        }
      }
      return { status: "pass" };
    },
  },

  // 14) AWS API Gateway / CloudFront fingerprint headers.
  {
    id: "api-aws-gateway-headers",
    category: "api",
    title: "Tespit: AWS API Gateway / Amazon başlıkları",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "API9:2023 Improper Inventory Management",
    description:
      "Yanıt AWS'e özgü başlıklar (x-amz-*, x-amzn-*, apigw-requestid) içeriyor. Tek başına açık " +
      "değildir ama arka uç altyapısını (Amazon API Gateway/Lambda) ifşa eder.",
    remediation:
      "Gerekmiyorsa bu başlıkları ters vekil/edge katmanında temizleyin; teknoloji ifşasını azaltın.",
    references: ["https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-troubleshooting.html"],
    profiles: ["PASSIVE", "STANDARD", "DEEP"],
    evaluate(ev) {
      for (const p of pagesOf(ev)) {
        const hdr = Object.keys(p.headers).find(
          (h) => /^x-amz-/.test(h) || /^x-amzn-/.test(h) || h === "apigw-requestid",
        );
        if (hdr) {
          return {
            status: "fail",
            location: p.url,
            confidence: "confirmed",
            evidence: `${hdr}: ${p.headers[hdr]}`,
          };
        }
      }
      return { status: "pass" };
    },
  },

  // 15) JWT leaked in a page body.
  {
    id: "api-jwt-in-body",
    category: "api",
    title: "Gövdede JWT sızıntısı",
    severity: "MEDIUM",
    cwe: "CWE-522",
    owasp: "API2:2023 Broken Authentication",
    description:
      "HTML/JSON yanıt gövdesinde bir JWT görülüyor. Token bir oturumu/erişimi temsil ediyorsa " +
      "istemci tarafında ifşası hesap ele geçirmeye yol açabilir.",
    remediation:
      "Token'ları yanıt gövdesine gömmeyin; kısa ömürlü tutun, HttpOnly çerez veya güvenli " +
      "depolama kullanın. İfşa olan token'ları iptal edin/döndürün.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const re = /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/;
      for (const p of pagesOf(ev)) {
        const m = re.exec(p.body || "");
        if (m) {
          const tok = m[0];
          const redacted = `${tok.slice(0, 16)}…[gizlendi]`;
          return {
            status: "fail",
            location: p.url,
            confidence: "firm",
            evidence: `JWT bulundu: ${redacted}`,
          };
        }
      }
      return { status: "pass" };
    },
  },

  // 16) JWT leaked in response headers / cookies.
  {
    id: "api-jwt-in-headers",
    category: "api",
    title: "Yanıt başlığı/çerezinde JWT sızıntısı",
    severity: "MEDIUM",
    cwe: "CWE-522",
    owasp: "API2:2023 Broken Authentication",
    description:
      "Bir yanıt başlığında veya Set-Cookie değerinde JWT görülüyor. Çerezde ise uygun bayraklar " +
      "yoksa; başka başlıkta ise ara sunucular/loglar tarafından yakalanabilir.",
    remediation:
      "Token taşıyan çerezlere HttpOnly + Secure + SameSite ekleyin; token'ları gereksiz " +
      "başlıklarda yansıtmayın.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const re = /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/;
      for (const p of pagesOf(ev)) {
        for (const [h, v] of Object.entries(p.headers)) {
          const m = re.exec(v);
          if (m) {
            return {
              status: "fail",
              location: p.url,
              confidence: "firm",
              evidence: `${h}: ${m[0].slice(0, 16)}…[gizlendi]`,
            };
          }
        }
        for (const c of p.setCookies) {
          const m = re.exec(c);
          if (m) {
            return {
              status: "fail",
              location: p.url,
              confidence: "firm",
              evidence: `Set-Cookie içinde JWT: ${m[0].slice(0, 16)}…[gizlendi]`,
            };
          }
        }
      }
      return { status: "pass" };
    },
  },

  // 17) JSON endpoint returning a 5xx error.
  {
    id: "api-json-server-error",
    category: "api",
    title: "Tespit: JSON uç noktası 5xx döndürüyor",
    severity: "INFO",
    cwe: "CWE-388",
    owasp: "API8:2023 Security Misconfiguration",
    description:
      "Bir JSON uç noktası sunucu hatası (5xx) döndürdü. İşlenmemiş bir istisna, kararsız bir " +
      "servis ya da girdi doğrulama eksikliğine işaret edebilir.",
    remediation:
      "Hataları yakalayıp yapılandırılmış, ayrıntısız bir hata yanıtına dönüştürün; " +
      "5xx oranlarını izleyip alarma bağlayın.",
    references: ["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const jsonPages = pagesOf(ev).filter(isJsonPage);
      if (jsonPages.length === 0) return null;
      const bad = jsonPages.find((p) => p.status >= 500 && p.status <= 599);
      if (bad) {
        return {
          status: "fail",
          location: bad.url,
          confidence: "confirmed",
          evidence: `HTTP ${bad.status} · ${bad.contentType || "?"}`,
        };
      }
      return { status: "pass" };
    },
  },

  // 18) OpenAPI/Swagger spec embedded in a body.
  {
    id: "api-openapi-spec-in-body",
    category: "api",
    title: "Tespit: gövdede gömülü OpenAPI/Swagger tanımı",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "API9:2023 Improper Inventory Management",
    description:
      "Yanıt gövdesi gömülü bir OpenAPI/Swagger tanımı içeriyor. Yayınlanan uç nokta envanterini " +
      "ve şemayı ifşa eder.",
    remediation:
      "Makine-okunur API tanımlarını yalnızca yetkili/dahili tüketiciler için sunun.",
    references: ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const re = /"swagger"\s*:\s*"2\.0"|"openapi"\s*:\s*"3(\.\d+)*"/;
      const hit = scanBodies(ev, (body) => reCtx(body, re));
      if (!hit) return null;
      return {
        status: "fail",
        location: hit.page.url,
        confidence: "confirmed",
        evidence: hit.sample,
      };
    },
  },

  // 19) API endpoints discovered in inline JS.
  {
    id: "api-endpoints-discovered",
    category: "api",
    title: "Tespit: satır içi JS içinde API uç noktaları",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "API9:2023 Improper Inventory Management",
    description:
      "İstemci JavaScript'inde API uç noktaları keşfedildi. Tek başına açık değildir ama gizli " +
      "kalması beklenen uç noktaların yüzeyini görünür kılar.",
    remediation:
      "İstemciden erişilen tüm API'lerde yetkilendirmenin sunucu tarafında zorlandığından emin olun; " +
      "gizli bir uç noktaya güvenmeyin.",
    references: ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      if (!ev.apiEndpoints || ev.apiEndpoints.length === 0) return null;
      const sample = ev.apiEndpoints.slice(0, 8).join("\n");
      return {
        status: "fail",
        location: ev.origin,
        confidence: "confirmed",
        evidence: `${ev.apiEndpoints.length} uç nokta bulundu:\n${sample}`,
      };
    },
  },
];

// ---------------------------------------------------------------------------
// HTTP_CONFIG_CHECKS — category "http-config"
// ---------------------------------------------------------------------------

// Factory for the "dangerous HTTP method advertised in Allow" family.
function methodCheck(opts: {
  method: string;
  id: string;
  title: string;
  severity: Check["severity"];
  description: string;
  remediation: string;
}): Check {
  return {
    id: opts.id,
    category: "http-config",
    title: opts.title,
    severity: opts.severity,
    cwe: "CWE-650",
    owasp: "A05:2021 Security Misconfiguration",
    description: opts.description,
    remediation: opts.remediation,
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const allow = (ev.allowHeader || "").trim();
      if (!allow) return null;
      const list = methodsFromAllow(allow);
      if (list.includes(opts.method)) {
        return {
          status: "fail",
          location: `${ev.origin} (OPTIONS)`,
          confidence: "firm",
          evidence: `Allow: ${allow}`,
        };
      }
      return { status: "pass" };
    },
  };
}

// Factory for verbose-error / debug-page body signatures.
function debugPageCheck(opts: {
  id: string;
  title: string;
  severity: Check["severity"];
  description: string;
  remediation: string;
  reference: string;
  match: (body: string) => string | null;
}): Check {
  return {
    id: opts.id,
    category: "http-config",
    title: opts.title,
    severity: opts.severity,
    cwe: "CWE-209",
    owasp: "A05:2021 Security Misconfiguration",
    description: opts.description,
    remediation: opts.remediation,
    references: [opts.reference],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const hit = scanBodies(ev, (body) => opts.match(body));
      if (!hit) return null;
      return {
        status: "fail",
        location: hit.page.url,
        confidence: "firm",
        evidence: hit.sample,
      };
    },
  };
}

// Factory for default/placeholder server pages.
function defaultPageCheck(opts: {
  id: string;
  server: string;
  needle: RegExp;
}): Check {
  return {
    id: opts.id,
    category: "http-config",
    title: `Varsayılan/yer tutucu sayfa: ${opts.server}`,
    severity: "LOW",
    cwe: "CWE-1188",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      `Sunucu ${opts.server} varsayılan/yer tutucu sayfasını gösteriyor. Yapılandırılmamış bir ` +
      `sunucuya, terk edilmiş bir sanal ana bilgisayara veya bilgi ifşasına işaret eder.`,
    remediation:
      "Varsayılan sayfaları kaldırın, kullanılmayan sanal ana bilgisayarları kapatın ve sunucu " +
      "banner/varsayılan içeriğini üretim içeriğiyle değiştirin.",
    references: ["https://owasp.org/www-project-web-security-testing-guide/"],
    profiles: ["PASSIVE", "STANDARD", "DEEP"],
    evaluate(ev) {
      const hit = scanBodies(ev, (body) => reCtx(body, opts.needle));
      if (!hit) return null;
      return {
        status: "fail",
        location: hit.page.url,
        confidence: "confirmed",
        evidence: hit.sample,
      };
    },
  };
}

export const HTTP_CONFIG_CHECKS: Check[] = [
  // 1-6) Dangerous HTTP methods advertised via Allow.
  methodCheck({
    method: "PUT",
    id: "httpcfg-method-put",
    title: "Tehlikeli HTTP metodu etkin: PUT",
    severity: "HIGH",
    description:
      "Sunucu Allow başlığında PUT metodunu duyuruyor. Yetkisiz PUT, sunucuya dosya yazma/üzerine " +
      "yazma (uzaktan kod çalıştırmaya kadar) imkânı verebilir.",
    remediation:
      "Gerekli değilse PUT metodunu kapatın; gerekliyse yalnızca kimliği doğrulanmış ve yetkili " +
      "isteklerle sınırlayın.",
  }),
  methodCheck({
    method: "DELETE",
    id: "httpcfg-method-delete",
    title: "Tehlikeli HTTP metodu etkin: DELETE",
    severity: "HIGH",
    description:
      "Sunucu Allow başlığında DELETE metodunu duyuruyor. Yetkisiz DELETE sunucudaki kaynakların " +
      "silinmesine yol açabilir.",
    remediation:
      "Gerekli değilse DELETE metodunu kapatın; gerekliyse katı kimlik doğrulama ve yetkilendirmeye bağlayın.",
  }),
  methodCheck({
    method: "TRACE",
    id: "httpcfg-method-trace",
    title: "HTTP TRACE etkin (Cross-Site Tracing)",
    severity: "MEDIUM",
    description:
      "Sunucu TRACE metodunu duyuruyor. TRACE, Cross-Site Tracing (XST) saldırılarında HttpOnly " +
      "çerezlerin veya kimlik bilgilerinin çalınmasına yardımcı olabilir.",
    remediation: "TRACE metodunu web sunucusunda tamamen devre dışı bırakın.",
  }),
  methodCheck({
    method: "TRACK",
    id: "httpcfg-method-track",
    title: "HTTP TRACK etkin (Cross-Site Tracing)",
    severity: "MEDIUM",
    description:
      "Sunucu TRACK (TRACE'in Microsoft muadili) metodunu duyuruyor; TRACE ile aynı XST riskini taşır.",
    remediation: "TRACK metodunu devre dışı bırakın.",
  }),
  methodCheck({
    method: "PATCH",
    id: "httpcfg-method-patch",
    title: "HTTP PATCH etkin",
    severity: "LOW",
    description:
      "Sunucu PATCH metodunu duyuruyor. Kısmi güncellemeye izin verir; yetkilendirme eksikse " +
      "kaynakların değiştirilmesine yol açabilir.",
    remediation:
      "PATCH yalnızca amaçlanan API uç noktalarında ve yetkilendirme ile açık olmalıdır; statik " +
      "içerikte kapatın.",
  }),
  methodCheck({
    method: "CONNECT",
    id: "httpcfg-method-connect",
    title: "HTTP CONNECT etkin",
    severity: "MEDIUM",
    description:
      "Sunucu CONNECT metodunu duyuruyor. Yanlış yapılandırılmışsa sunucunun bir proxy gibi " +
      "kullanılmasına (SSRF/tünelleme) izin verebilir.",
    remediation: "Web sunucusunda CONNECT metodunu devre dışı bırakın.",
  }),

  // 7) OPTIONS reveals the method list.
  {
    id: "httpcfg-options-reveals-methods",
    category: "http-config",
    title: "Tespit: OPTIONS metod listesini açığa çıkarıyor",
    severity: "INFO",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "OPTIONS isteği bir Allow başlığıyla desteklenen metodları listeliyor. Tek başına açık değildir " +
      "ama saldırgana desteklenen fiilleri gösterir.",
    remediation:
      "Gerekmeyen metodları kapatın; Allow başlığı yalnızca gerçekten desteklenen ve güvenli " +
      "metodları içermelidir.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const allow = (ev.allowHeader || "").trim();
      if (!allow) return null;
      return {
        status: "fail",
        location: `${ev.origin} (OPTIONS)`,
        confidence: "confirmed",
        evidence: `Allow: ${allow}`,
      };
    },
  },

  // 8) HTTP → HTTPS not enforced.
  {
    id: "httpcfg-http-not-enforced",
    category: "http-config",
    title: "HTTP → HTTPS yönlendirmesi zorlanmıyor",
    severity: "HIGH",
    cwe: "CWE-319",
    owasp: "A02:2021 Cryptographic Failures",
    description:
      "Düz HTTP kökü içeriği 2xx ile şifresiz sunuyor ve HTTPS'e yönlendirmiyor. Trafik araya girme " +
      "(MITM) ve gizli dinlemeye açık.",
    remediation:
      "Tüm HTTP isteklerini kalıcı olarak (301) HTTPS'e yönlendirin ve ardından HSTS başlığını " +
      "etkinleştirin.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      if (!ev.httpRoot) return null;
      if (ev.redirectsToHttps) return { status: "pass" };
      if (ev.httpRoot.status >= 200 && ev.httpRoot.status < 300) {
        return {
          status: "fail",
          location: ev.httpRoot.url,
          confidence: "confirmed",
          evidence: `Düz HTTP kökü HTTP ${ev.httpRoot.status} döndürdü (HTTPS'e yönlendirme yok)`,
        };
      }
      return null;
    },
  },

  // 9) Redirects to HTTPS but no HSTS on the target.
  {
    id: "httpcfg-redirect-no-hsts",
    category: "http-config",
    title: "HTTPS'e yönlendiriliyor ama hedefte HSTS yok",
    severity: "LOW",
    cwe: "CWE-319",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Site HTTP'den HTTPS'e yönlendiriyor ancak yönlendirme hedefi Strict-Transport-Security " +
      "başlığı göndermiyor. İlk (düz HTTP) istek hâlâ SSL-strip saldırısına açık kalır.",
    remediation:
      "HTTPS yanıtlarında «Strict-Transport-Security: max-age=63072000; includeSubDomains; preload» " +
      "başlığını ekleyin.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      if (!ev.redirectsToHttps) return null;
      const hsts = (ev.root.headers["strict-transport-security"] || "").trim();
      if (hsts) return { status: "pass" };
      return {
        status: "fail",
        location: ev.root.url,
        confidence: "firm",
        evidence: "HTTPS'e yönlendirme var ancak Strict-Transport-Security başlığı yok",
      };
    },
  },

  // 10) Django DEBUG page.
  debugPageCheck({
    id: "httpcfg-django-debug",
    title: "Ayrıntılı hata: Django DEBUG sayfası",
    severity: "HIGH",
    description:
      "Django uygulaması DEBUG=True ile ayrıntılı hata sayfası gösteriyor. Ayarlar, ortam " +
      "değişkenleri, SQL sorguları ve yığın izleri ifşa olur.",
    remediation: "Üretimde DEBUG=False yapın ve ALLOWED_HOSTS'u yapılandırın.",
    reference: "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
    match: (b) => ctx(b, "You're seeing this error because you have") ?? reCtx(b, /DEBUG\s*=\s*True/),
  }),

  // 11) Rails exception trace.
  debugPageCheck({
    id: "httpcfg-rails-trace",
    title: "Ayrıntılı hata: Rails istisna izi",
    severity: "HIGH",
    description:
      "Ruby on Rails uygulaması ayrıntılı istisna sayfası (Full Trace / Application Trace) gösteriyor. " +
      "Kaynak yolları, gem sürümleri ve iç yapı ifşa olur.",
    remediation:
      "Üretimde consider_all_requests_local = false yapın ve özel hata sayfaları sunun.",
    reference: "https://guides.rubyonrails.org/configuring.html",
    match: (b) => {
      if (!/Application Trace|Full Trace/.test(b)) return null;
      if (!/(ActionController|ActiveRecord|RAILS_ENV|Rails\.root|actionpack)/.test(b)) return null;
      return ctx(b, "Application Trace") ?? ctx(b, "Full Trace");
    },
  }),

  // 12) ASP.NET yellow screen of death.
  debugPageCheck({
    id: "httpcfg-aspnet-yellowscreen",
    title: "Ayrıntılı hata: ASP.NET sunucu hatası (YSOD)",
    severity: "MEDIUM",
    description:
      "ASP.NET ayrıntılı sunucu hatası (sarı ekran) gösteriyor. Yığın izleri, kaynak yolları ve " +
      "olası SQL istisnaları ifşa olur.",
    remediation:
      "web.config içinde customErrors=\"On\" (veya <deployment retail=\"true\"/>) ayarlayın ve " +
      "ayrıntılı hataları kapatın.",
    reference: "https://learn.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs",
    match: (b) => ctx(b, "Server Error in '/' Application") ?? ctx(b, "[SqlException"),
  }),

  // 13) PHP fatal error / warning with path.
  debugPageCheck({
    id: "httpcfg-php-error",
    title: "Ayrıntılı hata: PHP hata/uyarı ifşası",
    severity: "MEDIUM",
    description:
      "Yanıt, dosya yolları içeren PHP fatal error/warning mesajları gösteriyor. Sunucu dizin " +
      "yapısını ve kod detaylarını ifşa eder.",
    remediation:
      "php.ini içinde display_errors=Off yapın; hataları yalnızca log dosyasına yazın (log_errors=On).",
    reference: "https://www.php.net/manual/en/errorfunc.configuration.php#ini.display-errors",
    match: (b) => {
      const re = /(Fatal error|Warning|Parse error|Notice):\s.*\bin\s+\/[^\s<:]+\.php\b/;
      return reCtx(b, re);
    },
  }),

  // 14) Flask / Werkzeug interactive debugger.
  debugPageCheck({
    id: "httpcfg-werkzeug-debugger",
    title: "Kritik: Werkzeug/Flask etkileşimli hata ayıklayıcısı",
    severity: "HIGH",
    description:
      "Werkzeug etkileşimli hata ayıklayıcısı (Traceback konsolu) açık. PIN olmadan sunucuda kod " +
      "çalıştırmaya kadar giden bir uzaktan istismara yol açabilir.",
    remediation:
      "Üretimde debug=False çalıştırın; Werkzeug hata ayıklayıcısını internete asla açmayın.",
    reference: "https://werkzeug.palletsprojects.com/en/stable/debug/",
    match: (b) => {
      if (/Werkzeug Debugger/.test(b)) return ctx(b, "Werkzeug Debugger");
      if (/Traceback \(most recent call last\)/.test(b) && /werkzeug|traceback\.js|__traceback__/i.test(b))
        return ctx(b, "Traceback (most recent call last)");
      return null;
    },
  }),

  // 15) Express / Node stack trace.
  debugPageCheck({
    id: "httpcfg-express-stacktrace",
    title: "Ayrıntılı hata: Express/Node yığın izi",
    severity: "MEDIUM",
    description:
      "Express/Node uygulaması bir yığın izi (Error: … at …) gösteriyor. Sunucu dosya yolları ve " +
      "iç modül yapısı ifşa olur.",
    remediation:
      "Üretimde NODE_ENV=production ayarlayın ve özel hata ara yazılımı (error middleware) ile " +
      "yığın izini istemciye göndermeyin.",
    reference: "https://expressjs.com/en/advanced/best-practice-security.html",
    match: (b) => {
      const re = /Error:.*<\/?pre>[\s\S]{0,400}?\bat\s+[\w$.<>]+\s+\(?\/?[^\s)]+:\d+:\d+\)?/;
      if (re.test(b)) return reCtx(b, /Error:[\s\S]{0,200}?\bat\s+/);
      return null;
    },
  }),

  // 16) Generic Python/Java traceback.
  debugPageCheck({
    id: "httpcfg-generic-traceback",
    title: "Ayrıntılı hata: yığın izi (traceback) ifşası",
    severity: "MEDIUM",
    description:
      "Yanıt gövdesinde işlenmemiş bir yığın izi (Python traceback veya Java istisna zinciri) var. " +
      "Sunucu içi yolları ve teknoloji ayrıntılarını ifşa eder.",
    remediation:
      "İşlenmemiş istisnaları yakalayıp genel bir hata sayfasına dönüştürün; izleri yalnızca loglara yazın.",
    reference: "https://owasp.org/www-community/Improper_Error_Handling",
    match: (b) => {
      if (/Traceback \(most recent call last\)/.test(b))
        return ctx(b, "Traceback (most recent call last)");
      const re = /\bat\s+(?:java|org|com|net)\.[\w.$]+\([\w.$]+\.java:\d+\)/;
      return reCtx(b, re);
    },
  }),

  // 17) SQL error disclosure.
  {
    id: "httpcfg-sql-error-disclosure",
    category: "http-config",
    title: "Ayrıntılı hata: SQL hata mesajı ifşası",
    severity: "MEDIUM",
    cwe: "CWE-209",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Yanıt gövdesinde bir veritabanı hata mesajı görülüyor. Şema/sürgü ayrıntılarını ifşa eder ve " +
      "çoğu zaman SQL enjeksiyonu için güçlü bir belirtidir.",
    remediation:
      "Veritabanı hatalarını yakalayın; istemciye ham hata döndürmeyin. Parametreli sorgular kullanın.",
    references: ["https://owasp.org/www-community/Improper_Error_Handling"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const re =
        /(SQL syntax.*MySQL|You have an error in your SQL syntax|Warning:\s+mysql_|ORA-\d{5}|PostgreSQL.*ERROR|SQLSTATE\[|System\.Data\.SqlClient\.SqlException|Unclosed quotation mark after the character string)/;
      const hit = scanBodies(ev, (body) => reCtx(body, re));
      if (!hit) return null;
      return {
        status: "fail",
        location: hit.page.url,
        confidence: "firm",
        evidence: hit.sample,
      };
    },
  },

  // 18) Directory listing enabled.
  {
    id: "httpcfg-directory-listing",
    category: "http-config",
    title: "Dizin listeleme etkin",
    severity: "MEDIUM",
    cwe: "CWE-548",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Sunucu bir dizinin içeriğini otomatik listeliyor (Index of / veya Directory listing for). " +
      "Yayınlanması amaçlanmayan dosyalar keşfedilebilir.",
    remediation:
      "Otomatik dizin listelemeyi kapatın (Apache: Options -Indexes; Nginx: autoindex off).",
    references: ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      const hit = scanBodies(ev, (body) => {
        return (
          reCtx(body, /<title>\s*Index of \//i) ??
          ctx(body, "Directory listing for")
        );
      });
      if (!hit) return null;
      return {
        status: "fail",
        location: hit.page.url,
        confidence: "confirmed",
        evidence: hit.sample,
      };
    },
  },

  // 19-22) Default / placeholder server pages.
  defaultPageCheck({ id: "httpcfg-default-nginx", server: "nginx", needle: /Welcome to nginx!/i }),
  defaultPageCheck({
    id: "httpcfg-default-apache",
    server: "Apache",
    needle: /Apache2 (?:Ubuntu|Debian|CentOS)? ?Default Page|It works!/i,
  }),
  defaultPageCheck({
    id: "httpcfg-default-iis",
    server: "IIS",
    needle: /IIS Windows Server|Internet Information Services/i,
  }),
  defaultPageCheck({
    id: "httpcfg-default-tomcat",
    server: "Apache Tomcat",
    needle: /If you're seeing this, you've successfully installed Tomcat|Apache Tomcat\/[\d.]+/i,
  }),

  // 23) Root returns a 5xx (server unstable).
  {
    id: "httpcfg-server-5xx",
    category: "http-config",
    title: "Tespit: kök sayfa 5xx döndürüyor",
    severity: "INFO",
    cwe: "CWE-388",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Kök sayfa bir sunucu hatası (5xx) döndürdü. Kararsız bir servise veya işlenmemiş bir " +
      "istisnaya işaret edebilir.",
    remediation:
      "Sunucu hatalarını araştırın; 5xx oranlarını izleyip alarma bağlayın ve istemciye ayrıntısız " +
      "hata sayfası sunun.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#server_error_responses"],
    profiles: ["PASSIVE", "STANDARD", "DEEP"],
    evaluate(ev) {
      if (ev.root.status >= 500 && ev.root.status <= 599) {
        return {
          status: "fail",
          location: ev.root.url,
          confidence: "confirmed",
          evidence: `HTTP ${ev.root.status}`,
        };
      }
      return { status: "pass" };
    },
  },

  // 24) Referrer-Policy: unsafe-url.
  {
    id: "httpcfg-referrer-policy-unsafe-url",
    category: "http-config",
    title: "Referrer-Policy: unsafe-url (referrer sızıntısı)",
    severity: "MEDIUM",
    cwe: "CWE-200",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "«Referrer-Policy: unsafe-url» tam URL'yi (yol ve sorgu dizesi dâhil) HTTPS'ten HTTP'ye " +
      "dahi her isteğe Referer olarak gönderir; oturum token'ları veya hassas parametreler sızabilir.",
    remediation:
      "Referrer-Policy'yi «strict-origin-when-cross-origin» veya «no-referrer» gibi güvenli bir " +
      "değere ayarlayın.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    profiles: ["PASSIVE", "STANDARD", "DEEP"],
    evaluate(ev) {
      for (const p of pagesOf(ev)) {
        const rp = (p.headers["referrer-policy"] || "").trim().toLowerCase();
        if (!rp) continue;
        if (rp.split(",").map((s) => s.trim()).includes("unsafe-url")) {
          return {
            status: "fail",
            location: p.url,
            confidence: "confirmed",
            evidence: `Referrer-Policy: ${p.headers["referrer-policy"]}`,
          };
        }
      }
      return { status: "pass" };
    },
  },

  // 25) Overly permissive Access-Control-Allow-Methods: *.
  {
    id: "httpcfg-acam-wildcard",
    category: "http-config",
    title: "Access-Control-Allow-Methods: * (aşırı izin)",
    severity: "LOW",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "«Access-Control-Allow-Methods: *» tüm HTTP metodlarını çapraz köken isteklere açar. Diğer " +
      "gevşek CORS ayarlarıyla birleştiğinde saldırı yüzeyini genişletir.",
    remediation:
      "İzin verilen metodları yalnızca gerçekten gerekenlerle (örn. GET, POST) açıkça listeleyin.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods"],
    profiles: ["STANDARD", "DEEP"],
    evaluate(ev) {
      for (const p of pagesOf(ev)) {
        if ((p.headers["access-control-allow-methods"] || "").trim() === "*") {
          return {
            status: "fail",
            location: p.url,
            confidence: "confirmed",
            evidence: "Access-Control-Allow-Methods: *",
          };
        }
      }
      return { status: "pass" };
    },
  },
];
