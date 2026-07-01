// The actual security checks. Each analyzer turns raw HTTP/TLS observations
// into FindingDraft objects, drawing severity + remediation from the knowledge
// base. Analyzers are pure-ish: they fetch (via the shared client) and return
// findings; they never persist or stream directly.
import tls from "node:tls";
import { httpGet, type HttpResult, type RequestBudget } from "./http";
import { kbEntry } from "./knowledge";
import { assertPublicHost } from "../ssrf";
import type { FindingDraft, Severity } from "../types";

function mk(
  checkId: string,
  location: string,
  extra: {
    evidence?: string;
    descriptionExtra?: string;
    severity?: Severity;
    confidence?: FindingDraft["confidence"];
    titleSuffix?: string;
  } = {},
): FindingDraft {
  const kb = kbEntry(checkId);
  if (!kb) {
    return {
      checkId,
      title: checkId,
      severity: extra.severity ?? "INFO",
      location,
      description: extra.descriptionExtra ?? "",
      remediation: "",
      evidence: extra.evidence,
      confidence: extra.confidence ?? "firm",
    };
  }
  return {
    checkId,
    title: kb.title + (extra.titleSuffix ?? ""),
    severity: extra.severity ?? kb.severity,
    cwe: kb.cwe,
    owasp: kb.owasp,
    location,
    description: extra.descriptionExtra ? `${kb.description}\n\n${extra.descriptionExtra}` : kb.description,
    remediation: kb.remediation,
    evidence: extra.evidence,
    confidence: extra.confidence ?? "firm",
  };
}

// --- Security headers --------------------------------------------------------

export function analyzeSecurityHeaders(res: HttpResult): FindingDraft[] {
  const out: FindingDraft[] = [];
  const h = res.headers;
  const at = res.finalUrl;
  const isHttps = at.startsWith("https://");

  if (isHttps && !h["strict-transport-security"]) out.push(mk("missing-hsts", at));
  if (!h["content-security-policy"]) out.push(mk("missing-csp", at));
  if (!h["x-content-type-options"]) out.push(mk("missing-x-content-type-options", at));

  const csp = h["content-security-policy"] ?? "";
  if (!h["x-frame-options"] && !/frame-ancestors/i.test(csp)) {
    out.push(mk("missing-x-frame-options", at));
  }
  if (!h["referrer-policy"]) out.push(mk("missing-referrer-policy", at));
  if (!h["permissions-policy"]) out.push(mk("missing-permissions-policy", at));

  // CSP present but weak: unsafe-inline/unsafe-eval on scripts, wildcard
  // sources, or no object-src lock. Presence alone is not protection.
  if (csp) {
    const weaknesses: string[] = [];
    const scriptSrc = /script-src[^;]*/i.exec(csp)?.[0] ?? "";
    if (/'unsafe-inline'/i.test(scriptSrc) && !/'nonce-|'strict-dynamic'|'sha(256|384|512)-/i.test(scriptSrc)) {
      weaknesses.push("script-src 'unsafe-inline' (nonce/hash olmadan)");
    }
    if (/'unsafe-eval'/i.test(scriptSrc)) weaknesses.push("script-src 'unsafe-eval'");
    if (/(?:default|script)-src[^;]*\*(?![.\w])/i.test(csp)) weaknesses.push("joker (*) kaynak");
    if (!/object-src/i.test(csp) && !/default-src[^;]*'none'/i.test(csp)) {
      weaknesses.push("object-src 'none' yok");
    }
    if (weaknesses.length) {
      out.push(mk("weak-csp", at, { evidence: `Zayıf yönergeler:\n- ${weaknesses.join("\n- ")}` }));
    }
  }

  const server = h["server"];
  const powered = h["x-powered-by"];
  if ((server && /\d/.test(server)) || powered) {
    out.push(
      mk("server-version-disclosure", at, {
        evidence: [server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`]
          .filter(Boolean)
          .join("\n"),
      }),
    );
  }
  return out;
}

// --- Cookies -----------------------------------------------------------------

export function analyzeCookies(res: HttpResult): FindingDraft[] {
  // Prefer the properly-split Set-Cookie array (fetch collapses multiple
  // Set-Cookie into one comma-joined string, which mangles `Expires=` dates).
  const cookies =
    res.setCookies.length > 0
      ? res.setCookies
      : res.headers["set-cookie"]
        ? res.headers["set-cookie"].split(/,(?=[^;]+?=)/)
        : [];
  if (!cookies.length) return [];
  const isHttps = res.finalUrl.startsWith("https://");
  const out: FindingDraft[] = [];
  for (const c of cookies) {
    const name = c.split("=")[0]?.trim() ?? "cookie";
    const missing: string[] = [];
    const hasSecure = /;\s*secure/i.test(c);
    if (isHttps && !hasSecure) missing.push("Secure");
    if (!/;\s*httponly/i.test(c)) missing.push("HttpOnly");
    if (!/;\s*samesite/i.test(c)) missing.push("SameSite");
    if (missing.length) {
      out.push(
        mk("insecure-cookie", res.finalUrl, {
          titleSuffix: ` — «${name}»`,
          evidence: `Set-Cookie: ${c.trim()}\nEksik bayraklar: ${missing.join(", ")}`,
        }),
      );
    }
    // SameSite=None *requires* Secure, or the browser rejects it and it becomes
    // a CSRF/leak vector.
    if (/;\s*samesite\s*=\s*none/i.test(c) && !hasSecure) {
      out.push(
        mk("insecure-samesite-none", res.finalUrl, {
          titleSuffix: ` — «${name}»`,
          evidence: `Set-Cookie: ${c.trim()}`,
        }),
      );
    }
  }
  return out;
}

// --- HTTPS enforcement -------------------------------------------------------

export async function analyzeHttpsRedirect(host: string, budget: RequestBudget): Promise<FindingDraft[]> {
  const res = await httpGet(`http://${host}/`, { budget, redirect: "manual" });
  if (res.error) return [];
  const loc = res.headers["location"] ?? "";
  const redirectsToHttps = res.status >= 300 && res.status < 400 && loc.startsWith("https://");
  if (!redirectsToHttps && res.status !== 0) {
    return [
      mk("no-https", `http://${host}/`, {
        evidence: `HTTP yanıt kodu: ${res.status}${loc ? `, Location: ${loc}` : " (HTTPS yönlendirmesi yok)"}`,
        confidence: res.status >= 200 && res.status < 300 ? "confirmed" : "firm",
      }),
    ];
  }
  return [];
}

// --- TLS ---------------------------------------------------------------------

interface TlsInfo {
  protocol?: string;
  validTo?: Date;
  authorized?: boolean;
  authorizationError?: string;
  error?: string;
}

function inspectTls(host: string): Promise<TlsInfo> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r: TlsInfo) => {
      if (done) return;
      done = true;
      resolve(r);
    };
    // rejectUnauthorized:false so we can *inspect* invalid certs and report
    // them; we capture socket.authorized to know whether the chain validated.
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol() ?? undefined;
        const validTo = cert?.valid_to ? new Date(cert.valid_to) : undefined;
        const authorized = socket.authorized;
        const authorizationError = socket.authorizationError
          ? String(socket.authorizationError)
          : undefined;
        socket.end();
        finish({ protocol, validTo, authorized, authorizationError });
      },
    );
    socket.setTimeout(8000, () => {
      socket.destroy();
      finish({ error: "timeout" });
    });
    socket.on("error", (e) => finish({ error: e.message }));
  });
}

export async function analyzeTls(host: string): Promise<FindingDraft[]> {
  // Defence-in-depth: never open a raw TLS socket to an internal host.
  try {
    await assertPublicHost(host);
  } catch {
    return [];
  }
  const info = await inspectTls(host);
  if (info.error) return [];
  const out: FindingDraft[] = [];

  // Untrusted/invalid certificate (self-signed, expired, hostname mismatch,
  // unknown CA). Browsers hard-block these.
  if (info.authorized === false && info.authorizationError) {
    out.push(
      mk("tls-untrusted", `https://${host}`, {
        evidence: `Sertifika doğrulaması başarısız: ${info.authorizationError}`,
        confidence: "confirmed",
      }),
    );
  }

  if (info.validTo) {
    const daysLeft = Math.floor((info.validTo.getTime() - Date.now()) / 86_400_000);
    if (daysLeft < 0) {
      out.push(
        mk("tls-expired", `https://${host}`, {
          evidence: `Sertifika ${info.validTo.toISOString()} tarihinde sona ermiş (${-daysLeft} gün önce).`,
          confidence: "confirmed",
        }),
      );
    } else if (daysLeft < 14) {
      out.push(
        mk("tls-expired", `https://${host}`, {
          severity: "MEDIUM",
          titleSuffix: ` (${daysLeft} gün kaldı)`,
          evidence: `Sertifika ${daysLeft} gün içinde dolacak (${info.validTo.toISOString()}).`,
        }),
      );
    }
  }

  if (info.protocol && /TLSv1(\.[01])?$/.test(info.protocol) && info.protocol !== "TLSv1.2" && info.protocol !== "TLSv1.3") {
    out.push(
      mk("tls-weak", `https://${host}`, {
        evidence: `Müzakere edilen protokol: ${info.protocol}`,
      }),
    );
  }
  return out;
}

// --- Mixed content -----------------------------------------------------------

export function analyzeMixedContent(res: HttpResult): FindingDraft[] {
  if (!res.finalUrl.startsWith("https://") || !res.body) return [];
  const matches = [...res.body.matchAll(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)]
    .map((m) => m[1])
    .filter((u) => !/\.(png|jpg|jpeg|gif|svg|ico)$/i.test(u)) // images are passive mixed content (lower risk)
    .slice(0, 5);
  if (!matches.length) return [];
  return [
    mk("mixed-content", res.finalUrl, {
      evidence: matches.join("\n"),
    }),
  ];
}

// --- Subresource Integrity ---------------------------------------------------

export function analyzeSri(res: HttpResult): FindingDraft[] {
  if (!res.body) return [];
  let origin: string;
  try {
    origin = new URL(res.finalUrl).origin;
  } catch {
    return [];
  }
  const tags = res.body.match(/<script\b[^>]*\bsrc\s*=\s*["'][^"']+["'][^>]*>/gi) ?? [];
  const bad: string[] = [];
  for (const tag of tags) {
    const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1];
    if (!src) continue;
    let abs: URL;
    try {
      abs = new URL(src, res.finalUrl);
    } catch {
      continue;
    }
    if (abs.origin === origin) continue; // same-origin scripts don't need SRI
    if (/\bintegrity\s*=/i.test(tag)) continue;
    bad.push(abs.toString());
    if (bad.length >= 5) break;
  }
  if (!bad.length) return [];
  return [mk("sri-missing", res.finalUrl, { evidence: `Bütünlük (SRI) olmayan dış scriptler:\n${bad.join("\n")}` })];
}

// --- Cache-Control on sensitive responses ------------------------------------

export function analyzeCacheControl(res: HttpResult): FindingDraft[] {
  const cc = res.headers["cache-control"] ?? "";
  // Only meaningful when the response looks authenticated/sensitive.
  const sensitive = res.setCookies.length > 0 || /<input[^>]+type\s*=\s*["']?password/i.test(res.body);
  if (!sensitive) return [];
  if (/no-store|private/i.test(cc)) return [];
  return [
    mk("missing-cache-control", res.finalUrl, {
      evidence: cc ? `Cache-Control: ${cc}` : "Cache-Control başlığı yok (oturum çerezi/parola alanı mevcut).",
    }),
  ];
}

// --- Sensitive paths ---------------------------------------------------------

const SENSITIVE_PATHS = [
  "/.env",
  "/.git/config",
  "/.git/HEAD",
  "/config.json",
  "/wp-config.php.bak",
  "/.DS_Store",
  "/backup.zip",
  "/.svn/entries",
  "/phpinfo.php",
  "/server-status",
];

export async function checkSensitivePaths(origin: string, budget: RequestBudget): Promise<FindingDraft[]> {
  const out: FindingDraft[] = [];
  for (const p of SENSITIVE_PATHS) {
    const res = await httpGet(`${origin}${p}`, { budget, redirect: "manual" });
    if (res.status === 200 && res.body && looksLikeRealFile(p, res.body)) {
      out.push(
        mk("sensitive-file-exposed", res.finalUrl, {
          titleSuffix: ` — ${p}`,
          evidence: `200 OK, ${res.body.length} bayt.\nÖrnek: ${res.body.slice(0, 200).replace(/\s+/g, " ")}`,
          confidence: "confirmed",
        }),
      );
    }
  }
  return out;
}

function looksLikeRealFile(path: string, body: string): boolean {
  // Guard against SPAs that return 200 + index.html for everything.
  if (/<!doctype html>|<html/i.test(body) && !path.endsWith(".php")) {
    if (path === "/.env" || path.includes(".git")) return false;
  }
  if (path === "/.env") return /[A-Z_]+=/.test(body);
  if (path.includes(".git")) return /ref:|\[core\]/.test(body);
  return true;
}

// --- Directory listing -------------------------------------------------------

export function analyzeDirectoryListing(res: HttpResult): FindingDraft[] {
  if (res.status === 200 && /<title>Index of \/|Directory listing for/i.test(res.body)) {
    return [mk("directory-listing", res.finalUrl, { evidence: "Yanıt gövdesi dizin listesi içeriyor.", confidence: "confirmed" })];
  }
  return [];
}

// --- CORS --------------------------------------------------------------------

export async function analyzeCors(url: string, budget: RequestBudget): Promise<FindingDraft[]> {
  const probe = "https://evil.example.com";
  const res = await httpGet(url, { budget, headers: { Origin: probe } });
  if (res.error) return [];
  const acao = res.headers["access-control-allow-origin"];
  const acac = res.headers["access-control-allow-credentials"];
  if (acao && (acao === probe || acao === "*") && acac === "true") {
    return [
      mk("cors-misconfig", res.finalUrl, {
        evidence: `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}\n(Origin yansıtılıyor/credentials açık)`,
        confidence: "confirmed",
      }),
    ];
  }
  return [];
}

// --- Reflected XSS (light, non-destructive) ----------------------------------

export async function probeReflectedXss(
  baseUrl: string,
  params: string[],
  budget: RequestBudget,
): Promise<FindingDraft[]> {
  const out: FindingDraft[] = [];
  const marker = `sntnl${Math.random().toString(36).slice(2, 8)}`;
  const payload = `"><svg/onload=${marker}>`;
  for (const param of params.slice(0, 6)) {
    const u = new URL(baseUrl);
    u.searchParams.set(param, payload);
    const res = await httpGet(u.toString(), { budget });
    if (res.error || !res.body) continue;
    // Reflected verbatim (unencoded) → likely XSS. Encoded reflection is safe.
    if (res.body.includes(payload)) {
      out.push(
        mk("reflected-xss", u.toString(), {
          titleSuffix: ` — parametre «${param}»`,
          evidence: `Gönderilen payload yanıtta kodlanmadan yansıdı:\n${payload}`,
          confidence: "firm",
        }),
      );
    }
  }
  return out;
}

// --- Open redirect -----------------------------------------------------------

const REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnUrl", "dest", "target", "r"];

export async function probeOpenRedirect(baseUrl: string, budget: RequestBudget): Promise<FindingDraft[]> {
  const out: FindingDraft[] = [];
  const u0 = new URL(baseUrl);
  const candidates = REDIRECT_PARAMS.filter((p) => u0.searchParams.has(p));
  const evil = "https://sentinel-redirect-test.example.com/";
  for (const param of candidates.slice(0, 4)) {
    const u = new URL(baseUrl);
    u.searchParams.set(param, evil);
    const res = await httpGet(u.toString(), { budget, redirect: "manual" });
    const loc = res.headers["location"] ?? "";
    if (res.status >= 300 && res.status < 400 && loc.startsWith(evil)) {
      out.push(
        mk("open-redirect", u.toString(), {
          titleSuffix: ` — parametre «${param}»`,
          evidence: `Location: ${loc}`,
          confidence: "confirmed",
        }),
      );
    }
  }
  return out;
}

// --- Outdated libraries (heuristic) -----------------------------------------

export function detectOutdatedLibraries(scripts: string[]): FindingDraft[] {
  const out: FindingDraft[] = [];
  for (const s of scripts) {
    const jq = s.match(/jquery[-.]?(\d+)\.(\d+)(?:\.(\d+))?/i);
    if (jq) {
      const major = Number(jq[1]);
      const minor = Number(jq[2]);
      if (major < 3 || (major === 3 && minor < 5)) {
        out.push(
          mk("outdated-library", s, {
            titleSuffix: ` — jQuery ${jq[1]}.${jq[2]}${jq[3] ? "." + jq[3] : ""}`,
            evidence: `Yüklenen: ${s}\njQuery < 3.5 sürümlerinde bilinen XSS açıkları (ör. CVE-2020-11022/11023) bulunur.`,
          }),
        );
      }
    }
  }
  return out;
}
