// One-shot evidence collection. Every check reads this snapshot, so request
// volume stays bounded no matter how many checks reference the same data.
import tls from "node:tls";
import { promises as dns } from "node:dns";
import { httpGet, type HttpResult, type RequestBudget } from "../http";
import { crawl } from "../crawler";
import { assertPublicHost } from "../../ssrf";
import type { Emit, ScanProfile } from "./types";
import { SENSITIVE_PATHS } from "./data/paths";
import { runActiveProbes } from "./active";
import type { Evidence, PageEvidence, TlsEvidence, TlsMatrix, DnsEvidence, ProbeEvidence } from "./types";

function toPage(res: HttpResult): PageEvidence {
  const title = /<title[^>]*>([^<]*)<\/title>/i.exec(res.body)?.[1]?.trim().slice(0, 200) ?? "";
  return {
    url: res.finalUrl,
    status: res.status,
    ok: res.ok,
    headers: res.headers,
    setCookies: res.setCookies,
    body: res.body,
    title,
    contentType: res.headers["content-type"] ?? "",
    error: res.error,
  };
}

// ---- TLS deep inspection ----------------------------------------------------

// Node's getCipher() no longer reports key bits, so derive the symmetric
// strength from the negotiated suite name (the bulk-cipher token, never the SHA
// MAC — "AES128-GCM-SHA256" is 128-bit, not 256). Undefined when unrecognised.
function cipherBitsFromName(name?: string): number | undefined {
  if (!name) return undefined;
  const n = name.toUpperCase();
  if (/AES[_-]?256|CHACHA20/.test(n)) return 256;
  if (/AES[_-]?128/.test(n)) return 128;
  if (/3DES|DES[_-]?CBC3|DES[_-]?EDE/.test(n)) return 112;
  if (/EXP(ORT)?|[_-]40[_-]/.test(n)) return 40;
  if (/RC4/.test(n)) return 128; // nominal; still flagged by crypto-weak-cipher
  if (/(^|[^A-Z0-9])DES([_-]|$)/.test(n)) return 56;
  if (/NULL/.test(n)) return 0;
  return undefined;
}

function deepTls(host: string): Promise<TlsEvidence> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r: TlsEvidence) => {
      if (done) return;
      done = true;
      resolve(r);
    };
    const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true);
      const cipher = socket.getCipher?.();
      const protocol = socket.getProtocol() ?? undefined;
      const validTo = cert?.valid_to ? new Date(cert.valid_to) : undefined;
      const daysToExpiry = validTo ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : undefined;
      const str = (x: unknown): string | undefined => (Array.isArray(x) ? x.join(",") : typeof x === "string" ? x : undefined);
      const issuerCN = str(cert?.issuer?.CN);
      const subjectCN = str(cert?.subject?.CN);
      const san = (cert as { subjectaltname?: string })?.subjectaltname;
      const selfSigned =
        !!issuerCN && !!subjectCN && issuerCN === subjectCN && socket.authorized === false;
      finish({
        reachable: true,
        protocol,
        cipherName: cipher?.name,
        cipherBits: (cipher as { bits?: number })?.bits ?? cipherBitsFromName(cipher?.name),
        validFrom: cert?.valid_from,
        validTo: cert?.valid_to,
        daysToExpiry,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
        issuer: issuerCN,
        subjectCN,
        altNames: san ? san.split(/,\s*/).map((s) => s.replace(/^DNS:/, "")) : undefined,
        keyBits: (cert as { bits?: number })?.bits,
        // Note: Node's TLS/X509 API exposes no signature-algorithm field, so
        // sigAlg is intentionally not collected (the SHA-1/MD5 check was removed
        // rather than shipped permanently N/A).
        selfSigned,
        san,
      });
      socket.end();
    });
    socket.setTimeout(8000, () => {
      socket.destroy();
      finish({ reachable: false, error: "timeout" });
    });
    socket.on("error", (e) => finish({ reachable: false, error: e.message } as TlsEvidence));
  });
}

// ---- DNS + email security ---------------------------------------------------

async function tryResolve<T>(fn: () => Promise<T[]>): Promise<{ ok: boolean; value: T[] | null }> {
  try {
    return { ok: true, value: await fn() };
  } catch {
    return { ok: false, value: null };
  }
}

// Approximate registrable ("org") domain without a full public-suffix list.
// Handles the common two-level TLDs (co.uk, com.tr, …) so DMARC/CAA tree-climbing
// from a subdomain reaches the right apex.
const TWO_LEVEL_SLD = new Set(["co", "com", "org", "net", "gov", "edu", "ac", "gob", "go", "or", "ne", "in", "gen"]);
function registrableDomain(host: string): string {
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return host;
  const secondToLast = parts[parts.length - 2];
  if (TWO_LEVEL_SLD.has(secondToLast) && parts.length >= 3) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

async function collectDns(host: string): Promise<DnsEvidence> {
  const out: DnsEvidence = { resolved: false, a: [], aaaa: [], mx: [], ns: [], txt: [], caa: [] };
  const safe = async <T>(p: Promise<T>, fallback: T): Promise<T> => {
    try {
      return await p;
    } catch {
      return fallback;
    }
  };
  out.a = await safe(dns.resolve4(host), []);
  out.aaaa = await safe(dns.resolve6(host), []);
  out.mx = (await safe(dns.resolveMx(host), [])).map((m) => m.exchange);
  out.ns = await safe(dns.resolveNs(host), []);
  // TXT resolution drives SPF/DMARC — retry transient failures, and record
  // whether it ultimately succeeded so "missing" checks don't fire on a
  // timeout (can't-check ≠ absent).
  let txts: string[][] | null = null;
  for (let attempt = 0; attempt < 3 && txts === null; attempt++) {
    try {
      txts = await dns.resolveTxt(host);
    } catch {
      txts = null;
    }
  }
  out.txtResolved = txts !== null;
  out.txt = (txts ?? []).map((chunks) => chunks.join(""));
  out.spf = out.txt.find((t) => /^v=spf1/i.test(t));

  const org = registrableDomain(host);

  // CAA lives at the exact name OR any ancestor up to the org domain (RFC 8659
  // tree-climbing). Query the host and the org domain; caaResolved is false only
  // if BOTH lookups errored (so "missing" isn't concluded from a failed lookup).
  const caaHost = await tryResolve(() => dns.resolveCaa(host));
  const caaOrg = org !== host ? await tryResolve(() => dns.resolveCaa(org)) : caaHost;
  out.caaResolved = caaHost.ok || caaOrg.ok;
  out.caa = [...(caaHost.value ?? []), ...(caaOrg.value ?? [])].map((c) => JSON.stringify(c));

  // DMARC is published at _dmarc.<domain>; receivers fall back to the org domain
  // for subdomains. Check both; dmarcResolved is false only if both lookups fail.
  const dmarcHost = await tryResolve(() => dns.resolveTxt(`_dmarc.${host}`));
  const dmarcOrg = org !== host ? await tryResolve(() => dns.resolveTxt(`_dmarc.${org}`)) : dmarcHost;
  out.dmarcResolved = dmarcHost.ok || dmarcOrg.ok;
  const dmarcRecords = [...(dmarcHost.value ?? []), ...(dmarcOrg.value ?? [])].map((c) => c.join(""));
  out.dmarc = dmarcRecords.find((t) => /^v=DMARC1/i.test(t));
  out.dmarcPolicy = out.dmarc ? /p=(\w+)/i.exec(out.dmarc)?.[1]?.toLowerCase() : undefined;
  const mtaSts = await safe(dns.resolveTxt(`_mta-sts.${host}`), []);
  out.mtaSts = mtaSts.some((c) => /v=STSv1/i.test(c.join("")));
  // Best-effort DKIM detection via common selectors (only meaningful with MX).
  // Passive and inexact — the check that reads this is INFO/tentative.
  if (out.mx.length > 0) {
    const selectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2", "smtp"];
    const hits = await Promise.all(
      selectors.map((s) =>
        safe(dns.resolveTxt(`${s}._domainkey.${host}`), [] as string[][]).then((r) =>
          r.some((c) => /v=DKIM1|(^|;)\s*[kp]=/i.test(c.join(""))),
        ),
      ),
    );
    out.dkimHint = hits.some(Boolean);
  }
  out.resolved = out.a.length > 0 || out.aaaa.length > 0 || out.mx.length > 0;
  return out;
}

// ---- Sensitive-path probing (bounded by profile + budget) -------------------

function isHtmlResp(res: HttpResult): boolean {
  return /text\/html/i.test(res.headers["content-type"] ?? "") || /<!doctype html>|<html[\s>]/i.test(res.body);
}

function looksReal(path: string, res: HttpResult): boolean {
  if (res.status !== 200 || !res.body) return false;
  const body = res.body;
  const isHtml = isHtmlResp(res);
  if (path.endsWith(".json")) return /^[\s]*[[{]/.test(body);
  if (path === "/.env" || /\.env/.test(path)) return /^[A-Z0-9_]+\s*=/m.test(body) && !isHtml;
  if (path.includes(".git")) return /(ref:|\[core\]|^P )/m.test(body) && !isHtml;
  if (/\.(sql|bak|old|zip|tar|gz)$/i.test(path)) return !isHtml;
  if (/\.(xml|yml|yaml|ini|conf|config)$/i.test(path)) return !isHtml || /<\?xml/i.test(body);
  return true;
}

interface Baseline {
  status: number;
  len: number;
  html: boolean;
}

// Probe a couple of definitely-nonexistent paths to learn how the site answers
// "not found". Sites that return a 200 app-shell for everything (SPAs, GitHub,
// many frameworks) would otherwise trigger false disclosure findings.
async function softNotFoundBaseline(origin: string, budget: RequestBudget): Promise<{ baselines: Baseline[]; catchAll: boolean }> {
  const baselines: Baseline[] = [];
  for (const rnd of ["/sentinel-nx-a8f3e1q9z2", "/sentinel-nx-4d7b0c.html"]) {
    if (budget.expired()) break;
    const r = await httpGet(`${origin}${rnd}`, { budget, redirect: "manual" });
    if (!r.error) baselines.push({ status: r.status, len: r.body.length, html: isHtmlResp(r) });
  }
  const catchAll = baselines.some((b) => b.status === 200);
  return { baselines, catchAll };
}

function titleSegs(title: string): string[] {
  return title
    .split(/[·|—–:]|\s[-|]\s/)
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length >= 3);
}
function pageTitle(body: string): string {
  return /<title[^>]*>([^<]*)<\/title>/i.exec(body)?.[1]?.trim() ?? "";
}

async function probePaths(
  origin: string,
  profile: ScanProfile,
  budget: RequestBudget,
  emit: Emit,
  rootTitle: string,
): Promise<Record<string, ProbeEvidence>> {
  const out: Record<string, ProbeEvidence> = {};
  if (profile === "PASSIVE") return out;
  const { baselines, catchAll } = await softNotFoundBaseline(origin, budget);
  const rootSegs = new Set(titleSegs(rootTitle)); // the site's title "brand"
  const maxTier = profile === "DEEP" ? 2 : 1;
  const list = SENSITIVE_PATHS.filter((p) => p.tier <= maxTier);
  let probed = 0;
  for (const sig of list) {
    if (budget.expired()) break;
    const res = await httpGet(`${origin}${sig.path}`, { budget, redirect: "manual" });
    if (res.error) continue;
    let exists = looksReal(sig.path, res) && (!sig.sig || sig.sig.test(res.body));
    // Soft-404 suppression: drop matches indistinguishable from the site's
    // "not found" response, and — on catch-all-200 sites — any signatureless
    // HTML hit (a real leaked file is almost never the app's HTML shell).
    if (exists) {
      const twin = baselines.find((b) => b.status === res.status && Math.abs(res.body.length - b.len) <= Math.max(64, b.len * 0.15));
      if (twin) exists = false;
      else if (catchAll && !sig.sig && isHtmlResp(res)) exists = false;
      else if (isHtmlResp(res) && rootSegs.size) {
        // Shares the homepage's title "brand" → it's the app's own page (e.g. a
        // code-host serving /phpmyadmin as an org page), not a leaked artefact.
        const shares = titleSegs(pageTitle(res.body)).some((s) => rootSegs.has(s));
        if (shares) exists = false;
      }
    }
    out[sig.path] = {
      path: sig.path,
      status: res.status,
      contentType: res.headers["content-type"] ?? "",
      length: res.body.length,
      snippet: res.body.slice(0, 200).replace(/\s+/g, " "),
      exists,
    };
    probed += 1;
  }
  await emit({ type: "log", level: "info", message: `Hassas yol taraması: ${probed} yol denendi.` });
  return out;
}

// ---- Methods ----------------------------------------------------------------

async function collectMethods(target: string, budget: RequestBudget): Promise<{ methods: Record<string, number>; allow: string }> {
  const methods: Record<string, number> = {};
  let allow = "";
  const opt = await httpGet(target, { budget, method: "OPTIONS", redirect: "manual" });
  if (!opt.error) {
    methods.OPTIONS = opt.status;
    allow = opt.headers["allow"] ?? opt.headers["access-control-allow-methods"] ?? "";
  }
  return { methods, allow };
}

// ---- TLS protocol/cipher enumeration (DEEP) ---------------------------------

function tlsConnect(host: string, opts: tls.ConnectionOptions): Promise<{ ok: boolean; cipher?: string }> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r: { ok: boolean; cipher?: string }) => {
      if (done) return;
      done = true;
      resolve(r);
    };
    let socket: tls.TLSSocket;
    try {
      socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, ...opts }, () => {
        const c = socket.getCipher?.();
        socket.destroy();
        finish({ ok: true, cipher: c?.name });
      });
    } catch {
      finish({ ok: false });
      return;
    }
    socket.setTimeout(5000, () => {
      socket.destroy();
      finish({ ok: false });
    });
    socket.on("error", () => finish({ ok: false }));
  });
}

async function enumerateTls(host: string, normalCipher: string | undefined): Promise<TlsMatrix> {
  const versions: Array<"TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3"> = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
  const protocols = { "TLSv1": false, "TLSv1.1": false, "TLSv1.2": false, "TLSv1.3": false } as TlsMatrix["protocols"];
  for (const v of versions) {
    // Only a SUCCESSFUL handshake marks a version as enabled — a failure is
    // ambiguous (client may have it disabled), so we never false-positive.
    const r = await tlsConnect(host, {
      minVersion: v,
      maxVersion: v,
      ciphers: v === "TLSv1.3" ? undefined : "DEFAULT@SECLEVEL=0",
    }).catch(() => ({ ok: false }));
    protocols[v] = r.ok;
  }
  // Weak-cipher offering: try to negotiate a legacy cipher on TLS ≤1.2.
  let weakCiphersOffered: string[] = [];
  const weak = await tlsConnect(host, {
    minVersion: "TLSv1",
    maxVersion: "TLSv1.2",
    ciphers: "RC4-SHA:RC4-MD5:DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA@SECLEVEL=0",
  }).catch(() => ({ ok: false, cipher: undefined as string | undefined }));
  if (weak.ok && weak.cipher && /RC4|3DES|DES-CBC3|NULL|EXPORT/i.test(weak.cipher)) {
    weakCiphersOffered = [weak.cipher];
  }
  const forwardSecrecy = /ECDHE|DHE/i.test(normalCipher ?? "");
  return { tested: true, protocols, weakCiphersOffered, forwardSecrecy };
}

async function resolveCnames(host: string): Promise<string[]> {
  try {
    return await dns.resolveCname(host);
  } catch {
    return [];
  }
}

// GraphQL introspection probe (POST a minimal introspection query).
async function probeGraphql(origin: string, budget: RequestBudget): Promise<Evidence["graphql"]> {
  const endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];
  const query = JSON.stringify({ query: "{__schema{queryType{name}}}" });
  for (const ep of endpoints) {
    if (budget.expired()) break;
    const res = await httpGet(`${origin}${ep}`, {
      budget,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: query,
    });
    if (res.error || res.status >= 500) continue;
    // Parse JSON and require a genuine GraphQL envelope — a plain REST route that
    // merely contains the word "data"/"errors" must NOT be classified as GraphQL,
    // and introspection is "enabled" ONLY if data.__schema is a non-null object.
    let json: unknown;
    try {
      json = JSON.parse(res.body);
    } catch {
      continue;
    }
    if (!json || typeof json !== "object") continue;
    const obj = json as { data?: unknown; errors?: unknown };
    const dataObj = obj.data && typeof obj.data === "object" ? (obj.data as Record<string, unknown>) : null;
    const schema = dataObj ? dataObj.__schema : undefined;
    const introspectionEnabled = !!schema && typeof schema === "object";
    const gqlErrors =
      Array.isArray(obj.errors) &&
      (obj.errors as Array<Record<string, unknown>>).some(
        (e) => e && (e.locations || e.extensions || /Cannot query|must be|GraphQL|__schema|introspection|Syntax Error/i.test(String(e.message ?? ""))),
      );
    const graphqlShaped = introspectionEnabled || (dataObj !== null && "__schema" in dataObj) || gqlErrors;
    if (!graphqlShaped) continue;
    return { endpoint: `${origin}${ep}`, reachable: true, introspectionEnabled };
  }
  return null;
}

// robots.txt mining: probe Disallow'd paths; return the ones publicly reachable.
// Applies the same soft-404 / app-shell suppression as probePaths, so an SPA
// that returns its index for /admin isn't reported as an exposed hidden path.
async function mineRobots(origin: string, budget: RequestBudget, rootTitle: string): Promise<string[]> {
  const res = await httpGet(`${origin}/robots.txt`, { budget, redirect: "manual" });
  if (res.error || res.status !== 200 || !/disallow/i.test(res.body)) return [];
  const disallowed = [...res.body.matchAll(/^\s*Disallow:\s*(\S+)/gim)]
    .map((m) => m[1])
    .filter((p) => p && p !== "/" && !p.includes("*"))
    .slice(0, 20);
  const base = await httpGet(`${origin}/sentinel-nx-r0b0ts-4c1`, { budget, redirect: "manual" });
  const baseline = base.error ? null : { status: base.status, len: base.body.length };
  const catchAll = baseline?.status === 200;
  const rootSegs = new Set(titleSegs(rootTitle));
  const accessible: string[] = [];
  for (const p of disallowed) {
    if (budget.expired()) break;
    const r = await httpGet(`${origin}${p}`, { budget, redirect: "manual" });
    if (r.error || r.status !== 200 || r.body.length === 0) continue;
    if (baseline && r.status === baseline.status && Math.abs(r.body.length - baseline.len) <= Math.max(64, baseline.len * 0.15)) continue;
    if (isHtmlResp(r)) {
      if (catchAll) continue;
      if (titleSegs(pageTitle(r.body)).some((s) => rootSegs.has(s))) continue;
    }
    accessible.push(p);
  }
  return accessible;
}

// ---------------------------------------------------------------------------

export async function collectEvidence(
  target: string,
  host: string,
  profile: ScanProfile,
  budget: RequestBudget,
  emit: Emit,
): Promise<Evidence | null> {
  const origin = new URL(target).origin;
  const scheme = new URL(target).protocol.replace(":", "");

  await emit({ type: "log", level: "step", message: `Hedef alınıyor: ${target}` });
  const rootRes = await httpGet(target, { budget });
  if (rootRes.error) {
    await emit({ type: "log", level: "error", message: `Hedefe ulaşılamadı: ${rootRes.error}` });
    return null;
  }
  const root = toPage(rootRes);
  await emit({ type: "log", level: "tool", message: `kök yanıt ▸ ${root.status} ${root.url}` });

  // Crawl (skipped for PASSIVE).
  let pages: PageEvidence[] = [root];
  let scripts: string[] = [];
  let links: string[] = [];
  let forms: Evidence["forms"] = [];
  let apiEndpoints: string[] = [];
  if (profile !== "PASSIVE") {
    const maxPages = profile === "DEEP" ? 40 : 15;
    await emit({ type: "log", level: "step", message: `Site taranıyor (en fazla ${maxPages} sayfa)…` });
    const c = await crawl(target, budget, maxPages, emit);
    scripts = c.scripts;
    links = c.links;
    forms = c.forms;
    apiEndpoints = c.apiEndpoints;
    await emit({
      type: "log",
      level: "info",
      message: `Keşfedildi: ${c.pages.length} sayfa, ${c.links.length} bağlantı, ${c.forms.length} form, ${c.scripts.length} script, ${c.apiEndpoints.length} API ucu`,
    });
  } else {
    // Still extract scripts from the root for content/SRI/fingerprint checks.
    scripts = [...root.body.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)]
      .map((m) => {
        try {
          return new URL(m[1], root.url).toString();
        } catch {
          return "";
        }
      })
      .filter(Boolean);
  }
  const inlineScripts = [...root.body.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)]
    .map((m) => m[1])
    .filter((s) => s.trim().length > 0)
    .slice(0, 30);

  // TLS (https only).
  await emit({ type: "log", level: "step", message: "TLS/sertifika denetleniyor…" });
  let tlsEv: TlsEvidence = { reachable: false };
  try {
    await assertPublicHost(host);
    tlsEv = await deepTls(host);
  } catch {
    tlsEv = { reachable: false, error: "ssrf-blocked" };
  }

  // DNS + email.
  await emit({ type: "log", level: "step", message: "DNS / e-posta güvenliği denetleniyor…" });
  const dnsEv = await collectDns(host);

  // HTTP → HTTPS enforcement.
  const httpRes = await httpGet(`http://${host}/`, { budget, redirect: "manual" });
  const httpRoot = httpRes.error ? null : toPage(httpRes);
  const loc = httpRoot?.headers["location"] ?? "";
  const redirectsToHttps = !!httpRoot && httpRoot.status >= 300 && httpRoot.status < 400 && loc.startsWith("https://");

  // Methods.
  const { methods, allow } = await collectMethods(target, budget);

  // CORS: probe with a hostile Origin and see how the server responds.
  let cors: Evidence["cors"] = null;
  {
    const probeOrigin = "https://evil.sentinel-cors-test.example.com";
    const cres = await httpGet(target, { budget, headers: { Origin: probeOrigin } });
    if (!cres.error) {
      const acao = cres.headers["access-control-allow-origin"] ?? "";
      const acac = cres.headers["access-control-allow-credentials"] ?? "";
      cors = {
        probeOrigin,
        acao,
        acac,
        reflectsOrigin: acao === probeOrigin,
        wildcard: acao === "*",
        allowsNullOrigin: acao.toLowerCase() === "null",
        vary: cres.headers["vary"] ?? "",
      };
    }
  }

  // CNAME chain (subdomain-takeover analysis).
  const cnames = await resolveCnames(host);

  // TLS protocol/cipher enumeration (DEEP only — several extra handshakes).
  let tlsMatrix: TlsMatrix | null = null;
  if (profile === "DEEP" && tlsEv.reachable && !tlsEv.error) {
    await emit({ type: "log", level: "step", message: "TLS protokol/şifre matrisi çıkarılıyor…" });
    tlsMatrix = await enumerateTls(host, tlsEv.cipherName);
  }

  // GraphQL introspection + robots.txt mining (active discovery).
  let graphql: Evidence["graphql"] = null;
  let robotsDisallow: string[] = [];
  if (profile !== "PASSIVE") {
    graphql = await probeGraphql(origin, budget);
    robotsDisallow = await mineRobots(origin, budget, root.title);
    if (robotsDisallow.length) {
      await emit({ type: "log", level: "info", message: `robots.txt madenciliği: ${robotsDisallow.length} gizli ama erişilebilir yol.` });
    }
  }

  // Sensitive paths.
  await emit({ type: "log", level: "step", message: "Hassas dosya/dizinler aranıyor…" });
  const paths = await probePaths(origin, profile, budget, emit, root.title);

  const ev: Evidence = {
    target,
    host,
    origin,
    scheme,
    profile,
    root,
    pages,
    scripts,
    inlineScripts,
    links,
    forms,
    apiEndpoints,
    tls: tlsEv,
    tlsMatrix,
    dns: dnsEv,
    cnames,
    graphql,
    robotsDisallow,
    methods,
    allowHeader: allow,
    cors,
    httpRoot,
    redirectsToHttps,
    paths,
    probes: {},
    budget,
  };

  // Active injection probes (STANDARD/DEEP) — populate ev.probes.
  if (profile !== "PASSIVE") {
    await emit({ type: "log", level: "step", message: "Aktif enjeksiyon probları çalıştırılıyor…" });
    await runActiveProbes(ev, emit);
  }

  return ev;
}
