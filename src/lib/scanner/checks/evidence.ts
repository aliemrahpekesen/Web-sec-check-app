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
import type { Evidence, PageEvidence, TlsEvidence, DnsEvidence, ProbeEvidence } from "./types";

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
        cipherBits: (cipher as { bits?: number })?.bits,
        validFrom: cert?.valid_from,
        validTo: cert?.valid_to,
        daysToExpiry,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
        issuer: issuerCN,
        subjectCN,
        altNames: san ? san.split(/,\s*/).map((s) => s.replace(/^DNS:/, "")) : undefined,
        keyBits: (cert as { bits?: number })?.bits,
        sigAlg: (cert as { sigalg?: string })?.sigalg,
        selfSigned,
        san,
      });
      socket.end();
    });
    socket.setTimeout(8000, () => {
      socket.destroy();
      finish({ reachable: false, a: [], error: "timeout" } as unknown as TlsEvidence);
    });
    socket.on("error", (e) => finish({ reachable: false, error: e.message } as TlsEvidence));
  });
}

// ---- DNS + email security ---------------------------------------------------

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
  const txts = await safe(dns.resolveTxt(host), []);
  out.txt = txts.map((chunks) => chunks.join(""));
  out.caa = (await safe(dns.resolveCaa(host), [])).map((c) => JSON.stringify(c));
  out.spf = out.txt.find((t) => /^v=spf1/i.test(t));
  const dmarcTxt = await safe(dns.resolveTxt(`_dmarc.${host}`), []);
  out.dmarc = dmarcTxt.map((c) => c.join("")).find((t) => /^v=DMARC1/i.test(t));
  out.dmarcPolicy = out.dmarc ? /p=(\w+)/i.exec(out.dmarc)?.[1]?.toLowerCase() : undefined;
  const mtaSts = await safe(dns.resolveTxt(`_mta-sts.${host}`), []);
  out.mtaSts = mtaSts.some((c) => /v=STSv1/i.test(c.join("")));
  out.resolved = out.a.length > 0 || out.aaaa.length > 0 || out.mx.length > 0;
  return out;
}

// ---- Sensitive-path probing (bounded by profile + budget) -------------------

function looksReal(path: string, res: HttpResult): boolean {
  if (res.status !== 200 || !res.body) return false;
  const body = res.body;
  // Guard against SPA/catch-all 200s that return index.html for everything.
  const isHtml = /<!doctype html>|<html[\s>]/i.test(body);
  if (path.endsWith(".json")) return /^[\s]*[[{]/.test(body);
  if (path === "/.env" || /\.env/.test(path)) return /^[A-Z0-9_]+\s*=/m.test(body) && !isHtml;
  if (path.includes(".git")) return /(ref:|\[core\]|^P )/m.test(body) && !isHtml;
  if (/\.(sql|bak|old|zip|tar|gz)$/i.test(path)) return !isHtml;
  if (/\.(xml|yml|yaml|ini|conf|config)$/i.test(path)) return !isHtml || /<\?xml/i.test(body);
  return true;
}

async function probePaths(
  origin: string,
  profile: ScanProfile,
  budget: RequestBudget,
  emit: Emit,
): Promise<Record<string, ProbeEvidence>> {
  const out: Record<string, ProbeEvidence> = {};
  if (profile === "PASSIVE") return out;
  const maxTier = profile === "DEEP" ? 2 : 1;
  const list = SENSITIVE_PATHS.filter((p) => p.tier <= maxTier);
  let probed = 0;
  for (const sig of list) {
    if (budget.expired()) break;
    const res = await httpGet(`${origin}${sig.path}`, { budget, redirect: "manual" });
    if (res.error) continue;
    const exists = looksReal(sig.path, res) && (!sig.sig || sig.sig.test(res.body));
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

  // Sensitive paths.
  await emit({ type: "log", level: "step", message: "Hassas dosya/dizinler aranıyor…" });
  const paths = await probePaths(origin, profile, budget, emit);

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
    dns: dnsEv,
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
