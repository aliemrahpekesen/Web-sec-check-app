// Deterministic scanning pipeline. Runs the full analyzer suite in a fixed,
// sensible order. This is the fallback engine when no Anthropic API key is
// configured — and the backbone the AI orchestrator reuses as tools.
import { httpGet, RequestBudget } from "./http";
import {
  analyzeSecurityHeaders,
  analyzeCookies,
  analyzeHttpsRedirect,
  analyzeTls,
  analyzeMixedContent,
  analyzeDirectoryListing,
  checkSensitivePaths,
  analyzeCors,
  probeReflectedXss,
  probeOpenRedirect,
  detectOutdatedLibraries,
} from "./analyzers";
import { crawl } from "./crawler";
import type { Emit, FindingDraft, ScanProfile } from "../types";

export interface EngineResult {
  findings: FindingDraft[];
  pagesCrawled: number;
  requestsMade: number;
}

function paramUrls(urls: string[]): string[] {
  return urls.filter((u) => {
    try {
      return [...new URL(u).searchParams.keys()].length > 0;
    } catch {
      return false;
    }
  });
}

export async function deterministicScan(
  target: string,
  host: string,
  profile: ScanProfile,
  emit: Emit,
): Promise<EngineResult> {
  const budget = new RequestBudget(profile === "DEEP" ? 400 : profile === "STANDARD" ? 200 : 40);
  const origin = new URL(target).origin;
  const findings: FindingDraft[] = [];
  const push = async (fs: FindingDraft[]) => {
    for (const f of fs) {
      findings.push(f);
      await emit({ type: "finding", finding: f });
    }
  };

  await emit({ type: "log", level: "step", message: `Hedef alınıyor: ${target}` });
  const root = await httpGet(target, { budget });
  if (root.error) {
    await emit({ type: "log", level: "error", message: `Hedefe ulaşılamadı: ${root.error}` });
    return { findings, pagesCrawled: 0, requestsMade: budget.count };
  }
  await emit({ type: "log", level: "tool", message: `kök yanıt ▸ ${root.status} ${root.finalUrl}` });

  await emit({ type: "log", level: "step", message: "Güvenlik başlıkları analiz ediliyor…" });
  await push(analyzeSecurityHeaders(root));
  await push(analyzeCookies(root));
  await push(analyzeMixedContent(root));
  await push(analyzeDirectoryListing(root));

  await emit({ type: "log", level: "step", message: "HTTPS zorlaması kontrol ediliyor…" });
  await push(await analyzeHttpsRedirect(host, budget));

  await emit({ type: "log", level: "step", message: "TLS/sertifika denetleniyor…" });
  await push(await analyzeTls(host));

  await emit({ type: "log", level: "step", message: "CORS politikası test ediliyor…" });
  await push(await analyzeCors(target, budget));

  let pagesCrawled = 1;
  let crawlLinks: string[] = [];
  let scripts: string[] = [];

  if (profile !== "PASSIVE") {
    const maxPages = profile === "DEEP" ? 40 : 15;
    await emit({ type: "log", level: "step", message: `Site taranıyor (en fazla ${maxPages} sayfa)…` });
    const c = await crawl(target, budget, maxPages, emit);
    pagesCrawled = c.pages.length;
    crawlLinks = c.links;
    scripts = c.scripts;
    await emit({
      type: "log",
      level: "info",
      message: `Keşfedildi: ${c.pages.length} sayfa, ${c.links.length} bağlantı, ${c.forms.length} form, ${c.scripts.length} script, ${c.apiEndpoints.length} API ucu`,
      meta: { apiEndpoints: c.apiEndpoints.slice(0, 25) },
    });

    await emit({ type: "log", level: "step", message: "Hassas dosya/dizinler aranıyor…" });
    await push(await checkSensitivePaths(origin, budget));

    await emit({ type: "log", level: "step", message: "Eski kütüphaneler taranıyor…" });
    await push(detectOutdatedLibraries(scripts));

    // Active injection probes on URLs that carry parameters + form fields.
    const targets = paramUrls([target, ...crawlLinks]).slice(0, profile === "DEEP" ? 20 : 8);
    if (targets.length) {
      await emit({ type: "log", level: "step", message: `Yansıyan XSS / açık yönlendirme test ediliyor (${targets.length} uç)…` });
      for (const t of targets) {
        const params = [...new URL(t).searchParams.keys()];
        await push(await probeReflectedXss(t, params, budget));
        await push(await probeOpenRedirect(t, budget));
      }
    }

    // Probe form GET actions too.
    for (const f of c.forms.filter((f) => f.method === "GET" && f.inputs.length).slice(0, 5)) {
      await push(await probeReflectedXss(f.action, f.inputs, budget));
    }
  }

  await emit({
    type: "log",
    level: "success",
    message: `Tarama tamamlandı. ${findings.length} bulgu, ${budget.count} istek, ${pagesCrawled} sayfa.`,
  });

  return { findings, pagesCrawled, requestsMade: budget.count };
}
