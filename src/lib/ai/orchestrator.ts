// The Claude Opus 4.8 *dynamic workflow* orchestrator.
//
// Instead of a fixed pipeline, Claude drives the scan: it inspects what the
// target exposes and adaptively decides which security tools to run next
// (crawl → discover APIs/forms → probe the interesting ones → reason about
// novel issues). We run a *manual* agentic tool-use loop (not the auto tool
// runner) so every tool call can be streamed to the Matrix log and every
// finding is recorded with full control. Findings produced by the analyzer
// tools are canonical; Claude may add reasoned findings via `report_finding`.
import Anthropic from "@anthropic-ai/sdk";
import { env } from "../env";
import { RequestBudget, httpGet } from "../scanner/http";
import { crawl } from "../scanner/crawler";
import {
  analyzeSecurityHeaders,
  analyzeCookies,
  analyzeMixedContent,
  analyzeDirectoryListing,
  analyzeSri,
  analyzeCacheControl,
  analyzeHttpsRedirect,
  analyzeTls,
  analyzeCors,
  checkSensitivePaths,
  probeReflectedXss,
  probeOpenRedirect,
  detectOutdatedLibraries,
} from "../scanner/analyzers";
import { kbEntry } from "../scanner/knowledge";
import type { EngineResult } from "../scanner/deterministic";
import type { Emit, FindingDraft, ScanProfile, Severity } from "../types";

const SYSTEM = `Sen SentinelScan'in kıdemli sızma test uzmanı (offensive security) ajanısın.
Yetkili bir güvenlik denetimi yürütüyorsun: kullanıcı hedef alan adının sahipliğini doğruladı.

GÖREVİN: Verilen web uygulamasını uçtan uca, dinamik olarak denetlemek. Sabit bir sıra izleme —
hedefte ne gördüğüne göre bir sonraki adımı SEN seç. İyi bir akış şöyledir:
  1) crawl_site ile alt sayfaları, formları, scriptleri ve arka uç API çağrılarını keşfet.
  2) analyze_headers, analyze_tls, check_https_redirect, check_cors ile yapılandırmayı incele.
  3) scan_sensitive_paths ile sızdırılmış dosyaları (.env, .git ...) ara.
  4) Parametre taşıyan ilginç uçlarda probe_xss ve probe_open_redirect çalıştır.
  5) fetch_url ile şüpheli yanıtları incele; araçların yakalamadığı özgün bir sorun görürsen
     report_finding ile bildir (ama araçların zaten döndürdüğü bulguyu TEKRAR bildirme).

Araçların döndürdüğü 'recorded findings' otomatik olarak rapora işlenir. Kapsamlı ol ama
istek bütçesine saygı göster. İş bittiğinde tek paragraflık kısa bir özet yaz ve dur.`;

const TOOLS: Anthropic.Tool[] = [
  {
    name: "crawl_site",
    description:
      "Aynı origin içinde gezinerek sayfaları, bağlantıları, formları, script kaynaklarını ve inline JS'teki arka uç API uçlarını keşfeder.",
    input_schema: {
      type: "object",
      properties: { maxPages: { type: "integer", description: "Taranacak azami sayfa (1-40)" } },
    },
  },
  {
    name: "fetch_url",
    description: "Tek bir URL'yi getirir; durum kodu, başlıklar ve gövde parçacığını döndürür.",
    input_schema: {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"],
    },
  },
  {
    name: "analyze_headers",
    description:
      "Bir URL'nin güvenlik başlıklarını, çerez bayraklarını, karışık içeriği ve dizin listelemeyi denetler. Bulguları kaydeder.",
    input_schema: {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"],
    },
  },
  {
    name: "analyze_tls",
    description: "Hedef hostun TLS protokolünü ve sertifika geçerliliğini denetler. Bulguları kaydeder.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "check_https_redirect",
    description: "Düz HTTP'nin HTTPS'e yönlendirilip yönlendirilmediğini kontrol eder. Bulguları kaydeder.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "check_cors",
    description: "Bir URL'de tehlikeli CORS yapılandırmasını (origin yansıtma + credentials) test eder.",
    input_schema: {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"],
    },
  },
  {
    name: "scan_sensitive_paths",
    description: "Yaygın hassas dosya/dizinlerin (.env, .git, yedekler) erişilebilirliğini test eder.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "scan_libraries",
    description: "Verilen script URL'lerinde bilinen savunmasız/eski istemci kütüphanelerini arar.",
    input_schema: {
      type: "object",
      properties: { scripts: { type: "array", items: { type: "string" } } },
      required: ["scripts"],
    },
  },
  {
    name: "probe_xss",
    description: "Bir URL'deki belirtilen parametrelerde zararsız bir payload ile yansıyan XSS test eder.",
    input_schema: {
      type: "object",
      properties: {
        url: { type: "string" },
        params: { type: "array", items: { type: "string" } },
      },
      required: ["url", "params"],
    },
  },
  {
    name: "probe_open_redirect",
    description: "Bir URL'de açık yönlendirme (open redirect) test eder.",
    input_schema: {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"],
    },
  },
  {
    name: "report_finding",
    description:
      "Araçların yakalamadığı, akıl yürüterek tespit ettiğin ÖZGÜN bir güvenlik bulgusunu rapora ekler.",
    input_schema: {
      type: "object",
      properties: {
        title: { type: "string" },
        severity: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] },
        location: { type: "string" },
        description: { type: "string" },
        evidence: { type: "string" },
        remediation: { type: "string", description: "Nasıl düzeltileceği, örnekle" },
        cwe: { type: "string" },
        owasp: { type: "string" },
      },
      required: ["title", "severity", "location", "description", "remediation"],
    },
  },
];

export async function aiOrchestratedScan(
  target: string,
  host: string,
  profile: ScanProfile,
  emit: Emit,
): Promise<EngineResult> {
  const client = new Anthropic({ apiKey: env.anthropicApiKey });
  const ttl = env.serverless ? 55_000 : profile === "DEEP" ? 240_000 : 120_000;
  const budget = new RequestBudget(profile === "DEEP" ? 400 : profile === "STANDARD" ? 220 : 50, ttl);
  const origin = new URL(target).origin;
  const findings: FindingDraft[] = [];
  let pagesCrawled = 1;

  const record = async (fs: FindingDraft[]): Promise<FindingDraft[]> => {
    const added: FindingDraft[] = [];
    for (const f of fs) {
      const dup = findings.some((x) => x.checkId === f.checkId && x.location === f.location);
      if (dup) continue;
      findings.push(f);
      added.push(f);
      await emit({ type: "finding", finding: f });
    }
    return added;
  };

  async function runTool(name: string, input: Record<string, unknown>): Promise<string> {
    await emit({ type: "log", level: "tool", message: `claude ▸ ${name}(${shortArgs(input)})` });
    switch (name) {
      case "crawl_site": {
        const maxPages = clamp(Number(input.maxPages) || (profile === "DEEP" ? 40 : 15), 1, 40);
        const c = await crawl(target, budget, maxPages, emit);
        pagesCrawled = Math.max(pagesCrawled, c.pages.length);
        return JSON.stringify({
          pages: c.pages.length,
          forms: c.forms.map((f) => ({ action: f.action, method: f.method, inputs: f.inputs })).slice(0, 30),
          scripts: c.scripts.slice(0, 40),
          apiEndpoints: c.apiEndpoints.slice(0, 40),
          parameterizedLinks: c.links.filter((l) => l.includes("?")).slice(0, 40),
        });
      }
      case "fetch_url": {
        const res = await httpGet(String(input.url), { budget });
        return JSON.stringify({
          status: res.status,
          finalUrl: res.finalUrl,
          headers: res.headers,
          bodySnippet: res.body.slice(0, 1500),
          error: res.error,
        });
      }
      case "analyze_headers": {
        const res = await httpGet(String(input.url), { budget });
        if (res.error) return JSON.stringify({ error: res.error });
        const fs = [
          ...analyzeSecurityHeaders(res),
          ...analyzeCookies(res),
          ...analyzeMixedContent(res),
          ...analyzeDirectoryListing(res),
          ...analyzeSri(res),
          ...analyzeCacheControl(res),
        ];
        const added = await record(fs);
        return JSON.stringify({ recordedFindings: added.map(slim), headers: res.headers });
      }
      case "analyze_tls": {
        const added = await record(await analyzeTls(host));
        return JSON.stringify({ recordedFindings: added.map(slim), note: added.length ? undefined : "TLS sağlıklı görünüyor" });
      }
      case "check_https_redirect": {
        const added = await record(await analyzeHttpsRedirect(host, budget));
        return JSON.stringify({ recordedFindings: added.map(slim) });
      }
      case "check_cors": {
        const added = await record(await analyzeCors(String(input.url), budget));
        return JSON.stringify({ recordedFindings: added.map(slim) });
      }
      case "scan_sensitive_paths": {
        const added = await record(await checkSensitivePaths(origin, budget));
        return JSON.stringify({ recordedFindings: added.map(slim) });
      }
      case "scan_libraries": {
        const scripts = Array.isArray(input.scripts) ? (input.scripts as string[]) : [];
        const added = await record(detectOutdatedLibraries(scripts));
        return JSON.stringify({ recordedFindings: added.map(slim) });
      }
      case "probe_xss": {
        const params = Array.isArray(input.params) ? (input.params as string[]) : [];
        const added = await record(await probeReflectedXss(String(input.url), params, budget));
        return JSON.stringify({ recordedFindings: added.map(slim) });
      }
      case "probe_open_redirect": {
        const added = await record(await probeOpenRedirect(String(input.url), budget));
        return JSON.stringify({ recordedFindings: added.map(slim) });
      }
      case "report_finding": {
        const f = normalizeReported(input);
        const added = await record([f]);
        return JSON.stringify({ ok: true, recorded: added.length > 0 });
      }
      default:
        return JSON.stringify({ error: `unknown tool ${name}` });
    }
  }

  // ---- Manual agentic loop --------------------------------------------------
  const messages: Anthropic.MessageParam[] = [
    {
      role: "user",
      content: `Hedef: ${target} (host: ${host}). Tarama profili: ${profile}. İstek bütçesi: ${budget.max}. Denetimi başlat.`,
    },
  ];

  const maxIterations = profile === "DEEP" ? 30 : 20;
  for (let i = 0; i < maxIterations; i++) {
    if (budget.count >= budget.max || budget.expired()) {
      await emit({ type: "log", level: "warn", message: "İstek/zaman bütçesi doldu; tarama sonlandırılıyor." });
      break;
    }

    let response: Anthropic.Message;
    try {
      response = await client.messages.create({
        model: env.model,
        max_tokens: 8000,
        thinking: { type: "adaptive" },
        system: SYSTEM,
        tools: TOOLS,
        messages,
      });
    } catch (e) {
      await emit({
        type: "log",
        level: "error",
        message: `AI orkestratör hatası: ${e instanceof Error ? e.message : String(e)}. Deterministik motora geçiliyor.`,
      });
      throw e; // caller falls back to deterministic
    }

    // Surface any assistant prose to the live log.
    const text = response.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join(" ")
      .trim();
    if (text) await emit({ type: "log", level: "info", message: `claude » ${text.slice(0, 400)}` });

    if (response.stop_reason === "refusal") {
      await emit({ type: "log", level: "warn", message: "Model isteği reddetti; deterministik motora geçiliyor." });
      throw new Error("refusal");
    }

    const toolUses = response.content.filter((b): b is Anthropic.ToolUseBlock => b.type === "tool_use");
    if (response.stop_reason !== "tool_use" || toolUses.length === 0) {
      // Claude is done.
      break;
    }

    messages.push({ role: "assistant", content: response.content });
    const toolResults: Anthropic.ToolResultBlockParam[] = [];
    for (const tu of toolUses) {
      const result = await runTool(tu.name, (tu.input ?? {}) as Record<string, unknown>);
      toolResults.push({ type: "tool_result", tool_use_id: tu.id, content: result });
    }
    messages.push({ role: "user", content: toolResults });
  }

  await emit({
    type: "log",
    level: "success",
    message: `Dinamik iş akışı tamamlandı. ${findings.length} bulgu, ${budget.count} istek, ${pagesCrawled} sayfa.`,
  });

  return { findings, pagesCrawled, requestsMade: budget.count };
}

// ---- helpers ----------------------------------------------------------------

function slim(f: FindingDraft) {
  return { checkId: f.checkId, title: f.title, severity: f.severity, location: f.location };
}

function shortArgs(input: Record<string, unknown>): string {
  const s = JSON.stringify(input);
  return s.length > 80 ? s.slice(0, 77) + "…" : s.replace(/^\{|\}$/g, "");
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

function normalizeReported(input: Record<string, unknown>): FindingDraft {
  const sev = String(input.severity ?? "INFO").toUpperCase() as Severity;
  const checkId = `ai-${String(input.title ?? "finding")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .slice(0, 40)}`;
  const kb = kbEntry(checkId);
  return {
    checkId,
    title: String(input.title ?? "AI bulgusu"),
    severity: (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]).includes(sev) ? sev : "INFO",
    cwe: input.cwe ? String(input.cwe) : kb?.cwe,
    owasp: input.owasp ? String(input.owasp) : kb?.owasp,
    location: String(input.location ?? ""),
    description: String(input.description ?? ""),
    evidence: input.evidence ? String(input.evidence) : undefined,
    remediation: String(input.remediation ?? kb?.remediation ?? ""),
    confidence: "tentative",
  };
}
