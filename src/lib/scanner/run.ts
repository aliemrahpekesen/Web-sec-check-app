// Scan entrypoint used by the worker. Picks the engine (Claude Opus 4.8
// dynamic workflow when an API key is present, deterministic otherwise),
// finalizes scoring, and updates the scan record. The AI path falls back to
// deterministic on any orchestrator error so a scan never dies on an API hiccup.
import { prisma } from "../db";
import { aiEnabled } from "../env";
import { createEmitter } from "../events";
import { deterministicScan, type EngineResult } from "./deterministic";
import { aiOrchestratedScan } from "../ai/orchestrator";
import { scoreFindings } from "./scoring";
import type { ScanJobData } from "../queue";
import type { Emit, ScanProfile } from "../types";

export async function runScan(job: ScanJobData): Promise<void> {
  const { scanId, target, host, profile } = job;
  const { emit } = createEmitter(scanId);

  await prisma.scan.update({
    where: { id: scanId },
    data: { status: "RUNNING", startedAt: new Date() },
  });
  await emit({ type: "status", status: "RUNNING", message: "Tarama başlatıldı" });

  let engine = aiEnabled() ? "ai" : "deterministic";
  await emit({
    type: "log",
    level: "step",
    message:
      engine === "ai"
        ? "Motor: Claude Opus 4.8 dinamik iş akışı (AI orkestratör)"
        : "Motor: deterministik tarama (ANTHROPIC_API_KEY ayarlı değil)",
  });

  try {
    let result: EngineResult;
    if (engine === "ai") {
      try {
        result = await aiOrchestratedScan(target, host, profile, emit);
      } catch {
        engine = "deterministic";
        await emit({ type: "log", level: "warn", message: "AI motoru başarısız; deterministik motora geçildi." });
        result = await deterministicScan(target, host, profile, emit);
      }
    } else {
      result = await deterministicScan(target, host, profile, emit);
    }

    const { riskScore, grade } = scoreFindings(result.findings);
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: "COMPLETED",
        engine,
        riskScore,
        grade,
        pagesCrawled: result.pagesCrawled,
        requestsMade: result.requestsMade,
        completedAt: new Date(),
      },
    });
    await emit({
      type: "done",
      status: "COMPLETED",
      riskScore,
      grade,
      message: `Rapor hazır — risk skoru ${riskScore}/100, not ${grade}.`,
      meta: {
        engine,
        pagesCrawled: result.pagesCrawled,
        requestsMade: result.requestsMade,
        coverage: result.coverage,
      },
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "FAILED", error: message, completedAt: new Date() },
    });
    await emit({ type: "done", status: "FAILED", message: `Tarama başarısız: ${message}` });
  }
}

// Stateless run (DB-less serverless demo): runs the engine and streams logs +
// findings + a final summary directly to the SSE writer. Nothing is persisted.
export async function runScanStateless(
  target: string,
  host: string,
  profile: ScanProfile,
  emit: Emit,
): Promise<void> {
  await emit({ type: "status", status: "RUNNING", message: "Tarama başlatıldı (stateless)" });
  let engine = aiEnabled() ? "ai" : "deterministic";
  await emit({
    type: "log",
    level: "step",
    message:
      engine === "ai"
        ? "Motor: Claude Opus 4.8 dinamik iş akışı (AI orkestratör)"
        : "Motor: deterministik tarama",
  });

  try {
    let result: EngineResult;
    if (engine === "ai") {
      try {
        result = await aiOrchestratedScan(target, host, profile, emit);
      } catch {
        engine = "deterministic";
        await emit({ type: "log", level: "warn", message: "AI motoru başarısız; deterministik motora geçildi." });
        result = await deterministicScan(target, host, profile, emit);
      }
    } else {
      result = await deterministicScan(target, host, profile, emit);
    }
    const { riskScore, grade } = scoreFindings(result.findings);
    await emit({
      type: "done",
      status: "COMPLETED",
      riskScore,
      grade,
      message: `Rapor hazır — risk skoru ${riskScore}/100, not ${grade}.`,
      meta: { engine, pagesCrawled: result.pagesCrawled, requestsMade: result.requestsMade, coverage: result.coverage },
    });
  } catch (e) {
    await emit({
      type: "done",
      status: "FAILED",
      message: `Tarama başarısız: ${e instanceof Error ? e.message : String(e)}`,
    });
  }
}
