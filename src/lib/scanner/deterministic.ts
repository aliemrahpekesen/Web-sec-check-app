// Deterministic scanning engine, now catalog-driven: collect evidence once,
// then run the full check catalog (400+ checks) over it. Produces findings AND
// a coverage report (checks run / passed / failed per category) so the UI can
// prove how much was actually verified. This is the fallback engine when no
// Anthropic key is set — and the shared backbone the AI orchestrator builds on.
import { RequestBudget } from "./http";
import { env } from "../env";
import { collectEvidence } from "./checks/evidence";
import { runChecks } from "./checks/engine";
import { checksForProfile } from "./checks/registry";
import { CATEGORY_LABELS } from "./checks/types";
import type { Coverage } from "./checks/types";
import type { Emit, FindingDraft, ScanProfile } from "../types";

export interface EngineResult {
  findings: FindingDraft[];
  pagesCrawled: number;
  requestsMade: number;
  coverage?: Coverage;
}

export async function deterministicScan(
  target: string,
  host: string,
  profile: ScanProfile,
  emit: Emit,
): Promise<EngineResult> {
  const ttl = env.serverless ? 55_000 : profile === "DEEP" ? 300_000 : 150_000;
  const maxReq = profile === "DEEP" ? 800 : profile === "STANDARD" ? 400 : 60;
  const budget = new RequestBudget(maxReq, ttl);

  const ev = await collectEvidence(target, host, profile, budget, emit);
  if (!ev) return { findings: [], pagesCrawled: 0, requestsMade: budget.count };

  const checks = checksForProfile(profile);
  await emit({ type: "log", level: "step", message: `${checks.length} güvenlik kontrolü değerlendiriliyor…` });

  const { findings: catFindings, coverage } = runChecks(checks, ev);

  const findings: FindingDraft[] = [];
  for (const f of catFindings) {
    const draft: FindingDraft = {
      checkId: f.checkId,
      title: f.title,
      severity: f.severity,
      cwe: f.cwe,
      owasp: f.owasp,
      location: f.location,
      description: f.description,
      evidence: f.evidence,
      remediation: f.remediation,
      confidence: f.confidence,
      category: f.category,
      references: f.references,
    };
    findings.push(draft);
    await emit({ type: "finding", finding: draft });
  }

  // Per-category coverage line, so the live log shows verified-good coverage.
  const parts = Object.entries(coverage.byCategory)
    .map(([cat, c]) => `${CATEGORY_LABELS[cat as keyof typeof CATEGORY_LABELS] ?? cat}: ${c.failed}/${c.run}`)
    .join(" · ");
  await emit({ type: "log", level: "info", message: `Kapsam — ${parts}` });
  await emit({
    type: "log",
    level: "success",
    message: `Tarama tamamlandı. ${coverage.total} kontrol koştu, ${coverage.passed} geçti, ${findings.length} bulgu, ${budget.count} istek.`,
  });

  return { findings, pagesCrawled: ev.pages.length, requestsMade: budget.count, coverage };
}
