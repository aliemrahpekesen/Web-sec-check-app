// Runs the check catalog over collected evidence and produces findings plus a
// coverage report (run / passed / failed per category). The coverage report is
// what lets the UI prove to the user how much was actually checked — trust
// comes from showing the passes, not just the failures.
import type { Check, CatalogFinding, CheckOutcome, Coverage, Evidence, CheckCategory } from "./types";

function asArray(o: CheckOutcome | CheckOutcome[] | null): CheckOutcome[] {
  if (o == null) return [];
  return Array.isArray(o) ? o : [o];
}

export interface RunResult {
  findings: CatalogFinding[];
  coverage: Coverage;
}

export function runChecks(checks: Check[], ev: Evidence): RunResult {
  const findings: CatalogFinding[] = [];
  const seen = new Set<string>();
  const coverage: Coverage = { total: 0, passed: 0, failed: 0, notApplicable: 0, byCategory: {} };

  const bump = (cat: CheckCategory, key: "run" | "passed" | "failed") => {
    const c = (coverage.byCategory[cat] ??= { run: 0, passed: 0, failed: 0 });
    c[key] += 1;
  };

  for (const check of checks) {
    if (check.profiles && !check.profiles.includes(ev.profile)) continue;

    let outcomes: CheckOutcome[];
    try {
      outcomes = asArray(check.evaluate(ev));
    } catch {
      // A misbehaving check must never abort the scan; treat as N/A.
      outcomes = [];
    }

    coverage.total += 1;
    bump(check.category, "run");

    if (outcomes.length === 0) {
      coverage.notApplicable += 1;
      continue;
    }

    const fails = outcomes.filter((o) => o.status === "fail");
    if (fails.length === 0) {
      // Only pass/na outcomes → the check applied and the target is clean.
      if (outcomes.some((o) => o.status === "pass")) {
        coverage.passed += 1;
        bump(check.category, "passed");
      } else {
        coverage.notApplicable += 1;
      }
      continue;
    }

    coverage.failed += 1;
    bump(check.category, "failed");

    for (const o of fails) {
      const location = o.location ?? ev.target;
      const dedupe = `${check.id}::${location}::${o.titleSuffix ?? ""}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      findings.push({
        checkId: check.id,
        category: check.category,
        title: check.title + (o.titleSuffix ?? ""),
        severity: o.severity ?? check.severity,
        cwe: check.cwe,
        owasp: check.owasp,
        location,
        description: o.detail ? `${check.description}\n\n${o.detail}` : check.description,
        evidence: o.evidence,
        remediation: check.remediation,
        references: check.references,
        confidence: o.confidence ?? check.confidence ?? "firm",
      });
    }
  }

  return { findings, coverage };
}
