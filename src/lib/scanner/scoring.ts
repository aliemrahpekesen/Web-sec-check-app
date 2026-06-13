// Risk scoring. Turns a set of findings into a 0-100 risk score and an A–F
// grade for the report header.
import type { FindingDraft, Severity } from "../types";

const WEIGHT: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 20,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

export function scoreFindings(findings: FindingDraft[]): { riskScore: number; grade: string } {
  const raw = findings.reduce((acc, f) => acc + (WEIGHT[f.severity] ?? 0), 0);
  // Cap and invert: 0 findings → 0 risk; lots of severe findings → ~100.
  const riskScore = Math.min(100, raw);
  const grade =
    riskScore === 0
      ? "A"
      : riskScore < 10
        ? "B"
        : riskScore < 25
          ? "C"
          : riskScore < 45
            ? "D"
            : riskScore < 70
              ? "E"
              : "F";
  return { riskScore, grade };
}

export function severityRank(s: Severity): number {
  return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[s];
}
