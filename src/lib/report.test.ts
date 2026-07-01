import { describe, it, expect } from "vitest";
import { buildJsonReport, buildMarkdownReport, countBySeverity, type ReportFinding, type ReportMeta } from "./report";

const meta: ReportMeta = {
  target: "https://ex.com/",
  host: "ex.com",
  profile: "STANDARD",
  engine: "deterministic",
  riskScore: 20,
  grade: "C",
  pagesCrawled: 3,
  requestsMade: 12,
  generatedAt: "2026-01-01T00:00:00.000Z",
};

const findings: ReportFinding[] = [
  { checkId: "missing-csp", title: "CSP eksik", severity: "MEDIUM", location: "https://ex.com/", description: "d", remediation: "r" },
  { checkId: "reflected-xss", title: "XSS", severity: "HIGH", location: "https://ex.com/?q=", description: "d2", evidence: "e", remediation: "r2", cwe: "CWE-79" },
];

describe("countBySeverity", () => {
  it("tallies per severity", () => {
    const c = countBySeverity(findings);
    expect(c.HIGH).toBe(1);
    expect(c.MEDIUM).toBe(1);
    expect(c.CRITICAL).toBe(0);
  });
});

describe("buildJsonReport", () => {
  it("produces valid JSON with summary", () => {
    const parsed = JSON.parse(buildJsonReport(meta, findings));
    expect(parsed.tool).toBe("SentinelScan");
    expect(parsed.summary.total).toBe(2);
    expect(parsed.findings).toHaveLength(2);
  });
});

describe("buildMarkdownReport", () => {
  it("orders findings by severity and includes remediation", () => {
    const md = buildMarkdownReport(meta, findings);
    expect(md).toContain("# SentinelScan");
    expect(md.indexOf("[HIGH]")).toBeLessThan(md.indexOf("[MEDIUM]"));
    expect(md).toContain("Nasıl düzeltilir");
  });

  it("handles a clean scan", () => {
    expect(buildMarkdownReport(meta, [])).toContain("bulgu yok");
  });
});
