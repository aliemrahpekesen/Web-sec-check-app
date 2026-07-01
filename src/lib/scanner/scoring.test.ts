import { describe, it, expect } from "vitest";
import { scoreFindings, severityRank } from "./scoring";
import type { FindingDraft } from "../types";

function f(severity: FindingDraft["severity"]): FindingDraft {
  return { checkId: "x", title: "x", severity, location: "l", description: "", remediation: "" };
}

describe("scoreFindings", () => {
  it("clean scan scores 0 / grade A", () => {
    expect(scoreFindings([])).toEqual({ riskScore: 0, grade: "A" });
  });

  it("weights by severity and caps at 100", () => {
    expect(scoreFindings([f("CRITICAL")]).riskScore).toBe(40);
    expect(scoreFindings([f("LOW")]).grade).toBe("B");
    const many = scoreFindings(Array.from({ length: 5 }, () => f("CRITICAL")));
    expect(many.riskScore).toBe(100);
    expect(many.grade).toBe("F");
  });

  it("INFO findings do not affect the score", () => {
    expect(scoreFindings([f("INFO"), f("INFO")])).toEqual({ riskScore: 0, grade: "A" });
  });
});

describe("severityRank", () => {
  it("orders most severe first", () => {
    expect(severityRank("CRITICAL")).toBeLessThan(severityRank("HIGH"));
    expect(severityRank("HIGH")).toBeLessThan(severityRank("LOW"));
    expect(severityRank("LOW")).toBeLessThan(severityRank("INFO"));
  });
});
