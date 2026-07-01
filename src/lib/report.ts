// Report serialization — turns a completed scan into a shareable JSON or
// Markdown document. Framework-neutral and pure so it can be used from the
// client (download button), a future server export endpoint, or tests.
import type { Severity } from "./types";

export interface ReportFinding {
  checkId: string;
  title: string;
  severity: Severity;
  cwe?: string | null;
  owasp?: string | null;
  location: string;
  description: string;
  evidence?: string | null;
  remediation: string;
  confidence?: string | null;
}

export interface ReportMeta {
  target: string;
  host: string;
  profile: string;
  engine: string;
  riskScore: number | null;
  grade: string | null;
  pagesCrawled: number;
  requestsMade: number;
  generatedAt: string;
}

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function countBySeverity(findings: ReportFinding[]): Record<Severity, number> {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as Record<Severity, number>;
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

export function buildJsonReport(meta: ReportMeta, findings: ReportFinding[]): string {
  return JSON.stringify(
    {
      tool: "SentinelScan",
      meta,
      summary: { total: findings.length, bySeverity: countBySeverity(findings) },
      findings,
    },
    null,
    2,
  );
}

export function buildMarkdownReport(meta: ReportMeta, findings: ReportFinding[]): string {
  const counts = countBySeverity(findings);
  const engineLabel = meta.engine === "ai" ? "Claude Opus 4.8 dinamik iş akışı" : "deterministik";
  const lines: string[] = [];

  lines.push(`# SentinelScan Güvenlik Raporu`);
  lines.push("");
  lines.push(`- **Hedef:** ${meta.target}`);
  lines.push(`- **Profil:** ${meta.profile}`);
  lines.push(`- **Motor:** ${engineLabel}`);
  lines.push(`- **Risk skoru:** ${meta.riskScore ?? "—"}/100 (Not: ${meta.grade ?? "—"})`);
  lines.push(`- **Kapsam:** ${meta.pagesCrawled} sayfa · ${meta.requestsMade} istek`);
  lines.push(`- **Üretildi:** ${meta.generatedAt}`);
  lines.push("");
  lines.push(`## Özet`);
  lines.push("");
  lines.push(`| Kritiklik | Adet |`);
  lines.push(`| --- | ---: |`);
  for (const sev of ORDER) lines.push(`| ${sev} | ${counts[sev]} |`);
  lines.push(`| **Toplam** | **${findings.length}** |`);
  lines.push("");

  if (findings.length === 0) {
    lines.push(`Bu profil için bulgu yok. ✓`);
    return lines.join("\n");
  }

  lines.push(`## Bulgular`);
  const sorted = [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
  for (const f of sorted) {
    lines.push("");
    lines.push(`### [${f.severity}] ${f.title}`);
    const tags = [f.cwe, f.owasp, f.confidence ? `güven: ${f.confidence}` : null].filter(Boolean);
    if (tags.length) lines.push(`*${tags.join(" · ")}*`);
    lines.push("");
    lines.push(`- **Konum:** ${f.location}`);
    if (f.description) {
      lines.push(`- **Açıklama:** ${f.description.replace(/\n/g, " ")}`);
    }
    if (f.evidence) {
      lines.push(`- **Kanıt:**`);
      lines.push("");
      lines.push("```");
      lines.push(f.evidence);
      lines.push("```");
    }
    lines.push(`- **Nasıl düzeltilir:**`);
    lines.push("");
    lines.push("```");
    lines.push(f.remediation);
    lines.push("```");
  }
  return lines.join("\n");
}
