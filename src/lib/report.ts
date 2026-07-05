// Report serialization — turns a completed scan into a shareable JSON or
// Markdown document. Framework-neutral and pure so it can be used from the
// client (download button), a future server export endpoint, or tests.
import type { Severity } from "./types";

export interface ReportFinding {
  checkId: string;
  title: string;
  severity: Severity;
  category?: string | null;
  cwe?: string | null;
  owasp?: string | null;
  references?: string[] | null;
  location: string;
  description: string;
  evidence?: string | null;
  remediation: string;
  confidence?: string | null;
}

export interface ReportCoverage {
  total: number;
  passed: number;
  failed: number;
  notApplicable: number;
  byCategory: Record<string, { run: number; passed: number; failed: number }>;
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

export function buildJsonReport(meta: ReportMeta, findings: ReportFinding[], coverage?: ReportCoverage): string {
  return JSON.stringify(
    {
      tool: "SentinelScan",
      meta,
      summary: { total: findings.length, bySeverity: countBySeverity(findings), coverage: coverage ?? null },
      findings,
    },
    null,
    2,
  );
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const SEV_HTML: Record<Severity, string> = {
  CRITICAL: "#b91c1c",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#2563eb",
  INFO: "#6b7280",
};

// Self-contained, printable HTML report (shareable single file).
export function buildHtmlReport(meta: ReportMeta, findings: ReportFinding[], coverage?: ReportCoverage): string {
  const counts = countBySeverity(findings);
  const engineLabel = meta.engine === "ai" ? "Claude Opus 4.8 dinamik iş akışı" : "deterministik";
  const sorted = [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));

  const findingHtml = sorted
    .map(
      (f) => `
    <div class="finding" data-sev="${f.severity}" data-cat="${esc(f.category ?? "")}">
      <div class="fhead">
        <span class="badge" style="background:${SEV_HTML[f.severity]}">${f.severity}</span>
        <strong>${esc(f.title)}</strong>
      </div>
      <div class="meta">${[f.category, f.cwe, f.owasp, f.confidence ? `güven: ${f.confidence}` : ""].filter((x): x is string => !!x).map(esc).join(" · ")}</div>
      <div class="loc"><b>Konum:</b> ${esc(f.location)}</div>
      <p>${esc(f.description).replace(/\n/g, "<br>")}</p>
      ${f.evidence ? `<pre class="ev">${esc(f.evidence)}</pre>` : ""}
      <div class="rem"><b>Nasıl düzeltilir</b><pre>${esc(f.remediation)}</pre></div>
      ${f.references && f.references.length ? `<div class="refs">${f.references.map((r) => `<a href="${esc(r)}">${esc(r)}</a>`).join("<br>")}</div>` : ""}
    </div>`,
    )
    .join("");

  const covRows = coverage
    ? Object.entries(coverage.byCategory)
        .sort((a, b) => b[1].failed - a[1].failed)
        .map(([c, v]) => `<tr><td>${esc(c)}</td><td>${v.run}</td><td>${v.passed}</td><td>${v.failed}</td></tr>`)
        .join("")
    : "";

  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelScan Raporu — ${esc(meta.host)}</title>
<style>
:root{color-scheme:light}body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;color:#111}
.wrap{max-width:920px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#555;font-size:13px;margin-bottom:16px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:16px}
.grade{font-size:40px;font-weight:800;float:right}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #e5e7eb;padding:4px 8px;text-align:left}th{background:#f3f4f6}
.sevrow{display:flex;gap:8px;margin:12px 0}.sevrow div{flex:1;text-align:center;border:1px solid #e5e7eb;border-radius:8px;padding:8px}
.badge{color:#fff;font-weight:700;font-size:11px;padding:2px 8px;border-radius:6px;margin-right:8px}
.finding{background:#fff;border:1px solid #e5e7eb;border-left:4px solid #999;border-radius:8px;padding:12px 14px;margin-bottom:10px}
.fhead{font-size:15px}.meta{color:#666;font-size:12px;margin:4px 0}.loc{font-family:monospace;font-size:12px;color:#2563eb;word-break:break-all}
pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}
.rem pre{background:#f0fdf4;color:#14532d;border:1px solid #bbf7d0}.refs a{color:#2563eb;font-size:12px;word-break:break-all}
.foot{color:#888;font-size:11px;text-align:center;margin-top:24px}
</style></head><body><div class="wrap">
<div class="card">
  <div class="grade" style="color:${SEV_HTML[(meta.grade ?? "A").startsWith("A") || (meta.grade ?? "").startsWith("B") ? "INFO" : (meta.grade ?? "") >= "D" ? "CRITICAL" : "MEDIUM"]}">${esc(meta.grade ?? "—")}</div>
  <h1>SentinelScan Güvenlik Raporu</h1>
  <div class="sub">${esc(meta.target)} · ${esc(meta.profile)} · ${engineLabel} · risk ${meta.riskScore ?? 0}/100 · ${meta.pagesCrawled} sayfa · ${meta.requestsMade} istek · ${esc(meta.generatedAt)}</div>
  <div class="sevrow">${ORDER.map((s) => `<div><b style="color:${SEV_HTML[s]}">${counts[s]}</b><br>${s}</div>`).join("")}</div>
</div>
${coverage ? `<div class="card"><h3>Denetim Kapsamı — ${coverage.total} kontrol koştu, ${coverage.passed} geçti, ${coverage.failed} bulgu</h3><table><tr><th>Kategori</th><th>Koşan</th><th>Geçen</th><th>Bulgu</th></tr>${covRows}</table></div>` : ""}
<div class="card"><h3>Bulgular (${findings.length})</h3>${findings.length ? findingHtml : "<p>Bu profil için bulgu yok. ✓</p>"}</div>
<div class="foot">SentinelScan · Yalnızca yetkili güvenlik testleri için</div>
</div></body></html>`;
}

export function buildMarkdownReport(meta: ReportMeta, findings: ReportFinding[], coverage?: ReportCoverage): string {
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

  if (coverage) {
    lines.push(`## Denetim Kapsamı`);
    lines.push("");
    lines.push(`**${coverage.total}** kontrol koştu · **${coverage.passed}** geçti · **${coverage.failed}** bulgu üretti · ${coverage.notApplicable} uygulanamaz.`);
    lines.push("");
    lines.push(`| Kategori | Koşan | Geçen | Bulgu |`);
    lines.push(`| --- | ---: | ---: | ---: |`);
    for (const [cat, c] of Object.entries(coverage.byCategory).sort((a, b) => b[1].failed - a[1].failed)) {
      lines.push(`| ${cat} | ${c.run} | ${c.passed} | ${c.failed} |`);
    }
    lines.push("");
  }

  if (findings.length === 0) {
    lines.push(`Bu profil için bulgu yok. ✓`);
    return lines.join("\n");
  }

  lines.push(`## Bulgular`);
  const sorted = [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
  for (const f of sorted) {
    lines.push("");
    lines.push(`### [${f.severity}] ${f.title}`);
    const tags = [f.category, f.cwe, f.owasp, f.confidence ? `güven: ${f.confidence}` : null].filter(Boolean);
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
    if (f.references && f.references.length) {
      lines.push(`- **Referanslar:** ${f.references.map((r) => `<${r}>`).join(" · ")}`);
    }
  }
  return lines.join("\n");
}
