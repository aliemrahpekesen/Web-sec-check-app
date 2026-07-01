"use client";

import { useState } from "react";
import { SeverityBadge } from "./SeverityBadge";
import type { Severity } from "@/lib/types";
import { buildJsonReport, buildMarkdownReport, type ReportMeta } from "@/lib/report";

export interface FindingRow {
  id: string;
  checkId: string;
  title: string;
  severity: Severity;
  cwe: string | null;
  owasp: string | null;
  location: string;
  description: string;
  evidence: string | null;
  remediation: string;
  confidence: string;
}

export interface FullScan {
  id: string;
  target: string;
  host: string;
  profile: string;
  status: string;
  engine: string;
  riskScore: number | null;
  grade: string | null;
  pagesCrawled: number;
  requestsMade: number;
  error: string | null;
  findings: FindingRow[];
}

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const GRADE_COLOR: Record<string, string> = {
  A: "text-matrix",
  B: "text-matrix",
  C: "text-sev-medium",
  D: "text-sev-high",
  E: "text-sev-high",
  F: "text-sev-critical",
};

export function Report({
  scan,
  counts,
  running,
}: {
  scan: FullScan | null;
  counts: Record<string, number>;
  running: boolean;
}) {
  if (!scan) {
    return (
      <div className="glass flex h-[70vh] items-center justify-center rounded-xl">
        <span className="animate-flicker font-mono text-matrix-dim">rapor yükleniyor…</span>
      </div>
    );
  }

  const total = scan.findings.length;

  function download(kind: "json" | "md") {
    const meta: ReportMeta = {
      target: scan!.target,
      host: scan!.host,
      profile: scan!.profile,
      engine: scan!.engine,
      riskScore: scan!.riskScore,
      grade: scan!.grade,
      pagesCrawled: scan!.pagesCrawled,
      requestsMade: scan!.requestsMade,
      generatedAt: new Date().toISOString(),
    };
    const content =
      kind === "json" ? buildJsonReport(meta, scan!.findings) : buildMarkdownReport(meta, scan!.findings);
    const blob = new Blob([content], { type: kind === "json" ? "application/json" : "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelscan-${scan!.host}-${Date.now()}.${kind === "json" ? "json" : "md"}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Header / score */}
      <div className="glass rounded-xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="truncate font-mono text-sm text-matrix">{scan.target}</div>
            <div className="mt-1 font-mono text-xs text-matrix-dim">
              {scan.profile} · motor: {scan.engine === "ai" ? "Claude Opus 4.8 dinamik" : "deterministik"} ·{" "}
              {scan.pagesCrawled} sayfa · {scan.requestsMade} istek
            </div>
          </div>
          <div className="text-center">
            <div className={`text-5xl font-bold ${GRADE_COLOR[scan.grade ?? "A"] ?? "text-matrix"}`}>
              {scan.grade ?? (running ? "…" : "—")}
            </div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-matrix-dim">
              risk {scan.riskScore ?? 0}/100
            </div>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-5 gap-2">
          {ORDER.map((sev) => (
            <div
              key={sev}
              className="rounded-lg border border-matrix/10 bg-black/30 py-2 text-center"
            >
              <div className="text-lg font-bold text-matrix">{counts[sev] ?? 0}</div>
              <div className="font-mono text-[9px] uppercase tracking-wider text-matrix-dim">
                {sev}
              </div>
            </div>
          ))}
        </div>

        {!running && (
          <div className="mt-4 flex gap-2">
            <button
              onClick={() => download("md")}
              className="rounded-lg border border-matrix/30 bg-black/30 px-3 py-1.5 font-mono text-xs text-matrix transition hover:border-matrix/60 hover:bg-matrix/10"
            >
              ⬇ Markdown rapor
            </button>
            <button
              onClick={() => download("json")}
              className="rounded-lg border border-matrix/30 bg-black/30 px-3 py-1.5 font-mono text-xs text-matrix transition hover:border-matrix/60 hover:bg-matrix/10"
            >
              ⬇ JSON rapor
            </button>
          </div>
        )}

        {scan.status === "FAILED" && (
          <div className="mt-3 rounded border border-sev-critical/40 bg-sev-critical/10 p-2 font-mono text-xs text-sev-critical">
            Tarama başarısız: {scan.error}
          </div>
        )}
      </div>

      {/* Findings */}
      <div className="flex flex-col gap-2">
        {total === 0 && !running && (
          <div className="glass rounded-xl p-6 text-center font-mono text-sm text-matrix">
            ✓ Bu profil için bulgu yok. Tebrikler.
          </div>
        )}
        {total === 0 && running && (
          <div className="glass rounded-xl p-6 text-center font-mono text-sm text-matrix-dim">
            bulgular akarken burada belirecek…
          </div>
        )}
        {scan.findings.map((f) => (
          <FindingCard key={f.id} f={f} />
        ))}
      </div>
    </div>
  );
}

function FindingCard({ f }: { f: FindingRow }) {
  const [open, setOpen] = useState(f.severity === "CRITICAL" || f.severity === "HIGH");
  return (
    <div className="glass animate-fade-in rounded-xl">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
      >
        <span className="flex min-w-0 items-center gap-3">
          <SeverityBadge severity={f.severity} />
          <span className="truncate font-medium text-matrix/90">{f.title}</span>
        </span>
        <span className="font-mono text-xs text-matrix-dim">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-matrix/10 px-4 py-3 text-sm">
          <div className="flex flex-wrap gap-2 font-mono text-[11px]">
            {f.cwe && (
              <span className="rounded border border-matrix/20 px-2 py-0.5 text-matrix-dim">
                {f.cwe}
              </span>
            )}
            {f.owasp && (
              <span className="rounded border border-matrix/20 px-2 py-0.5 text-matrix-dim">
                {f.owasp}
              </span>
            )}
            <span className="rounded border border-matrix/20 px-2 py-0.5 text-matrix-dim">
              güven: {f.confidence}
            </span>
          </div>

          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-matrix-dim">Konum</div>
            <div className="break-all font-mono text-xs text-sev-low">{f.location}</div>
          </div>

          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-matrix-dim">Açıklama</div>
            <p className="whitespace-pre-wrap text-matrix/80">{f.description}</p>
          </div>

          {f.evidence && (
            <div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-matrix-dim">Kanıt</div>
              <pre className="overflow-x-auto rounded bg-black/50 p-3 font-mono text-xs text-sev-medium">
                {f.evidence}
              </pre>
            </div>
          )}

          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-matrix">
              ⟶ Nasıl düzeltilir
            </div>
            <pre className="overflow-x-auto whitespace-pre-wrap rounded border border-matrix/20 bg-matrix-dark/40 p-3 font-mono text-xs text-matrix/90">
              {f.remediation}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
