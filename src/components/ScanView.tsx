"use client";

import { useEffect, useRef, useState, useCallback, useMemo } from "react";
import Link from "next/link";
import { MatrixRain } from "./MatrixRain";
import { Report, type FullScan, type FindingRow, type CoverageData } from "./Report";
import type { FindingDraft, LiveEvent, LogLevel, Severity } from "@/lib/types";

interface LogLine {
  seq: number;
  level: LogLevel;
  message: string;
  at: string;
}

const LEVEL_STYLE: Record<LogLevel, string> = {
  info: "text-matrix/70",
  step: "text-matrix font-semibold",
  tool: "text-sev-low",
  finding: "text-sev-medium",
  warn: "text-sev-high",
  error: "text-sev-critical",
  success: "text-matrix text-glow font-semibold",
};

const LEVEL_PREFIX: Record<LogLevel, string> = {
  info: "·",
  step: "▸",
  tool: "⚙",
  finding: "⚠",
  warn: "!",
  error: "✗",
  success: "✓",
};

const RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function draftToRow(f: FindingDraft): FindingRow {
  return {
    id: `${f.checkId}::${f.location}`,
    checkId: f.checkId,
    title: f.title,
    severity: f.severity,
    category: f.category ?? null,
    cwe: f.cwe ?? null,
    owasp: f.owasp ?? null,
    references: f.references ?? null,
    location: f.location,
    description: f.description,
    evidence: f.evidence ?? null,
    remediation: f.remediation,
    confidence: f.confidence ?? "firm",
  };
}

interface Summary {
  status: string;
  riskScore?: number;
  grade?: string;
  engine?: string;
  pagesCrawled?: number;
  requestsMade?: number;
  coverage?: CoverageData;
}

export function ScanView({ scanId }: { scanId: string }) {
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [status, setStatus] = useState<string>("QUEUED");
  const [base, setBase] = useState<FullScan | null>(null); // from GET (target/host + DB findings)
  const [streamFindings, setStreamFindings] = useState<FindingRow[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const consoleRef = useRef<HTMLDivElement>(null);
  const seen = useRef<Set<number>>(new Set());

  const loadReport = useCallback(async () => {
    const res = await fetch(`/api/scans/${scanId}`);
    if (!res.ok) return;
    const data = await res.json();
    setBase(data.scan);
    setStatus((prev) => (prev === "COMPLETED" || prev === "FAILED" ? prev : data.scan.status));
  }, [scanId]);

  useEffect(() => {
    void loadReport();
    const es = new EventSource(`/api/scans/${scanId}/stream`);

    es.onmessage = (ev) => {
      let e: LiveEvent;
      try {
        e = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (e.type === "log" && e.message && typeof e.seq === "number") {
        if (seen.current.has(e.seq)) return;
        seen.current.add(e.seq);
        setLogs((prev) => [
          ...prev,
          { seq: e.seq, level: (e.level ?? "info") as LogLevel, message: e.message!, at: e.at },
        ]);
      }
      if (e.type === "finding" && e.finding) {
        const row = draftToRow(e.finding);
        setStreamFindings((prev) =>
          prev.some((x) => x.id === row.id) ? prev : [...prev, row],
        );
      } else if (e.type === "status" && e.status) {
        setStatus(e.status);
      } else if (e.type === "done") {
        if (e.status) setStatus(e.status);
        setSummary({
          status: e.status ?? "COMPLETED",
          riskScore: e.riskScore,
          grade: e.grade,
          engine: (e.meta?.engine as string) ?? undefined,
          pagesCrawled: e.meta?.pagesCrawled as number | undefined,
          requestsMade: e.meta?.requestsMade as number | undefined,
          coverage: (e.meta?.coverage as CoverageData | undefined) ?? undefined,
        });
        es.close();
        // DB mode: findings live in Postgres — refetch. Stateless: harmless.
        setTimeout(() => void loadReport(), 600);
      }
    };
    es.onerror = () => {
      /* browser auto-reconnects; server replays + dedupes by seq */
    };

    return () => es.close();
  }, [scanId, loadReport]);

  useEffect(() => {
    consoleRef.current?.scrollTo({ top: consoleRef.current.scrollHeight });
  }, [logs]);

  // Merge DB findings (if any) with streamed findings, dedupe, sort by severity.
  const effective: FullScan | null = useMemo(() => {
    if (!base) return null;
    const map = new Map<string, FindingRow>();
    for (const f of base.findings ?? []) map.set(`${f.checkId}::${f.location}`, f);
    for (const f of streamFindings) if (!map.has(f.id)) map.set(f.id, f);
    const findings = [...map.values()].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
    return {
      ...base,
      status: summary?.status ?? status ?? base.status,
      riskScore: summary?.riskScore ?? base.riskScore,
      grade: summary?.grade ?? base.grade,
      engine: summary?.engine ?? base.engine,
      pagesCrawled: summary?.pagesCrawled ?? base.pagesCrawled,
      requestsMade: summary?.requestsMade ?? base.requestsMade,
      findings,
    };
  }, [base, streamFindings, summary, status]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of effective?.findings ?? []) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [effective]);

  const running = status === "RUNNING" || status === "QUEUED";
  const findingCount = effective?.findings.length ?? 0;

  return (
    <main className="relative min-h-screen grid-bg">
      <MatrixRain opacity={0.1} />
      <div className="relative z-10 mx-auto max-w-6xl px-4 py-8">
        <div className="mb-6 flex items-center justify-between">
          <Link href="/" className="font-mono text-sm text-matrix-dim hover:text-matrix">
            ← SentinelScan
          </Link>
          <span className="truncate pl-4 font-mono text-xs text-matrix-dim">{base?.host ?? ""}</span>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Live Matrix console */}
          <section className="flex flex-col">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="font-mono text-sm uppercase tracking-widest text-matrix">⟫ canlı akış</h2>
              <span className="font-mono text-xs">
                <span className={`mr-3 ${running ? "animate-flicker text-matrix" : "text-matrix-dim"}`}>
                  ● {status}
                </span>
                <span className="text-sev-medium">{findingCount} bulgu</span>
              </span>
            </div>
            <div
              ref={consoleRef}
              className="glass h-[70vh] overflow-y-auto rounded-xl p-4 font-mono text-[13px] leading-relaxed"
            >
              {logs.length === 0 && (
                <div className="animate-flicker text-matrix-dim">[SENTINEL] orkestratör bekleniyor…</div>
              )}
              {logs.map((l) => (
                <div key={l.seq} className="animate-fade-in whitespace-pre-wrap break-words">
                  <span className="text-matrix-dim/50">
                    {new Date(l.at).toLocaleTimeString("tr-TR", { hour12: false })}{" "}
                  </span>
                  <span className={LEVEL_STYLE[l.level]}>
                    {LEVEL_PREFIX[l.level]} {l.message}
                  </span>
                </div>
              ))}
              {running && <div className="mt-1 inline-block animate-flicker text-matrix">█</div>}
            </div>
          </section>

          {/* Report */}
          <section>
            <Report scan={effective} counts={counts} running={running} coverage={summary?.coverage ?? base?.coverage ?? null} />
          </section>
        </div>
      </div>
    </main>
  );
}
