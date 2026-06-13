"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import Link from "next/link";
import { MatrixRain } from "./MatrixRain";
import { Report, type FullScan } from "./Report";
import type { LiveEvent, LogLevel } from "@/lib/types";

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

export function ScanView({ scanId }: { scanId: string }) {
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [status, setStatus] = useState<string>("QUEUED");
  const [liveFindings, setLiveFindings] = useState(0);
  const [report, setReport] = useState<FullScan | null>(null);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const consoleRef = useRef<HTMLDivElement>(null);
  const seen = useRef<Set<number>>(new Set());

  const loadReport = useCallback(async () => {
    const res = await fetch(`/api/scans/${scanId}`);
    if (!res.ok) return;
    const data = await res.json();
    setReport(data.scan);
    setCounts(data.counts ?? {});
    setStatus(data.scan.status);
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
        if (e.level === "finding") setLiveFindings((n) => n + 1);
      } else if (e.type === "finding") {
        setLiveFindings((n) => n + 1);
      } else if (e.type === "status" && e.status) {
        setStatus(e.status);
      } else if (e.type === "done") {
        if (e.status) setStatus(e.status);
        es.close();
        // Give the worker a beat to flush the final DB writes, then refresh.
        setTimeout(() => void loadReport(), 600);
      }
    };
    es.onerror = () => {
      // The browser auto-reconnects; the server replays history + dedupes by seq.
    };

    return () => es.close();
  }, [scanId, loadReport]);

  useEffect(() => {
    consoleRef.current?.scrollTo({ top: consoleRef.current.scrollHeight });
  }, [logs]);

  const running = status === "RUNNING" || status === "QUEUED";

  return (
    <main className="relative min-h-screen grid-bg">
      <MatrixRain opacity={0.1} />
      <div className="relative z-10 mx-auto max-w-6xl px-4 py-8">
        <div className="mb-6 flex items-center justify-between">
          <Link href="/" className="font-mono text-sm text-matrix-dim hover:text-matrix">
            ← SentinelScan
          </Link>
          <span className="font-mono text-xs text-matrix-dim">{scanId}</span>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Live Matrix console */}
          <section className="flex flex-col">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="font-mono text-sm uppercase tracking-widest text-matrix">
                ⟫ canlı akış
              </h2>
              <span className="font-mono text-xs">
                <span
                  className={`mr-3 ${running ? "animate-flicker text-matrix" : "text-matrix-dim"}`}
                >
                  ● {status}
                </span>
                <span className="text-sev-medium">{liveFindings} bulgu</span>
              </span>
            </div>
            <div
              ref={consoleRef}
              className="glass h-[70vh] overflow-y-auto rounded-xl p-4 font-mono text-[13px] leading-relaxed"
            >
              {logs.length === 0 && (
                <div className="animate-flicker text-matrix-dim">
                  [SENTINEL] orkestratör bekleniyor…
                </div>
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
            <Report scan={report} counts={counts} running={running} />
          </section>
        </div>
      </div>
    </main>
  );
}
