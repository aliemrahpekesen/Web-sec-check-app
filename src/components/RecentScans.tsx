"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

interface ScanRow {
  id: string;
  target: string;
  host: string;
  profile: string;
  status: string;
  engine: string;
  riskScore: number | null;
  grade: string | null;
  createdAt: string;
}

const STATUS_COLOR: Record<string, string> = {
  QUEUED: "text-matrix-dim",
  RUNNING: "text-matrix animate-flicker",
  COMPLETED: "text-matrix",
  FAILED: "text-sev-high",
  CANCELLED: "text-sev-info",
};

export function RecentScans() {
  const [scans, setScans] = useState<ScanRow[] | null>(null);

  useEffect(() => {
    fetch("/api/scans")
      .then((r) => r.json())
      .then((d) => setScans(d.scans ?? []))
      .catch(() => setScans([]));
  }, []);

  if (!scans || scans.length === 0) return null;

  return (
    <div className="mx-auto mt-12 w-full max-w-2xl">
      <h2 className="mb-3 font-mono text-xs uppercase tracking-widest text-matrix-dim">
        Son taramalar
      </h2>
      <div className="space-y-1.5">
        {scans.map((s) => (
          <Link
            key={s.id}
            href={`/scan/${s.id}`}
            className="flex items-center justify-between rounded-lg border border-matrix/12 bg-black/30 px-4 py-2.5 font-mono text-sm transition hover:border-matrix/40"
          >
            <span className="truncate text-matrix/90">{s.host}</span>
            <span className="flex items-center gap-3 text-xs">
              <span className="text-matrix-dim">{s.profile}</span>
              {s.grade && (
                <span className="rounded border border-matrix/30 px-1.5 text-matrix">{s.grade}</span>
              )}
              <span className={STATUS_COLOR[s.status] ?? "text-matrix-dim"}>{s.status}</span>
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}
