"use client";

import { useState } from "react";
import { SeverityBadge } from "./SeverityBadge";
import type { Severity } from "@/lib/types";
import { buildJsonReport, buildMarkdownReport, buildHtmlReport, type ReportMeta } from "@/lib/report";

export interface FindingRow {
  id: string;
  checkId: string;
  title: string;
  severity: Severity;
  category?: string | null;
  cwe: string | null;
  owasp: string | null;
  references?: string[] | null;
  location: string;
  description: string;
  evidence: string | null;
  remediation: string;
  confidence: string;
}

export interface CoverageData {
  total: number;
  passed: number;
  failed: number;
  notApplicable: number;
  byCategory: Record<string, { run: number; passed: number; failed: number }>;
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
  coverage?: CoverageData | null; // persisted coverage (present on reload of a completed scan)
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

const CAT_LABEL: Record<string, string> = {
  headers: "Güvenlik Başlıkları",
  cookies: "Çerezler",
  tls: "TLS / Sertifika",
  crypto: "Kriptografi",
  csp: "CSP",
  cors: "CORS",
  disclosure: "Bilgi/Dosya İfşası",
  content: "İçerik & Sırlar",
  injection: "Enjeksiyon",
  fingerprint: "Teknoloji Parmak İzi",
  "dns-email": "DNS & E-posta",
  "http-config": "HTTP Yapılandırması",
  "auth-session": "Kimlik / Oturum",
  api: "API",
  cache: "Önbellek",
  "supply-chain": "Tedarik Zinciri",
};

const CONF_COLOR: Record<string, string> = {
  confirmed: "text-matrix border-matrix/40",
  firm: "text-sev-low border-sev-low/40",
  tentative: "text-sev-medium border-sev-medium/40",
};

export function Report({
  scan,
  counts,
  running,
  coverage,
}: {
  scan: FullScan | null;
  counts: Record<string, number>;
  running: boolean;
  coverage?: CoverageData | null;
}) {
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [catFilter, setCatFilter] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  if (!scan) {
    return (
      <div className="glass flex h-[70vh] items-center justify-center rounded-xl">
        <span className="animate-flicker font-mono text-matrix-dim">rapor yükleniyor…</span>
      </div>
    );
  }

  const q = query.trim().toLowerCase();
  const filtered = scan.findings.filter((f) => {
    if (sevFilter.size && !sevFilter.has(f.severity)) return false;
    if (catFilter && f.category !== catFilter) return false;
    if (q && !`${f.title} ${f.location} ${f.checkId} ${f.cwe ?? ""} ${f.category ?? ""}`.toLowerCase().includes(q)) return false;
    return true;
  });
  const categories = [...new Set(scan.findings.map((f) => f.category).filter(Boolean))] as string[];
  const toggleSev = (s: Severity) =>
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  const total = scan.findings.length;

  function download(kind: "json" | "md" | "html") {
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
    const cov = coverage ?? undefined;
    const content =
      kind === "json"
        ? buildJsonReport(meta, scan!.findings, cov)
        : kind === "html"
          ? buildHtmlReport(meta, scan!.findings, cov)
          : buildMarkdownReport(meta, scan!.findings, cov);
    const type = kind === "json" ? "application/json" : kind === "html" ? "text/html" : "text/markdown";
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelscan-${scan!.host}-${Date.now()}.${kind}`;
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
            <div key={sev} className="rounded-lg border border-matrix/10 bg-black/30 py-2 text-center">
              <div className="text-lg font-bold text-matrix">{counts[sev] ?? 0}</div>
              <div className="font-mono text-[9px] uppercase tracking-wider text-matrix-dim">{sev}</div>
            </div>
          ))}
        </div>

        {coverage && (
          <div className="mt-4 rounded-lg border border-matrix/15 bg-black/20 p-3">
            <div className="mb-2 flex items-center justify-between font-mono text-[11px] text-matrix-dim">
              <span>DENETİM KAPSAMI</span>
              <span>
                <span className="text-matrix">{coverage.total}</span> kontrol koştu ·{" "}
                <span className="text-matrix">{coverage.passed}</span> geçti ·{" "}
                <span className="text-sev-high">{coverage.failed}</span> bulgu
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(coverage.byCategory)
                .sort((a, b) => b[1].failed - a[1].failed || b[1].run - a[1].run)
                .map(([cat, c]) => (
                  <span
                    key={cat}
                    title={`${c.run} kontrol, ${c.passed} geçti, ${c.failed} bulgu`}
                    className={`rounded border px-2 py-0.5 font-mono text-[10px] ${
                      c.failed > 0 ? "border-sev-high/40 text-sev-high" : "border-matrix/20 text-matrix-dim"
                    }`}
                  >
                    {CAT_LABEL[cat] ?? cat} {c.failed}/{c.run}
                  </span>
                ))}
            </div>
          </div>
        )}

        {!running && (
          <div className="mt-4 flex gap-2">
            <button
              onClick={() => download("md")}
              className="rounded-lg border border-matrix/30 bg-black/30 px-3 py-1.5 font-mono text-xs text-matrix transition hover:border-matrix/60 hover:bg-matrix/10"
            >
              ⬇ Markdown rapor
            </button>
            <button
              onClick={() => download("html")}
              className="rounded-lg border border-matrix/30 bg-black/30 px-3 py-1.5 font-mono text-xs text-matrix transition hover:border-matrix/60 hover:bg-matrix/10"
            >
              ⬇ HTML rapor
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

      {/* Filter bar */}
      {total > 0 && (
        <div className="glass flex flex-wrap items-center gap-2 rounded-xl p-3">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="bulgularda ara…"
            className="min-w-[140px] flex-1 rounded-lg border border-matrix/20 bg-black/40 px-3 py-1.5 font-mono text-xs text-matrix outline-none placeholder:text-matrix-dim/60 focus:border-matrix"
          />
          <div className="flex gap-1">
            {ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => (
              <button
                key={s}
                onClick={() => toggleSev(s)}
                className={`rounded border px-2 py-1 font-mono text-[10px] transition ${
                  sevFilter.has(s) ? "border-matrix bg-matrix/20 text-matrix" : "border-matrix/20 text-matrix-dim hover:border-matrix/50"
                }`}
              >
                {s} {counts[s] ?? 0}
              </button>
            ))}
          </div>
          {categories.length > 1 && (
            <select
              value={catFilter ?? ""}
              onChange={(e) => setCatFilter(e.target.value || null)}
              className="rounded-lg border border-matrix/20 bg-black/40 px-2 py-1.5 font-mono text-xs text-matrix outline-none focus:border-matrix"
            >
              <option value="">tüm kategoriler</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {CAT_LABEL[c] ?? c}
                </option>
              ))}
            </select>
          )}
          {(sevFilter.size > 0 || catFilter || query) && (
            <button
              onClick={() => {
                setSevFilter(new Set());
                setCatFilter(null);
                setQuery("");
              }}
              className="font-mono text-[11px] text-matrix-dim underline hover:text-matrix"
            >
              temizle ({filtered.length}/{total})
            </button>
          )}
        </div>
      )}

      {/* Findings */}
      <div className="flex flex-col gap-2">
        {total === 0 && !running && (
          <div className="glass rounded-xl p-6 text-center font-mono text-sm text-matrix">
            ✓ Bu profil için bulgu yok. {coverage ? `${coverage.total} kontrolün tamamı geçti.` : "Tebrikler."}
          </div>
        )}
        {total === 0 && running && (
          <div className="glass rounded-xl p-6 text-center font-mono text-sm text-matrix-dim">
            bulgular akarken burada belirecek…
          </div>
        )}
        {total > 0 && filtered.length === 0 && (
          <div className="glass rounded-xl p-6 text-center font-mono text-sm text-matrix-dim">
            Filtreyle eşleşen bulgu yok.
          </div>
        )}
        {filtered.map((f) => (
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
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left">
        <span className="flex min-w-0 items-center gap-3">
          <SeverityBadge severity={f.severity} />
          <span className="truncate font-medium text-matrix/90">{f.title}</span>
        </span>
        <span className="font-mono text-xs text-matrix-dim">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-matrix/10 px-4 py-3 text-sm">
          <div className="flex flex-wrap gap-2 font-mono text-[11px]">
            {f.category && (
              <span className="rounded border border-matrix/30 bg-matrix/5 px-2 py-0.5 text-matrix">
                {CAT_LABEL[f.category] ?? f.category}
              </span>
            )}
            {f.cwe && <span className="rounded border border-matrix/20 px-2 py-0.5 text-matrix-dim">{f.cwe}</span>}
            {f.owasp && <span className="rounded border border-matrix/20 px-2 py-0.5 text-matrix-dim">{f.owasp}</span>}
            <span className={`rounded border px-2 py-0.5 ${CONF_COLOR[f.confidence] ?? "border-matrix/20 text-matrix-dim"}`}>
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
              <pre className="overflow-x-auto rounded bg-black/50 p-3 font-mono text-xs text-sev-medium">{f.evidence}</pre>
            </div>
          )}

          <div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-matrix">⟶ Nasıl düzeltilir</div>
            <pre className="overflow-x-auto whitespace-pre-wrap rounded border border-matrix/20 bg-matrix-dark/40 p-3 font-mono text-xs text-matrix/90">
              {f.remediation}
            </pre>
          </div>

          {f.references && f.references.length > 0 && (
            <div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-matrix-dim">Referanslar</div>
              <ul className="mt-1 space-y-0.5">
                {f.references.map((r) => (
                  <li key={r}>
                    <a href={r} target="_blank" rel="noopener noreferrer" className="break-all font-mono text-xs text-sev-low underline hover:text-matrix">
                      {r}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
