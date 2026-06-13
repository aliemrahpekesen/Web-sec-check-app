import type { Severity } from "@/lib/types";

const STYLE: Record<Severity, string> = {
  CRITICAL: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  HIGH: "bg-sev-high/15 text-sev-high border-sev-high/40",
  MEDIUM: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  LOW: "bg-sev-low/15 text-sev-low border-sev-low/40",
  INFO: "bg-sev-info/15 text-sev-info border-sev-info/40",
};

const LABEL: Record<Severity, string> = {
  CRITICAL: "KRİTİK",
  HIGH: "YÜKSEK",
  MEDIUM: "ORTA",
  LOW: "DÜŞÜK",
  INFO: "BİLGİ",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wider ${STYLE[severity]}`}
    >
      {LABEL[severity]}
    </span>
  );
}
