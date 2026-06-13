import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { stateless } from "@/lib/env";
import { decodeScanId } from "@/lib/scanid";

export const runtime = "nodejs";

// GET /api/scans/:id — full scan with findings (severity-ordered) and log replay.
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  // Stateless demo: no DB. Decode the id into a stub so the UI can show the
  // target; the live report is built entirely from the SSE stream.
  if (stateless()) {
    const p = decodeScanId(params.id);
    if (!p) return NextResponse.json({ error: "Geçersiz tarama kimliği" }, { status: 404 });
    return NextResponse.json({
      scan: {
        id: params.id,
        target: p.target,
        host: p.host,
        profile: p.profile,
        status: "QUEUED",
        engine: "deterministic",
        riskScore: null,
        grade: null,
        pagesCrawled: 0,
        requestsMade: 0,
        error: null,
        findings: [],
      },
      counts: {},
    });
  }

  const scan = await prisma.scan.findUnique({
    where: { id: params.id },
    include: {
      findings: {
        orderBy: [{ severity: "asc" }, { createdAt: "asc" }],
      },
      logs: { orderBy: { seq: "asc" } },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Tarama bulunamadı" }, { status: 404 });
  }

  // Prisma orders enums alphabetically; resort by real severity rank.
  const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  scan.findings.sort((a, b) => rank[a.severity] - rank[b.severity]);

  const counts = scan.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return NextResponse.json({ scan, counts });
}
