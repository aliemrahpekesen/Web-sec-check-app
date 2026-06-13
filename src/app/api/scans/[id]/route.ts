import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const runtime = "nodejs";

// GET /api/scans/:id — full scan with findings (severity-ordered) and log replay.
export async function GET(_req: Request, { params }: { params: { id: string } }) {
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
