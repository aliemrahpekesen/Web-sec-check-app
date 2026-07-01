import { NextResponse } from "next/server";
import { env, stateless, aiEnabled } from "@/lib/env";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/health — liveness/readiness probe for monitoring and load balancers.
// In DB-backed modes it also verifies database connectivity (503 if down).
export async function GET() {
  const mode = stateless() ? "stateless" : env.serverless ? "serverless" : "self-hosted";
  const base = {
    status: "ok" as "ok" | "degraded",
    mode,
    engine: aiEnabled() ? "ai" : "deterministic",
    time: new Date().toISOString(),
  };

  if (stateless()) {
    return NextResponse.json(base, { headers: { "Cache-Control": "no-store" } });
  }

  try {
    const { prisma } = await import("@/lib/db");
    await prisma.$queryRaw`SELECT 1`;
    return NextResponse.json({ ...base, db: "ok" }, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    return NextResponse.json(
      { ...base, status: "degraded", db: "error", detail: e instanceof Error ? e.message : String(e) },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
}
