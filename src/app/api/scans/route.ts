import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getDefaultOrg } from "@/lib/org";
import { getScanQueue } from "@/lib/queue";
import { createScanSchema } from "@/lib/validation";
import { normalizeTarget, isLikelyPrivate } from "@/lib/url";
import { isAllowlisted, makeToken } from "@/lib/verify";

export const runtime = "nodejs";

// POST /api/scans — enqueue a scan.
export async function POST(req: Request) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Geçersiz JSON gövdesi" }, { status: 400 });
  }

  const parsed = createScanSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Geçersiz girdi", details: parsed.error.flatten() }, { status: 400 });
  }

  let normalized;
  try {
    normalized = normalizeTarget(parsed.data.target);
  } catch {
    return NextResponse.json({ error: "Geçersiz hedef URL" }, { status: 400 });
  }
  const { url, host, origin } = normalized;
  const profile = parsed.data.profile;

  if (isLikelyPrivate(host)) {
    return NextResponse.json(
      { error: "Özel/iç ağ adresleri taranamaz (SSRF koruması)." },
      { status: 400 },
    );
  }

  const org = await getDefaultOrg();

  // Active profiles (STANDARD/DEEP) require domain-ownership proof.
  if (profile !== "PASSIVE" && !isAllowlisted(host)) {
    const verified = await prisma.verifiedDomain.findFirst({
      where: { organizationId: org.id, host, verifiedAt: { not: null } },
    });
    if (!verified) {
      return NextResponse.json(
        {
          error: "verification_required",
          message:
            "Aktif tarama (STANDARD/DEEP) için alan adı sahipliğini doğrulamalısınız. PASSIVE profil doğrulama gerektirmez.",
          host,
          token: makeToken(org.id, host),
          verifyEndpoint: "/api/verify",
        },
        { status: 412 },
      );
    }
  }

  // Quota hook (billing-ready; FREE plan limit).
  if (org.scansThisPeriod >= org.monthlyScanQuota) {
    return NextResponse.json(
      { error: "quota_exceeded", message: "Bu dönemki tarama kotanız doldu." },
      { status: 429 },
    );
  }

  const scan = await prisma.scan.create({
    data: { organizationId: org.id, target: url, host, profile, status: "QUEUED" },
  });
  await prisma.organization.update({
    where: { id: org.id },
    data: { scansThisPeriod: { increment: 1 } },
  });

  await getScanQueue().add(
    "scan",
    { scanId: scan.id, target: url, host, profile },
    { jobId: scan.id },
  );

  return NextResponse.json(
    { id: scan.id, target: url, origin, profile, status: scan.status },
    { status: 201 },
  );
}

// GET /api/scans — recent scans for the org.
export async function GET() {
  const org = await getDefaultOrg();
  const scans = await prisma.scan.findMany({
    where: { organizationId: org.id },
    orderBy: { createdAt: "desc" },
    take: 25,
    select: {
      id: true,
      target: true,
      host: true,
      profile: true,
      status: true,
      engine: true,
      riskScore: true,
      grade: true,
      createdAt: true,
    },
  });
  return NextResponse.json({ scans });
}
