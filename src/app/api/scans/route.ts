import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { env, stateless } from "@/lib/env";
import { getDefaultOrg } from "@/lib/org";
import { getScanQueue } from "@/lib/queue";
import { createScanSchema } from "@/lib/validation";
import { normalizeTarget, isLikelyPrivate } from "@/lib/url";
import { isAllowlisted, makeToken } from "@/lib/verify";
import { encodeScanId } from "@/lib/scanid";
import { assertPublicHost, SsrfError } from "@/lib/ssrf";
import { rateLimit, clientIp } from "@/lib/ratelimit";

export const runtime = "nodejs";

// POST /api/scans — enqueue a scan.
export async function POST(req: Request) {
  const rl = rateLimit(`scan:${clientIp(req)}`);
  if (!rl.ok) {
    return NextResponse.json(
      { error: "rate_limited", message: "Çok fazla istek. Biraz sonra tekrar deneyin." },
      { status: 429, headers: { "Retry-After": String(rl.retryAfterSec) } },
    );
  }

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
  // Authoritative SSRF check: resolves DNS and rejects hosts that point at any
  // internal address (defeats DNS-rebinding and IP-encoding bypasses).
  try {
    await assertPublicHost(host);
  } catch (e) {
    const message = e instanceof SsrfError ? e.message : "Hedef doğrulanamadı";
    return NextResponse.json({ error: message }, { status: 400 });
  }

  // Stateless demo (no DB): the whole scan runs inside the SSE stream; encode
  // the parameters into the opaque scan id and return immediately.
  //
  // SECURITY: there is no database here to record domain-ownership proof, so the
  // active-profile gate below (which the full stack enforces) cannot run. Active
  // probing (STANDARD/DEEP) of a host the operator hasn't explicitly allowlisted
  // — or globally opted into via SENTINEL_SKIP_VERIFICATION — would turn the demo
  // into an open attack tool. Downgrade unverified active requests to PASSIVE.
  if (stateless()) {
    const effectiveProfile = profile !== "PASSIVE" && !isAllowlisted(host) ? "PASSIVE" : profile;
    const id = encodeScanId({ target: url, host, profile: effectiveProfile });
    return NextResponse.json(
      {
        id,
        target: url,
        origin,
        profile: effectiveProfile,
        status: "QUEUED",
        ...(effectiveProfile !== profile
          ? { notice: "Doğrulama olmadan aktif tarama yapılamaz; PASSIVE profile düşürüldü." }
          : {}),
      },
      { status: 201 },
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

  // Self-hosted: hand off to the BullMQ worker. Serverless: the scan is run
  // inline by the SSE stream route when the client connects (no worker/Redis).
  if (!env.serverless) {
    await getScanQueue().add(
      "scan",
      { scanId: scan.id, target: url, host, profile },
      { jobId: scan.id },
    );
  }

  return NextResponse.json(
    { id: scan.id, target: url, origin, profile, status: scan.status },
    { status: 201 },
  );
}

// GET /api/scans — recent scans for the org.
export async function GET() {
  if (stateless()) return NextResponse.json({ scans: [] });
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
