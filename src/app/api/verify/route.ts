import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getDefaultOrg } from "@/lib/org";
import { verifySchema } from "@/lib/validation";
import { normalizeTarget } from "@/lib/url";
import { makeToken, verifyDomain, VERIFICATION_PATH, DNS_PREFIX } from "@/lib/verify";

export const runtime = "nodejs";

// POST /api/verify — issue an ownership-proof token + instructions for a host.
export async function POST(req: Request) {
  const parsed = verifySchema.safeParse(await req.json().catch(() => ({})));
  if (!parsed.success) {
    return NextResponse.json({ error: "Geçersiz host" }, { status: 400 });
  }
  const host = normalizeTarget(parsed.data.host).host;
  const org = await getDefaultOrg();
  const token = makeToken(org.id, host);

  await prisma.verifiedDomain.upsert({
    where: { organizationId_host: { organizationId: org.id, host } },
    update: { token },
    create: { organizationId: org.id, host, token, method: "HTTP_FILE" },
  });

  return NextResponse.json({
    host,
    token,
    instructions: {
      dns: `${host} için bir TXT kaydı ekleyin:  ${DNS_PREFIX}=${token}`,
      file: `Şu adreste bu içeriğe sahip bir dosya yayınlayın: https://${host}${VERIFICATION_PATH}\nİçerik: ${token}`,
    },
  });
}

// PUT /api/verify — check the proof and mark the host verified on success.
export async function PUT(req: Request) {
  const parsed = verifySchema.safeParse(await req.json().catch(() => ({})));
  if (!parsed.success) {
    return NextResponse.json({ error: "Geçersiz host" }, { status: 400 });
  }
  const host = normalizeTarget(parsed.data.host).host;
  const org = await getDefaultOrg();

  const record = await prisma.verifiedDomain.findUnique({
    where: { organizationId_host: { organizationId: org.id, host } },
  });
  if (!record) {
    return NextResponse.json({ error: "Önce token isteyin (POST /api/verify)." }, { status: 400 });
  }

  const result = await verifyDomain(host, record.token);
  if (result.ok) {
    await prisma.verifiedDomain.update({
      where: { id: record.id },
      data: { verifiedAt: new Date(), method: result.method ?? "HTTP_FILE" },
    });
  }
  return NextResponse.json({ host, verified: result.ok, detail: result.detail });
}
