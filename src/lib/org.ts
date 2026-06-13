// v1 has no auth, so all activity is attributed to a single default org. The
// multi-tenant schema means adding real auth later is additive, not a rewrite —
// swap this helper for a session/API-key lookup.
import { prisma } from "./db";

export async function getDefaultOrg() {
  return prisma.organization.upsert({
    where: { slug: "demo" },
    update: {},
    create: { name: "Demo Organization", slug: "demo", plan: "FREE" },
  });
}
