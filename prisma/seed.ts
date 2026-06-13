// Minimal seed: ensure the default demo organization exists.
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const org = await prisma.organization.upsert({
    where: { slug: "demo" },
    update: {},
    create: { name: "Demo Organization", slug: "demo", plan: "FREE", monthlyScanQuota: 1000 },
  });
  console.log(`Seeded organization: ${org.slug} (${org.id})`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
