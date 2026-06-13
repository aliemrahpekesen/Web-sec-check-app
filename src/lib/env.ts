// Centralized, validated environment access. Used by both the Next.js server
// runtime and the standalone BullMQ worker, so it must stay framework-neutral
// (no `server-only` import — that throws in a plain Node process).

function bool(v: string | undefined, fallback = false): boolean {
  if (v === undefined) return fallback;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

function list(v: string | undefined): string[] {
  if (!v) return [];
  return v
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export const env = {
  databaseUrl: process.env.DATABASE_URL ?? "",
  redisUrl: process.env.REDIS_URL ?? "redis://localhost:6379",
  anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "",
  model: process.env.SENTINEL_MODEL || "claude-opus-4-8",
  appUrl: process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000",
  scanAllowlist: list(process.env.SENTINEL_SCAN_ALLOWLIST),
  skipVerification: bool(process.env.SENTINEL_SKIP_VERIFICATION, false),
};

export const aiEnabled = (): boolean => env.anthropicApiKey.trim().length > 0;
