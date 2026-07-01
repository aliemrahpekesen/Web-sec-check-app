// In-memory sliding-window rate limiter keyed by client identity (IP).
//
// This is a single-instance limiter — good enough for the demo and for a
// single worker/web node, and it fails safe (open) rather than blocking real
// traffic. For a multi-instance deployment, back it with Redis (the queue
// connection is already available); the call sites don't change.
import { env } from "./env";

interface Bucket {
  hits: number[]; // epoch-ms timestamps within the window
}

const WINDOW_MS = 60_000;
const buckets = new Map<string, Bucket>();
let lastSweep = 0;

function sweep(now: number): void {
  if (now - lastSweep < WINDOW_MS) return;
  lastSweep = now;
  for (const [key, b] of buckets) {
    b.hits = b.hits.filter((t) => now - t < WINDOW_MS);
    if (b.hits.length === 0) buckets.delete(key);
  }
}

export interface RateResult {
  ok: boolean;
  remaining: number;
  limit: number;
  retryAfterSec: number;
}

export function rateLimit(key: string, limit = env.rateLimitPerMinute): RateResult {
  const now = Date.now();
  sweep(now);
  const bucket = buckets.get(key) ?? { hits: [] };
  bucket.hits = bucket.hits.filter((t) => now - t < WINDOW_MS);

  if (bucket.hits.length >= limit) {
    const oldest = bucket.hits[0];
    buckets.set(key, bucket);
    return {
      ok: false,
      remaining: 0,
      limit,
      retryAfterSec: Math.max(1, Math.ceil((WINDOW_MS - (now - oldest)) / 1000)),
    };
  }

  bucket.hits.push(now);
  buckets.set(key, bucket);
  return { ok: true, remaining: limit - bucket.hits.length, limit, retryAfterSec: 0 };
}

// Best-effort client IP from proxy headers (Vercel/most reverse proxies set
// these). Falls back to a constant so the limiter still bounds total traffic.
export function clientIp(req: Request): string {
  const h = req.headers;
  const fwd = h.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0]!.trim();
  return h.get("x-real-ip") || h.get("cf-connecting-ip") || "unknown";
}
