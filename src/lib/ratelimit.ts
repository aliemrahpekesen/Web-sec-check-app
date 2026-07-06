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

// Best-effort client IP from proxy headers. SECURITY: the leftmost value of a
// multi-valued `X-Forwarded-For` is fully client-controlled — an attacker can
// prepend an arbitrary/rotating IP to dodge the per-IP limit or pin a victim.
// Prefer single-value headers that the *trusted edge* (Vercel/Cloudflare) sets
// itself and a client cannot append to; only fall back to XFF, and then to the
// value the edge appended (rightmost), never the client-controlled leftmost.
export function clientIp(req: Request): string {
  const h = req.headers;
  const trusted =
    h.get("x-vercel-forwarded-for") ||
    h.get("cf-connecting-ip") ||
    h.get("x-real-ip");
  if (trusted) return trusted.trim();
  const fwd = h.get("x-forwarded-for");
  if (fwd) {
    const parts = fwd.split(",").map((p) => p.trim()).filter(Boolean);
    // Rightmost = appended by the closest (trusted) proxy; safer than leftmost.
    if (parts.length) return parts[parts.length - 1]!;
  }
  return "unknown";
}
