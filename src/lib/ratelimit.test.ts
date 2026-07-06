import { describe, it, expect } from "vitest";
import { rateLimit, clientIp } from "./ratelimit";

describe("rateLimit", () => {
  it("allows up to the limit then blocks", () => {
    const key = `test-${Math.random()}`;
    expect(rateLimit(key, 2).ok).toBe(true);
    expect(rateLimit(key, 2).ok).toBe(true);
    const blocked = rateLimit(key, 2);
    expect(blocked.ok).toBe(false);
    expect(blocked.retryAfterSec).toBeGreaterThan(0);
  });

  it("tracks keys independently", () => {
    const a = `a-${Math.random()}`;
    const b = `b-${Math.random()}`;
    rateLimit(a, 1);
    expect(rateLimit(a, 1).ok).toBe(false);
    expect(rateLimit(b, 1).ok).toBe(true);
  });
});

describe("clientIp", () => {
  it("uses the proxy-appended (rightmost) x-forwarded-for entry, not the spoofable leftmost", () => {
    // The leftmost value is fully client-controlled; the rightmost is what the
    // trusted proxy appended. Trusting the leftmost lets a client dodge the
    // per-IP limit or pin a victim's IP.
    const req = new Request("https://x", { headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8" } });
    expect(clientIp(req)).toBe("5.6.7.8");
  });

  it("prefers a trusted single-value edge header over x-forwarded-for", () => {
    const req = new Request("https://x", {
      headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8", "x-real-ip": "9.9.9.9" },
    });
    expect(clientIp(req)).toBe("9.9.9.9");
  });

  it("falls back when no proxy headers are present", () => {
    expect(clientIp(new Request("https://x"))).toBe("unknown");
  });
});
