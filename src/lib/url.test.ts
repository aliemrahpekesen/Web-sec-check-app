import { describe, it, expect } from "vitest";
import { normalizeTarget, isLikelyPrivate, sameOrigin } from "./url";

describe("normalizeTarget", () => {
  it("adds https:// when no scheme is given", () => {
    expect(normalizeTarget("example.com").url).toBe("https://example.com/");
  });

  it("strips embedded credentials and fragments", () => {
    const n = normalizeTarget("https://user:pass@example.com/path#frag");
    expect(n.url).toBe("https://example.com/path");
    expect(n.host).toBe("example.com");
  });

  it("lowercases the host", () => {
    expect(normalizeTarget("HTTPS://Example.COM").host).toBe("example.com");
  });

  it("rejects non-http(s) schemes", () => {
    expect(() => normalizeTarget("javascript:alert(1)")).toThrow();
    expect(() => normalizeTarget("ftp://example.com")).toThrow();
    expect(() => normalizeTarget("file:///etc/passwd")).toThrow();
  });

  it("rejects empty input", () => {
    expect(() => normalizeTarget("   ")).toThrow();
  });
});

describe("isLikelyPrivate", () => {
  it("flags obvious private hosts and encoded loopback", () => {
    for (const h of ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "foo.local", "2130706433"]) {
      expect(isLikelyPrivate(h), h).toBe(true);
    }
  });

  it("allows public hosts", () => {
    for (const h of ["example.com", "8.8.8.8", "github.com"]) {
      expect(isLikelyPrivate(h), h).toBe(false);
    }
  });
});

describe("sameOrigin", () => {
  it("compares origins", () => {
    expect(sameOrigin("https://a.com/x", "https://a.com/y")).toBe(true);
    expect(sameOrigin("https://a.com", "https://b.com")).toBe(false);
    expect(sameOrigin("https://a.com", "http://a.com")).toBe(false);
  });
});
