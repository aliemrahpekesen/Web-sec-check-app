import { describe, it, expect } from "vitest";
import { makeToken, tokensMatch } from "./verify";

describe("makeToken", () => {
  it("is deterministic and host-case-insensitive", () => {
    const a = makeToken("org1", "Example.COM");
    const b = makeToken("org1", "example.com");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{40}$/);
  });

  it("differs across orgs and hosts", () => {
    expect(makeToken("org1", "example.com")).not.toBe(makeToken("org2", "example.com"));
    expect(makeToken("org1", "a.com")).not.toBe(makeToken("org1", "b.com"));
  });
});

describe("tokensMatch", () => {
  it("compares equal-length tokens", () => {
    const t = makeToken("org1", "example.com");
    expect(tokensMatch(t, t)).toBe(true);
    expect(tokensMatch(t, t.slice(0, -1) + "0")).toBe(false);
  });

  it("returns false for different lengths without throwing", () => {
    expect(tokensMatch("abc", "abcd")).toBe(false);
  });
});
