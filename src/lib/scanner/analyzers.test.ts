import { describe, it, expect } from "vitest";
import { analyzeSecurityHeaders, analyzeCookies, analyzeSri } from "./analyzers";
import type { HttpResult } from "./http";

function res(partial: Partial<HttpResult>): HttpResult {
  return {
    url: "https://ex.com/",
    finalUrl: "https://ex.com/",
    status: 200,
    ok: true,
    headers: {},
    setCookies: [],
    body: "",
    redirected: false,
    ...partial,
  };
}

const HARDENED = {
  "strict-transport-security": "max-age=63072000",
  "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=()",
  server: "Vercel",
};

describe("analyzeSecurityHeaders", () => {
  it("returns nothing for a hardened response", () => {
    expect(analyzeSecurityHeaders(res({ headers: HARDENED }))).toHaveLength(0);
  });

  it("flags the whole missing-header family on a bare response", () => {
    const ids = analyzeSecurityHeaders(res({ headers: {} })).map((f) => f.checkId);
    expect(ids).toEqual(
      expect.arrayContaining([
        "missing-hsts",
        "missing-csp",
        "missing-x-content-type-options",
        "missing-x-frame-options",
        "missing-referrer-policy",
        "missing-permissions-policy",
      ]),
    );
  });

  it("flags server-version-disclosure via X-Powered-By", () => {
    const ids = analyzeSecurityHeaders(res({ headers: { ...HARDENED, "x-powered-by": "Express" } })).map(
      (f) => f.checkId,
    );
    expect(ids).toContain("server-version-disclosure");
  });

  it("flags weak-csp when script-src allows unsafe-inline without a nonce", () => {
    const headers = { ...HARDENED, "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'" };
    const ids = analyzeSecurityHeaders(res({ headers })).map((f) => f.checkId);
    expect(ids).toContain("weak-csp");
  });

  it("does not flag weak-csp for a nonce-based policy", () => {
    const headers = {
      ...HARDENED,
      "content-security-policy":
        "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic' 'unsafe-inline'; object-src 'none'",
    };
    const ids = analyzeSecurityHeaders(res({ headers })).map((f) => f.checkId);
    expect(ids).not.toContain("weak-csp");
  });
});

describe("analyzeCookies", () => {
  it("passes a fully-flagged cookie", () => {
    const r = res({ setCookies: ["sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"] });
    expect(analyzeCookies(r)).toHaveLength(0);
  });

  it("flags missing flags", () => {
    const r = res({ setCookies: ["sid=abc; Path=/"] });
    const evidence = analyzeCookies(r)[0].evidence!;
    expect(evidence).toContain("Secure");
    expect(evidence).toContain("HttpOnly");
    expect(evidence).toContain("SameSite");
  });

  it("does not misparse cookies with an Expires date containing a comma", () => {
    const r = res({ setCookies: ["sid=abc; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Secure; HttpOnly; SameSite=Lax"] });
    // One cookie in, fully flagged → zero findings (the old comma-split produced false positives here).
    expect(analyzeCookies(r)).toHaveLength(0);
  });

  it("flags SameSite=None without Secure", () => {
    const r = res({ setCookies: ["sid=abc; HttpOnly; SameSite=None"] });
    const ids = analyzeCookies(r).map((f) => f.checkId);
    expect(ids).toContain("insecure-samesite-none");
  });
});

describe("analyzeSri", () => {
  it("flags cross-origin scripts without integrity", () => {
    const r = res({ body: `<script src="https://cdn.other.com/a.js"></script>` });
    expect(analyzeSri(r).map((f) => f.checkId)).toContain("sri-missing");
  });

  it("ignores same-origin scripts and integrity-protected ones", () => {
    const r = res({
      body: `<script src="/local.js"></script><script src="https://cdn.other.com/a.js" integrity="sha384-x"></script>`,
    });
    expect(analyzeSri(r)).toHaveLength(0);
  });
});
