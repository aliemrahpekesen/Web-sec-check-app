import { describe, it, expect } from "vitest";
import { ALL_CHECKS, checkCount, catalogByCategory } from "./registry";
import { runChecks } from "./engine";
import { RequestBudget } from "../http";
import type { Evidence, PageEvidence } from "./types";

// A fully-hardened target. A correct catalog must produce ZERO meaningful
// (CRITICAL/HIGH/MEDIUM) findings here — this is the false-positive guard.
const HARDENED_HEADERS: Record<string, string> = {
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; upgrade-insecure-requests",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "x-permitted-cross-domain-policies": "none",
  server: "webserver",
  "content-type": "text/html; charset=utf-8",
};

function page(overrides: Partial<PageEvidence> = {}): PageEvidence {
  return {
    url: "https://secure.example.com/",
    status: 200,
    ok: true,
    headers: HARDENED_HEADERS,
    setCookies: [],
    body: "<html><head><title>ok</title></head><body>hello</body></html>",
    title: "ok",
    contentType: "text/html; charset=utf-8",
    ...overrides,
  };
}

function evidence(overrides: Partial<Evidence> = {}): Evidence {
  const root = overrides.root ?? page();
  return {
    target: "https://secure.example.com/",
    host: "secure.example.com",
    origin: "https://secure.example.com",
    scheme: "https",
    profile: "DEEP",
    root,
    pages: [root],
    scripts: [],
    inlineScripts: [],
    links: [],
    forms: [],
    apiEndpoints: [],
    tls: {
      reachable: true,
      protocol: "TLSv1.3",
      cipherName: "TLS_AES_256_GCM_SHA384",
      cipherBits: 256,
      validFrom: "Jan 1 2026",
      validTo: "Jan 1 2027",
      daysToExpiry: 200,
      authorized: true,
      issuer: "Lets Encrypt",
      subjectCN: "secure.example.com",
      altNames: ["secure.example.com"],
      keyBits: 256,
      sigAlg: "sha256WithRSAEncryption",
      selfSigned: false,
    },
    tlsMatrix: {
      tested: true,
      protocols: { "TLSv1": false, "TLSv1.1": false, "TLSv1.2": true, "TLSv1.3": true },
      weakCiphersOffered: [],
      forwardSecrecy: true,
    },
    cnames: [],
    graphql: null,
    robotsDisallow: [],
    dns: {
      resolved: true,
      a: ["93.184.216.34"],
      aaaa: ["2606:2800:220:1:248:1893:25c8:1946"],
      mx: ["mx.example.com"],
      ns: ["ns1.example.com", "ns2.example.com"],
      txt: [],
      caa: ['0 issue "letsencrypt.org"'],
      spf: "v=spf1 -all",
      dmarc: "v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100",
      dmarcPolicy: "reject",
      dkimHint: true,
      mtaSts: true,
    },
    methods: { OPTIONS: 204 },
    allowHeader: "GET, HEAD, OPTIONS",
    cors: null,
    httpRoot: page({ url: "http://secure.example.com/", status: 301, headers: { location: "https://secure.example.com/" } }),
    redirectsToHttps: true,
    paths: {},
    probes: {},
    budget: new RequestBudget(100, 60_000),
    ...overrides,
  };
}

describe("catalog registry", () => {
  it("has at least 500 checks", () => {
    expect(checkCount()).toBeGreaterThanOrEqual(500);
  });

  it("has unique check ids", () => {
    const ids = ALL_CHECKS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every check carries required metadata", () => {
    for (const c of ALL_CHECKS) {
      expect(c.id, c.id).toBeTruthy();
      expect(c.title, c.id).toBeTruthy();
      expect(c.description.length, c.id).toBeGreaterThan(10);
      expect(c.remediation.length, c.id).toBeGreaterThan(5);
      expect(c.category, c.id).toBeTruthy();
      expect(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], c.id).toContain(c.severity);
      expect(typeof c.evaluate, c.id).toBe("function");
    }
  });

  it("spans many categories", () => {
    expect(Object.keys(catalogByCategory()).length).toBeGreaterThanOrEqual(12);
  });
});

describe("accuracy — no false positives on a hardened target", () => {
  it("produces zero CRITICAL/HIGH/MEDIUM findings on a secure site", () => {
    const { findings } = runChecks(ALL_CHECKS, evidence());
    const meaningful = findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM");
    expect(meaningful.map((f) => `${f.checkId}:${f.severity}`)).toEqual([]);
  });

  it("records passing coverage (verified-good checks)", () => {
    const { coverage } = runChecks(ALL_CHECKS, evidence());
    expect(coverage.total).toBeGreaterThanOrEqual(500);
    expect(coverage.passed).toBeGreaterThan(20);
  });
});

describe("accuracy — detects real problems on a vulnerable target", () => {
  const vuln = evidence({
    root: page({
      headers: { server: "Apache/2.4.1", "x-powered-by": "PHP/7.2.0", "content-type": "text/html" },
      setCookies: ["sessionid=abc123; Path=/"],
      body: `<html><script src="https://cdn.evil.com/a.js"></script> AKIA1234567890ABCDEF <a href="x" target="_blank">l</a></html>`,
    }),
    tls: {
      reachable: true,
      protocol: "TLSv1.0",
      cipherName: "TLS_RC4_128_MD5",
      cipherBits: 128,
      authorized: false,
      authorizationError: "self signed certificate",
      selfSigned: true,
      subjectCN: "x",
      issuer: "x",
      daysToExpiry: -3,
      validTo: "Jan 1 2020",
    },
    dns: { resolved: true, a: ["1.1.1.1"], aaaa: [], mx: ["mx"], ns: ["ns1"], txt: [], caa: [], spf: undefined, dmarc: undefined },
    tlsMatrix: { tested: true, protocols: { "TLSv1": true, "TLSv1.1": true, "TLSv1.2": true, "TLSv1.3": false }, weakCiphersOffered: ["RC4-SHA"], forwardSecrecy: false },
    graphql: { endpoint: "https://x/graphql", reachable: true, introspectionEnabled: true },
    robotsDisallow: ["/admin"],
    httpRoot: page({ url: "http://x/", status: 200 }),
    redirectsToHttps: false,
    cors: { probeOrigin: "https://evil.example.com", acao: "https://evil.example.com", acac: "true", reflectsOrigin: true, wildcard: false, allowsNullOrigin: false, vary: "" },
    paths: { "/.env": { path: "/.env", status: 200, contentType: "text/plain", length: 40, snippet: "DB_PASSWORD=secret", exists: true } },
  });

  const ids = new Set(runChecks(ALL_CHECKS, vuln).findings.map((f) => f.checkId));

  it.each([
    "hdr-hsts-missing",
    "hdr-nosniff-missing",
    "hdr-x-powered-by",
    "csp-missing",
    "cookie-httponly-missing",
    "cookie-secure-missing",
    "tls-self-signed",
    "crypto-weak-cipher",
    "cors-reflect-credentials",
    "secret-aws-akid",
    "content-sri-missing",
    "tlsm-tls10-enabled",
    "tlsm-weak-cipher-offered",
    "api-graphql-introspection",
    "disclosure-robots-accessible",
  ])("flags %s", (id) => {
    expect(ids.has(id)).toBe(true);
  });

  it("downgrades a signatureless HTML disclosure hit to LOW/tentative (app-page, not a leak)", () => {
    const ev = evidence({
      paths: {
        "/manager/html": { path: "/manager/html", status: 200, contentType: "text/html; charset=utf-8", length: 800, snippet: "<html>app</html>", exists: true },
      },
    });
    const f = runChecks(ALL_CHECKS, ev).findings.find((x) => x.location.includes("/manager/html"));
    expect(f).toBeDefined();
    expect(f!.severity).toBe("LOW");
    expect(f!.confidence).toBe("tentative");
  });

  it("keeps a non-HTML file leak confirmed/high", () => {
    const ev = evidence({
      paths: {
        "/backup.zip": { path: "/backup.zip", status: 200, contentType: "application/zip", length: 90000, snippet: "PK..", exists: true },
      },
    });
    const f = runChecks(ALL_CHECKS, ev).findings.find((x) => x.location.includes("/backup.zip"));
    expect(f).toBeDefined();
    expect(f!.confidence).toBe("confirmed");
    expect(f!.severity).toBe("HIGH");
  });

  it("does not report SPF/DMARC missing when the TXT lookup failed", () => {
    const ev = evidence({
      dns: { resolved: true, a: ["1.1.1.1"], aaaa: [], mx: ["mx"], ns: ["ns1"], txt: [], caa: [], txtResolved: false },
    });
    const ids = runChecks(ALL_CHECKS, ev).findings.map((f) => f.checkId);
    expect(ids).not.toContain("dns-spf-missing");
    expect(ids).not.toContain("dns-dmarc-missing");
  });

  it("flags the exposed .env file", () => {
    const disclosureHit = [...ids].some((id) => id.startsWith("disclosure-") && runChecks(ALL_CHECKS, vuln).findings.some((f) => f.checkId === id && f.location.includes("/.env")));
    expect(disclosureHit).toBe(true);
  });
});
