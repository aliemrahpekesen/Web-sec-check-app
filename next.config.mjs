/** @type {import('next').NextConfig} */

// Static security headers applied to every response. The per-request,
// nonce-based Content-Security-Policy is set in middleware.ts (it needs a
// fresh nonce per request, which a static config cannot provide).
const securityHeaders = [
  // Force HTTPS for two years, including subdomains, and allow preload.
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  // Stop MIME-type sniffing.
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Clickjacking defence (CSP frame-ancestors is the modern twin; we send both).
  { key: "X-Frame-Options", value: "DENY" },
  // Don't leak full URLs to third parties.
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Lock down powerful browser features we never use.
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), browsing-topics=(), interest-cohort=()",
  },
  // Isolate the browsing context.
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
];

const nextConfig = {
  reactStrictMode: true,
  // Drop the `X-Powered-By: Next.js` version-disclosure header.
  poweredByHeader: false,
  experimental: {
    // The scanner libraries are server-only; keep them out of the client bundle.
    serverComponentsExternalPackages: [
      "bullmq",
      "ioredis",
      "@anthropic-ai/sdk",
      "node-html-parser",
    ],
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
