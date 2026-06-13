import { NextResponse, type NextRequest } from "next/server";

// Per-request, nonce-based Content-Security-Policy.
//
// Next.js automatically stamps the nonce onto the inline bootstrap/hydration
// <script> tags it emits, *as long as* the request carries a CSP header with a
// `nonce-...` source — that's why we set the policy on the forwarded request
// headers as well as the response. `strict-dynamic` then lets those trusted
// scripts load the rest of the bundle, so we never need 'unsafe-inline' for
// scripts. Styles use 'unsafe-inline' (Tailwind ships an external stylesheet;
// injected inline styles are low-risk and don't warrant breaking the UI).
export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV !== "production";

  const csp = [
    `default-src 'self'`,
    `base-uri 'self'`,
    `font-src 'self' data:`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    `frame-src 'none'`,
    `img-src 'self' data: blob:`,
    `object-src 'none'`,
    // 'unsafe-eval' is only needed by the dev server (React Refresh / HMR).
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'unsafe-inline'`,
    `connect-src 'self'`,
    `worker-src 'self' blob:`,
    `manifest-src 'self'`,
    `upgrade-insecure-requests`,
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  // Apply to page routes only. API routes (incl. the SSE stream) are left
  // untouched so streaming responses aren't affected; static assets and the
  // image optimizer don't need a nonce.
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
