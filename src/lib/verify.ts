// Domain-ownership verification. Active scanning is only allowed against hosts
// the requester can prove they control — this is what keeps the SaaS from being
// an open attack tool. Two methods: a DNS TXT record, or a file served at a
// well-known path.
//
// The proof token is an HMAC over (orgId, host) keyed by a server-side secret.
// Without the secret it is unforgeable; a plain hash of public inputs (the old
// design) could be recomputed by anyone and defeated the whole gate.
import { promises as dns } from "node:dns";
import crypto from "node:crypto";
import { env } from "./env";
import { safeFetch } from "./ssrf";

export const VERIFICATION_PATH = "/.well-known/sentinel-verification.txt";
export const DNS_PREFIX = "sentinel-site-verification";

export function makeToken(orgId: string, host: string): string {
  return crypto
    .createHmac("sha256", env.verificationSecret)
    .update(`${orgId}:${host.toLowerCase()}`)
    .digest("hex")
    .slice(0, 40);
}

// Constant-time comparison so token checks don't leak via timing.
export function tokensMatch(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

export interface VerifyResult {
  ok: boolean;
  method?: "DNS_TXT" | "HTTP_FILE";
  detail: string;
}

export async function verifyDomain(host: string, token: string): Promise<VerifyResult> {
  // 1. DNS TXT check.
  try {
    const records = await dns.resolveTxt(host);
    for (const chunks of records) {
      const flat = chunks.join("");
      const m = flat.match(new RegExp(`${DNS_PREFIX}=([0-9a-f]+)`));
      if (m && tokensMatch(m[1], token)) {
        return { ok: true, method: "DNS_TXT", detail: "DNS TXT kaydı eşleşti." };
      }
    }
  } catch {
    /* fall through to HTTP */
  }

  // 2. HTTP file check (SSRF-guarded; the host is user-supplied).
  for (const scheme of ["https", "http"] as const) {
    try {
      const res = await safeFetch(`${scheme}://${host}${VERIFICATION_PATH}`, {
        redirect: "manual",
        timeout: 8000,
      });
      if (res.ok) {
        const body = (await res.text()).trim();
        if (tokensMatch(body, token)) {
          return { ok: true, method: "HTTP_FILE", detail: `${scheme} dosyası ile doğrulandı.` };
        }
      }
    } catch {
      /* try next scheme */
    }
  }

  return {
    ok: false,
    detail: "Eşleşen DNS TXT kaydı veya doğrulama dosyası bulunamadı. Kanıtı ekleyip tekrar deneyin.",
  };
}

// Whether a host may be actively scanned right now.
export function isAllowlisted(host: string): boolean {
  if (env.skipVerification) return true;
  return env.scanAllowlist.includes(host.toLowerCase());
}
