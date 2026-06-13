// Domain-ownership verification. Active scanning is only allowed against hosts
// the requester can prove they control — this is what keeps the SaaS from being
// an open attack tool. Two methods: a DNS TXT record, or a file served at a
// well-known path.
import { promises as dns } from "node:dns";
import crypto from "node:crypto";
import { env } from "./env";

export const VERIFICATION_PATH = "/.well-known/sentinel-verification.txt";
export const DNS_PREFIX = "sentinel-site-verification";

export function makeToken(orgId: string, host: string): string {
  return crypto
    .createHash("sha256")
    .update(`${orgId}:${host}:${env.appUrl}`)
    .digest("hex")
    .slice(0, 32);
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
    const flat = records.map((r) => r.join("")).join(" ");
    if (flat.includes(`${DNS_PREFIX}=${token}`)) {
      return { ok: true, method: "DNS_TXT", detail: "DNS TXT record matched." };
    }
  } catch {
    /* fall through to HTTP */
  }

  // 2. HTTP file check.
  for (const scheme of ["https", "http"]) {
    try {
      const res = await fetch(`${scheme}://${host}${VERIFICATION_PATH}`, {
        redirect: "manual",
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const body = (await res.text()).trim();
        if (body.includes(token)) {
          return { ok: true, method: "HTTP_FILE", detail: `Verified via ${scheme} file.` };
        }
      }
    } catch {
      /* try next scheme */
    }
  }

  return {
    ok: false,
    detail:
      "No matching DNS TXT record or verification file found. Add one of the proofs and retry.",
  };
}

// Whether a host may be actively scanned right now.
export function isAllowlisted(host: string): boolean {
  if (env.skipVerification) return true;
  return env.scanAllowlist.includes(host.toLowerCase());
}
