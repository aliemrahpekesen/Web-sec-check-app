// The full check catalog. Import every module and expose the flattened list.
import type { Check, CheckCategory } from "./types";
import { HEADER_CHECKS } from "./headers";
import { COOKIE_CHECKS } from "./cookies";
import { TLS_CHECKS } from "./tls";
import { CSP_CHECKS } from "./csp";
import { CORS_CHECKS } from "./cors";
import { CONTENT_CHECKS } from "./content";
import { CACHE_CHECKS } from "./cache";
import { AUTH_CHECKS } from "./auth";
import { DISCLOSURE_CHECKS } from "./disclosure";
import { INJECTION_CHECKS } from "./active";
import { FINGERPRINT_CHECKS } from "./fingerprint";
import { DNS_EMAIL_CHECKS } from "./dns";
import { API_CHECKS, HTTP_CONFIG_CHECKS } from "./apihttp";

const MODULES: Check[][] = [
  HEADER_CHECKS,
  COOKIE_CHECKS,
  TLS_CHECKS,
  CSP_CHECKS,
  CORS_CHECKS,
  CONTENT_CHECKS,
  CACHE_CHECKS,
  AUTH_CHECKS,
  DISCLOSURE_CHECKS,
  INJECTION_CHECKS,
  FINGERPRINT_CHECKS,
  DNS_EMAIL_CHECKS,
  API_CHECKS,
  HTTP_CONFIG_CHECKS,
];

function build(): Check[] {
  const byId = new Map<string, Check>();
  for (const mod of MODULES) {
    for (const c of mod) {
      if (!byId.has(c.id)) byId.set(c.id, c); // first definition wins; ids must be unique
    }
  }
  return [...byId.values()];
}

export const ALL_CHECKS: Check[] = build();

export function checkCount(): number {
  return ALL_CHECKS.length;
}

export function catalogByCategory(): Record<string, number> {
  const out: Record<string, number> = {};
  for (const c of ALL_CHECKS) out[c.category] = (out[c.category] ?? 0) + 1;
  return out;
}

// Checks that apply to a given profile (used for the "N checks available" count).
export function checksForProfile(profile: "PASSIVE" | "STANDARD" | "DEEP"): Check[] {
  return ALL_CHECKS.filter((c) => !c.profiles || c.profiles.includes(profile));
}

export const CATEGORY_ORDER: CheckCategory[] = [
  "injection",
  "disclosure",
  "tls",
  "crypto",
  "headers",
  "csp",
  "cookies",
  "cors",
  "content",
  "auth-session",
  "dns-email",
  "api",
  "http-config",
  "fingerprint",
  "cache",
  "supply-chain",
];
