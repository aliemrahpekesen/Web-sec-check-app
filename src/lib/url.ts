// URL normalization + a fast, synchronous SSRF pre-check. Framework-neutral.
// The authoritative SSRF enforcement (DNS resolution, IP-encoding decoding,
// per-redirect validation) lives in `ssrf.ts` and runs on every outbound
// request; `isLikelyPrivate` here is only a cheap early reject for obvious
// cases so the API can fail fast with a clear message.
import net from "node:net";
import { decodeIpv4Literal, isPrivateIp } from "./ssrf";

const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^0\.0\.0\.0$/,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./, // link-local (incl. cloud metadata)
  /^172\.(1[6-9]|2\d|3[01])\./, // 172.16.0.0/12
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 CGNAT
  /^::1$/,
  /^::$/,
  /\.local$/i,
  /\.internal$/i,
  /^metadata\./i,
];

export interface NormalizedTarget {
  url: string;
  host: string;
  origin: string;
}

export function normalizeTarget(input: string): NormalizedTarget {
  let raw = input.trim();
  if (!raw) throw new Error("Boş hedef");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

  const u = new URL(raw);
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`Yalnızca http/https desteklenir (verilen: ${u.protocol})`);
  }
  // Embedded credentials (user:pass@host) are a phishing/SSRF smell — drop them.
  u.username = "";
  u.password = "";
  u.hash = "";

  const host = u.hostname.toLowerCase();
  if (!host) throw new Error("Geçersiz host");

  return { url: u.toString(), host, origin: u.origin };
}

// Cheap synchronous check: obvious private hostnames + any private IP literal
// (including decimal/hex/octal encodings, which decodeIpv4Literal normalizes).
export function isLikelyPrivate(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "");
  if (PRIVATE_HOST_PATTERNS.some((re) => re.test(h))) return true;
  if (net.isIP(h) && isPrivateIp(h)) return true;
  const v4 = decodeIpv4Literal(h);
  if (v4 && isPrivateIp(v4)) return true;
  return false;
}

// Same-origin guard for the crawler: only follow links within the target origin.
export function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}
