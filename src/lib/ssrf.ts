// SSRF defence for the scanner's outbound HTTP.
//
// A web *security* scanner is the classic SSRF target: it fetches
// attacker-supplied URLs by design. Every safeguard here exists because the
// naive version (`fetch(userUrl)`) lets a caller reach cloud metadata
// (169.254.169.254), internal admin panels, or localhost — via direct private
// hosts, IP-address encodings (decimal/hex/octal/IPv6-mapped), a public
// hostname that resolves to a private IP, or a public URL that 3xx-redirects
// to one.
//
// Framework-neutral (used by the Next runtime and the standalone worker) — no
// `server-only` import.
import { promises as dns } from "node:dns";
import net from "node:net";

const MAX_REDIRECTS = 5;
const DEFAULT_TIMEOUT = 12_000;

// Local dev escape hatch: scan targets on the private network (e.g. a staging
// box on 10.x). NEVER enable in a public deployment.
function allowPrivate(): boolean {
  const v = process.env.SENTINEL_ALLOW_PRIVATE_TARGETS;
  return v !== undefined && ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

// ---------------------------------------------------------------------------
// IP classification
// ---------------------------------------------------------------------------

// Blocked IPv4 CIDRs: loopback, RFC1918 private, link-local (incl. cloud
// metadata 169.254.169.254), CGNAT, benchmarking, TEST-NET, documentation,
// multicast, reserved, broadcast, and 0.0.0.0/8.
const V4_BLOCKS: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
  ["255.255.255.255", 32],
];

function v4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, oct) => (acc * 256 + Number(oct)) >>> 0, 0);
}

function inV4Block(ipInt: number, base: string, bits: number): boolean {
  const baseInt = v4ToInt(base);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function isPrivateV4(ip: string): boolean {
  const ipInt = v4ToInt(ip);
  return V4_BLOCKS.some(([base, bits]) => inV4Block(ipInt, base, bits));
}

function isPrivateV6(ip: string): boolean {
  const lower = ip.toLowerCase().split("%")[0]; // strip zone id
  if (lower === "::1" || lower === "::") return true;
  // IPv4-mapped / -compatible (::ffff:a.b.c.d or ::ffff:7f00:1) → check the v4.
  const mapped = lower.match(/^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateV4(mapped[1]);
  const mappedHex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    return isPrivateV4(`${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`);
  }
  // NAT64 well-known prefix 64:ff9b::/96 embeds a v4 in the last 32 bits.
  if (lower.startsWith("64:ff9b::")) return true;
  const firstHextet = parseInt(lower.split(":")[0] || "0", 16);
  if ((firstHextet & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((firstHextet & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((firstHextet & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (lower.startsWith("2001:db8:")) return true; // documentation
  return false;
}

export function isPrivateIp(ip: string): boolean {
  const fam = net.isIP(ip);
  if (fam === 4) return isPrivateV4(ip);
  if (fam === 6) return isPrivateV6(ip);
  return true; // not a canonical IP → treat as unsafe
}

// ---------------------------------------------------------------------------
// IPv4 literal decoding — defeats the classic encoding bypasses.
// http://2130706433, http://0x7f.1, http://0177.0.0.1, http://127.1 all point
// at 127.0.0.1 but sail past a dotted-quad string check.
// ---------------------------------------------------------------------------

function parsePart(part: string): number | null {
  if (part === "") return null;
  let n: number;
  if (/^0x[0-9a-f]+$/i.test(part)) n = parseInt(part, 16);
  else if (/^0[0-7]+$/.test(part)) n = parseInt(part, 8);
  else if (/^\d+$/.test(part)) n = parseInt(part, 10);
  else return null;
  return Number.isFinite(n) ? n : null;
}

// Returns a canonical dotted-quad if `host` is any IPv4 literal encoding, else null.
export function decodeIpv4Literal(host: string): string | null {
  const parts = host.split(".");
  if (parts.length > 4) return null;
  const nums = parts.map(parsePart);
  if (nums.some((n) => n === null)) return null;
  const vals = nums as number[];
  let ipInt: number;
  // inet_aton semantics: the final part fills the remaining low bytes.
  if (vals.length === 1) {
    if (vals[0] > 0xffffffff) return null;
    ipInt = vals[0] >>> 0;
  } else {
    const last = vals[vals.length - 1];
    const lastMax = Math.pow(256, 4 - (vals.length - 1));
    if (last >= lastMax) return null;
    if (vals.slice(0, -1).some((v) => v > 255)) return null;
    ipInt = last >>> 0;
    vals.slice(0, -1).forEach((v, i) => {
      ipInt = (ipInt + v * Math.pow(256, 3 - i)) >>> 0;
    });
  }
  return [(ipInt >>> 24) & 0xff, (ipInt >>> 16) & 0xff, (ipInt >>> 8) & 0xff, ipInt & 0xff].join(".");
}

// ---------------------------------------------------------------------------
// Host assertion
// ---------------------------------------------------------------------------

// Throws SsrfError unless `host` provably points only at public addresses.
// IP literals are validated directly; hostnames are DNS-resolved and *every*
// answer must be public (a split-horizon name with one private A record is
// rejected).
export async function assertPublicHost(host: string): Promise<void> {
  if (allowPrivate()) return;
  const h = host.trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (!h) throw new SsrfError("Boş host");

  if (net.isIP(h)) {
    if (isPrivateIp(h)) throw new SsrfError(`Özel/iç IP reddedildi: ${h}`);
    return;
  }
  const v4 = decodeIpv4Literal(h);
  if (v4) {
    if (isPrivateIp(v4)) throw new SsrfError(`Özel/iç IP reddedildi: ${h} → ${v4}`);
    return;
  }

  let answers: Array<{ address: string }>;
  try {
    answers = await dns.lookup(h, { all: true, verbatim: true });
  } catch {
    throw new SsrfError(`DNS çözümlenemedi: ${h}`);
  }
  if (!answers.length) throw new SsrfError(`DNS kaydı yok: ${h}`);
  for (const a of answers) {
    if (isPrivateIp(a.address)) {
      throw new SsrfError(`Host özel IP'ye çözümleniyor (SSRF): ${h} → ${a.address}`);
    }
  }
}

// ---------------------------------------------------------------------------
// safeFetch — SSRF-validating fetch with manual, per-hop redirect checking.
// ---------------------------------------------------------------------------

export interface SafeFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  redirect?: "follow" | "manual";
  timeout?: number;
  signal?: AbortSignal;
}

function assertHttpUrl(u: URL): void {
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new SsrfError(`Desteklenmeyen şema: ${u.protocol}`);
  }
}

// Drop-in-ish replacement for fetch(). In "follow" mode it re-validates every
// redirect hop (a public URL cannot bounce you onto an internal one). In
// "manual" mode it validates the initial host and returns the raw 3xx so
// callers that inspect redirects (HTTPS-enforcement, open-redirect probes) keep
// working — those never dereference the Location, so a single validation is
// sufficient.
export async function safeFetch(url: string, opts: SafeFetchOptions = {}): Promise<Response> {
  const { method = "GET", headers = {}, redirect = "follow", timeout = DEFAULT_TIMEOUT, signal } = opts;

  let current = new URL(url);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    assertHttpUrl(current);
    await assertPublicHost(current.hostname);

    const res = await fetch(current.toString(), {
      method,
      headers,
      redirect: "manual",
      signal: signal ?? AbortSignal.timeout(timeout),
    });

    const isRedirect = res.status >= 300 && res.status < 400 && res.headers.has("location");
    if (redirect === "manual" || !isRedirect) return res;

    const location = res.headers.get("location")!;
    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      return res; // unparseable redirect target — hand the 3xx back
    }
    current = next;
  }
  throw new SsrfError(`Çok fazla yönlendirme (>${MAX_REDIRECTS})`);
}
