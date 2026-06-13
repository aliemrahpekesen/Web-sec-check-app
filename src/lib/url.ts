// URL normalization + SSRF-aware validation. Framework-neutral.

const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^0\.0\.0\.0$/,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./, // link-local
  /^172\.(1[6-9]|2\d|3[01])\./, // 172.16.0.0/12
  /^::1$/,
  /\.local$/i,
  /^metadata\./i,
];

export interface NormalizedTarget {
  url: string;
  host: string;
  origin: string;
}

export function normalizeTarget(input: string): NormalizedTarget {
  let raw = input.trim();
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  const u = new URL(raw);
  u.hash = "";
  return { url: u.toString(), host: u.hostname.toLowerCase(), origin: u.origin };
}

export function isLikelyPrivate(host: string): boolean {
  return PRIVATE_HOST_PATTERNS.some((re) => re.test(host));
}

// Same-origin guard for the crawler: only follow links within the target origin.
export function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}
