// Thin HTTP client used by all analyzers. Tracks a request count *and* a
// wall-clock deadline (so a scan always terminates — critical on serverless
// where the function is killed at ~60s), enforces timeouts and a body-size cap,
// routes every request through the SSRF-validating safeFetch, and never throws
// on HTTP status — analyzers inspect the structured result.
import { safeFetch, SsrfError } from "../ssrf";

export interface HttpResult {
  url: string;
  finalUrl: string;
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  // Raw Set-Cookie values, correctly split (fetch collapses them into one
  // comma-joined header string, which breaks on `Expires=` dates).
  setCookies: string[];
  body: string;
  redirected: boolean;
  error?: string;
}

const MAX_BODY = 512 * 1024; // 512 KB is plenty for analysis
const DEFAULT_TIMEOUT = 12_000;
const UA =
  "SentinelScan/0.1 (+https://github.com/aliemrahpekesen/web-sec-check-app; authorized security testing)";

export class RequestBudget {
  count = 0;
  readonly deadline: number;
  constructor(
    public max = 200,
    // Wall-clock budget in ms. Default 55s keeps inline serverless scans under
    // Vercel's 60s function limit; the worker path can pass a larger value.
    ttlMs = 55_000,
  ) {
    this.deadline = Date.now() + ttlMs;
  }
  spend(): boolean {
    this.count += 1;
    return this.count <= this.max && !this.expired();
  }
  expired(): boolean {
    return Date.now() >= this.deadline;
  }
  remainingMs(): number {
    return Math.max(0, this.deadline - Date.now());
  }
}

export async function httpGet(
  url: string,
  opts: {
    budget?: RequestBudget;
    redirect?: "follow" | "manual";
    method?: string;
    headers?: Record<string, string>;
    timeout?: number;
    body?: string;
  } = {},
): Promise<HttpResult> {
  const { budget, redirect = "follow", method = "GET", headers = {}, timeout = DEFAULT_TIMEOUT, body: reqBody } = opts;

  if (budget) {
    if (budget.expired()) return errorResult(url, "time budget exhausted");
    if (!budget.spend()) return errorResult(url, "request budget exhausted");
  }

  // Never let a single request run past the wall-clock deadline.
  const effectiveTimeout = budget ? Math.min(timeout, Math.max(1000, budget.remainingMs())) : timeout;

  try {
    const res = await safeFetch(url, {
      method,
      redirect,
      headers: { "User-Agent": UA, Accept: "*/*", ...headers },
      timeout: effectiveTimeout,
      body: reqBody,
    });

    const headerObj: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headerObj[k.toLowerCase()] = v;
    });
    const setCookies =
      typeof res.headers.getSetCookie === "function"
        ? res.headers.getSetCookie()
        : headerObj["set-cookie"]
          ? [headerObj["set-cookie"]]
          : [];

    let body = "";
    const ctype = headerObj["content-type"] ?? "";
    if (/text|html|json|javascript|xml|css/i.test(ctype) || ctype === "") {
      const buf = await res.arrayBuffer();
      body = Buffer.from(buf.slice(0, MAX_BODY)).toString("utf8");
    }

    const finalUrl = res.url || url;
    return {
      url,
      finalUrl,
      status: res.status,
      ok: res.ok,
      headers: headerObj,
      setCookies,
      body,
      redirected: res.redirected || finalUrl !== url,
    };
  } catch (e) {
    const msg = e instanceof SsrfError ? `SSRF engellendi: ${e.message}` : e instanceof Error ? e.message : String(e);
    return errorResult(url, msg);
  }
}

function errorResult(url: string, error: string): HttpResult {
  return { url, finalUrl: url, status: 0, ok: false, headers: {}, setCookies: [], body: "", redirected: false, error };
}
