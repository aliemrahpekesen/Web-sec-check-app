// Thin HTTP client used by all analyzers. Tracks request count, enforces
// timeouts and a body-size cap, and never throws on HTTP status — analyzers
// inspect the structured result.

export interface HttpResult {
  url: string;
  finalUrl: string;
  status: number;
  ok: boolean;
  headers: Record<string, string>;
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
  constructor(public max = 200) {}
  spend(): boolean {
    this.count += 1;
    return this.count <= this.max;
  }
}

export async function httpGet(
  url: string,
  opts: {
    budget?: RequestBudget;
    redirect?: RequestRedirect;
    method?: string;
    headers?: Record<string, string>;
    timeout?: number;
  } = {},
): Promise<HttpResult> {
  const { budget, redirect = "follow", method = "GET", headers = {}, timeout = DEFAULT_TIMEOUT } = opts;

  if (budget && !budget.spend()) {
    return errorResult(url, "request budget exhausted");
  }

  try {
    const res = await fetch(url, {
      method,
      redirect,
      headers: { "User-Agent": UA, Accept: "*/*", ...headers },
      signal: AbortSignal.timeout(timeout),
    });

    const headerObj: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headerObj[k.toLowerCase()] = v;
    });

    let body = "";
    const ctype = headerObj["content-type"] ?? "";
    if (/text|html|json|javascript|xml|css/i.test(ctype) || ctype === "") {
      const buf = await res.arrayBuffer();
      body = Buffer.from(buf.slice(0, MAX_BODY)).toString("utf8");
    }

    return {
      url,
      finalUrl: res.url || url,
      status: res.status,
      ok: res.ok,
      headers: headerObj,
      body,
      redirected: res.redirected || (res.url || url) !== url,
    };
  } catch (e) {
    return errorResult(url, e instanceof Error ? e.message : String(e));
  }
}

function errorResult(url: string, error: string): HttpResult {
  return { url, finalUrl: url, status: 0, ok: false, headers: {}, body: "", redirected: false, error };
}
