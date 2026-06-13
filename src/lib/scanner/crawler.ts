// Same-origin crawler. Discovers pages, links, forms, script sources, and
// likely backend API endpoints (by statically scanning inline JS for
// fetch()/axios/XHR URL literals). Bounded by a page cap and the request
// budget so it stays polite and fast.
import { parse } from "node-html-parser";
import { httpGet, RequestBudget } from "./http";
import { sameOrigin } from "../url";
import type { Emit } from "../types";

export interface PageInfo {
  url: string;
  status: number;
  title: string;
}

export interface FormInfo {
  page: string;
  action: string;
  method: string;
  inputs: string[];
}

export interface CrawlResult {
  pages: PageInfo[];
  links: string[];
  forms: FormInfo[];
  scripts: string[];
  apiEndpoints: string[];
}

const API_URL_RE =
  /(?:fetch|axios(?:\.\w+)?|\.open|XMLHttpRequest|\$\.(?:get|post|ajax))\s*\(\s*[`'"]([^`'"]+)[`'"]/g;
const PATHISH_RE = /[`'"](\/(?:api|graphql|v\d|rest)\/[^`'"<>\s]{0,120})[`'"]/g;

export async function crawl(
  startUrl: string,
  budget: RequestBudget,
  maxPages: number,
  emit: Emit,
): Promise<CrawlResult> {
  const origin = new URL(startUrl).origin;
  const queue: string[] = [startUrl];
  const seen = new Set<string>([startUrl]);
  const pages: PageInfo[] = [];
  const links = new Set<string>();
  const forms: FormInfo[] = [];
  const scripts = new Set<string>();
  const apiEndpoints = new Set<string>();

  while (queue.length && pages.length < maxPages) {
    const url = queue.shift()!;
    const res = await httpGet(url, { budget });
    if (res.error || !res.body) {
      pages.push({ url, status: res.status, title: "" });
      continue;
    }

    const root = parse(res.body);
    const title = root.querySelector("title")?.text?.trim().slice(0, 120) ?? "";
    pages.push({ url: res.finalUrl, status: res.status, title });
    await emit({
      type: "log",
      level: "tool",
      message: `crawl ▸ ${res.status} ${url}${title ? `  «${title}»` : ""}`,
    });

    // Anchors → expand frontier.
    for (const a of root.querySelectorAll("a[href]")) {
      const href = a.getAttribute("href");
      if (!href) continue;
      let abs: string;
      try {
        abs = new URL(href, url).toString().split("#")[0];
      } catch {
        continue;
      }
      links.add(abs);
      if (sameOrigin(abs, origin) && !seen.has(abs) && queue.length + pages.length < maxPages * 3) {
        seen.add(abs);
        queue.push(abs);
      }
    }

    // Forms → potential injection points.
    for (const f of root.querySelectorAll("form")) {
      const action = f.getAttribute("action") ?? url;
      let absAction: string;
      try {
        absAction = new URL(action, url).toString();
      } catch {
        absAction = url;
      }
      const inputs = f
        .querySelectorAll("input[name],textarea[name],select[name]")
        .map((i) => i.getAttribute("name")!)
        .filter(Boolean);
      forms.push({
        page: url,
        action: absAction,
        method: (f.getAttribute("method") ?? "GET").toUpperCase(),
        inputs,
      });
    }

    // Scripts + inline-JS endpoint mining.
    for (const s of root.querySelectorAll("script")) {
      const src = s.getAttribute("src");
      if (src) {
        try {
          scripts.add(new URL(src, url).toString());
        } catch {
          /* ignore */
        }
      } else {
        const code = s.text ?? "";
        for (const re of [API_URL_RE, PATHISH_RE]) {
          re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = re.exec(code))) {
            try {
              apiEndpoints.add(new URL(m[1], url).toString());
            } catch {
              /* ignore */
            }
          }
        }
      }
    }
  }

  return {
    pages,
    links: [...links],
    forms,
    scripts: [...scripts],
    apiEndpoints: [...apiEndpoints],
  };
}
