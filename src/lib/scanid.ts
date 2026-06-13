// In stateless (DB-less) serverless mode there is no scans table, so the scan
// parameters are encoded directly into the scan id. The id is an opaque
// base64url blob the stream route decodes and runs. Framework-neutral.
import type { ScanProfile } from "./types";

export interface ScanParams {
  target: string;
  host: string;
  profile: ScanProfile;
  nonce: string;
}

export function encodeScanId(p: Omit<ScanParams, "nonce">): string {
  const payload: ScanParams = { ...p, nonce: Math.random().toString(36).slice(2, 8) };
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeScanId(id: string): ScanParams | null {
  try {
    const json = Buffer.from(id, "base64url").toString("utf8");
    const p = JSON.parse(json) as ScanParams;
    if (!p.target || !p.host || !p.profile) return null;
    return p;
  } catch {
    return null;
  }
}
