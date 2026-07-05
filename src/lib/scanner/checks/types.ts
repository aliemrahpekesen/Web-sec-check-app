// The catalog check-engine contract.
//
// Design goals:
//  1. SCALE — hundreds of individually-defined checks across every category,
//     so coverage is broad and auditable (each check has a stable id + metadata).
//  2. ACCURACY — a check only produces a finding when it has concrete evidence.
//     Every finding carries the raw evidence, a confidence level, and CWE/OWASP/
//     reference links, so a reader can independently verify the report is correct.
//  3. TRUST — checks also report PASS (verified-good) and N/A (not-applicable),
//     so the report can show "X checks run, Y passed, Z failed" — coverage the
//     user can see, not just a list of problems.
//
// Framework-neutral: shared by the Next runtime and the standalone worker. No
// `server-only` import.
import type { RequestBudget } from "../http";
import type { FormInfo } from "../crawler";
import type { Severity, ScanProfile } from "../../types";

// Re-export the shared enums so every check module imports them from this barrel.
export type { Severity, ScanProfile, Emit } from "../../types";

export type Confidence = "tentative" | "firm" | "confirmed";

export type CheckCategory =
  | "headers" // HTTP security-response headers
  | "cookies" // cookie flags / prefixes / scope
  | "tls" // TLS protocol + certificate
  | "crypto" // cipher / key / signature strength
  | "csp" // Content-Security-Policy quality
  | "cors" // cross-origin resource sharing
  | "disclosure" // sensitive files / paths / info leakage
  | "content" // HTML/JS body: secrets, SRI, mixed content, forms
  | "injection" // active probes: XSS, SQLi, redirect, SSTI, traversal…
  | "fingerprint" // technology + version + known-vuln fingerprinting
  | "dns-email" // SPF/DKIM/DMARC/CAA/DNSSEC/takeover
  | "http-config" // methods, redirects, verbose errors, misconfig
  | "auth-session" // login/session exposure (unauthenticated view)
  | "api" // API surface: GraphQL/Swagger/verbs
  | "cache" // caching of sensitive responses
  | "supply-chain"; // dependency / integrity risks

export const CATEGORY_LABELS: Record<CheckCategory, string> = {
  headers: "Güvenlik Başlıkları",
  cookies: "Çerezler",
  tls: "TLS / Sertifika",
  crypto: "Kriptografi",
  csp: "İçerik Güvenlik Politikası",
  cors: "CORS",
  disclosure: "Bilgi / Dosya İfşası",
  content: "İçerik & Sırlar",
  injection: "Enjeksiyon / Aktif Testler",
  fingerprint: "Teknoloji Parmak İzi",
  "dns-email": "DNS & E-posta Güvenliği",
  "http-config": "HTTP Yapılandırması",
  "auth-session": "Kimlik / Oturum",
  api: "API Yüzeyi",
  cache: "Önbellek",
  "supply-chain": "Tedarik Zinciri",
};

// ---------------------------------------------------------------------------
// Evidence — collected ONCE per scan, then handed to every check. Checks are
// pure functions over this snapshot (except active probes, which run during
// collection and stash their results here). This keeps request volume bounded
// no matter how many checks reference the same observation.
// ---------------------------------------------------------------------------

export interface PageEvidence {
  url: string;
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  title: string;
  contentType: string;
  error?: string;
}

export interface TlsEvidence {
  reachable: boolean;
  protocol?: string;
  cipherName?: string;
  cipherBits?: number;
  validFrom?: string;
  validTo?: string;
  daysToExpiry?: number;
  authorized?: boolean;
  authorizationError?: string;
  issuer?: string;
  subjectCN?: string;
  altNames?: string[];
  keyBits?: number;
  sigAlg?: string;
  selfSigned?: boolean;
  san?: string;
  error?: string;
}

export interface DnsEvidence {
  resolved: boolean;
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  txt: string[];
  caa: string[];
  spf?: string;
  dmarc?: string;
  dmarcPolicy?: string;
  dkimHint?: boolean;
  mtaSts?: boolean;
  txtResolved?: boolean; // false = the TXT lookup failed → "missing" is unknown
  error?: string;
}

export interface TlsMatrix {
  tested: boolean;
  // Which protocol versions the server actually completes a handshake with.
  protocols: Record<"TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3", boolean>;
  weakCiphersOffered: string[]; // negotiated when only weak ciphers were offered
  forwardSecrecy: boolean; // an ECDHE/DHE suite negotiated on a modern handshake
}

export interface GraphqlEvidence {
  endpoint: string;
  reachable: boolean;
  introspectionEnabled: boolean;
}

export interface CorsEvidence {
  probeOrigin: string; // the malicious Origin we sent
  acao: string; // Access-Control-Allow-Origin returned
  acac: string; // Access-Control-Allow-Credentials returned
  reflectsOrigin: boolean; // ACAO echoed our probe origin
  wildcard: boolean; // ACAO === "*"
  allowsNullOrigin: boolean;
  vary: string;
}

export interface ProbeEvidence {
  path: string;
  status: number;
  contentType: string;
  length: number;
  snippet: string;
  exists: boolean; // 200 + passed content sanity (not a SPA catch-all)
}

export interface Evidence {
  target: string;
  host: string;
  origin: string;
  scheme: string;
  profile: ScanProfile;

  root: PageEvidence;
  pages: PageEvidence[];
  scripts: string[]; // absolute script src URLs
  inlineScripts: string[]; // inline <script> bodies (bounded)
  links: string[];
  forms: FormInfo[];
  apiEndpoints: string[];

  tls: TlsEvidence;
  tlsMatrix: TlsMatrix | null; // protocol/cipher enumeration (DEEP)
  dns: DnsEvidence;
  cnames: string[]; // CNAME chain for the host (subdomain-takeover analysis)
  graphql: GraphqlEvidence | null; // GraphQL introspection probe result
  robotsDisallow: string[]; // paths hidden by robots.txt Disallow (probed)

  methods: Record<string, number>; // HTTP method -> observed status
  allowHeader: string; // value of the Allow header on OPTIONS, if any

  cors: CorsEvidence | null; // result of an Origin-reflection probe

  httpRoot: PageEvidence | null; // plain-HTTP root (for redirect enforcement)
  redirectsToHttps: boolean;

  paths: Record<string, ProbeEvidence>; // probed path -> result (keyed by path)

  // Active-probe results keyed by check id, so injection checks stay pure.
  probes: Record<string, ActiveProbeResult[]>;

  budget: RequestBudget;
}

export interface ActiveProbeResult {
  location: string;
  confidence: Confidence;
  evidence: string;
  param?: string;
}

// ---------------------------------------------------------------------------
// Check + outcome
// ---------------------------------------------------------------------------

export type CheckStatus = "fail" | "pass" | "na";

export interface CheckOutcome {
  status: CheckStatus;
  // Present on "fail": the raw proof, the exact location, and confidence.
  evidence?: string;
  location?: string;
  confidence?: Confidence;
  severity?: Severity; // override the check's default severity for this outcome
  titleSuffix?: string; // e.g. " — «sessionid»" for per-cookie findings
  detail?: string; // extra description appended after the KB text
}

export interface Check {
  id: string;
  category: CheckCategory;
  title: string;
  severity: Severity;
  cwe?: string;
  owasp?: string;
  description: string;
  remediation: string;
  references?: string[];
  confidence?: Confidence; // default confidence for a failing outcome
  // Which profiles this check is meaningful for. Passive checks run on all;
  // active/expensive checks are gated. Omitted → all profiles.
  profiles?: ScanProfile[];
  // Returns null/[] when the check does not apply. A single outcome or many
  // (per-cookie, per-script, per-endpoint). Must be a pure function of `ev`.
  evaluate(ev: Evidence): CheckOutcome | CheckOutcome[] | null;
}

// A produced finding (a failing outcome joined with its check metadata).
export interface CatalogFinding {
  checkId: string;
  category: CheckCategory;
  title: string;
  severity: Severity;
  cwe?: string;
  owasp?: string;
  location: string;
  description: string;
  evidence?: string;
  remediation: string;
  references?: string[];
  confidence: Confidence;
}

export interface Coverage {
  total: number; // checks evaluated
  passed: number; // verified-good
  failed: number; // produced ≥1 finding
  notApplicable: number;
  byCategory: Record<string, { run: number; passed: number; failed: number }>;
}
