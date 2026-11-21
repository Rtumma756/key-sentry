// Pillar 2 — vibe-code security scanner, TypeScript side.
//
// Server-only module (imports node:crypto for fingerprints / audit
// hashes). It mirrors ~/workspace/ai-key-scanner/vibe_checks.py — the
// SAME check ids, titles, and severities, so Python CLI reports and
// web reports agree. Keep both in sync.
//
// Secret detection does NOT hard-code regexes here: scanTextWithPatterns
// takes its patterns from lib/detector-patterns.json (generated from the
// Python registry by scripts/export_detector_patterns.py — the Python
// registry is canonical). The vibe config checks below are the TS port
// of ONLY those checks.
//
// Masking: prefix4 only, fingerprints are SHA-256 first-16-hex. A raw
// secret never leaves this module in a finding.

import { createHash } from "node:crypto";

export type VibeSeverity = "critical" | "high" | "medium" | "low";

export interface VibeFinding {
  id: string;
  title: string;
  severity: VibeSeverity;
  file: string;
  line: number;
  evidence: string;
  fix: string;
  masked: string | null;
  fingerprint: string | null;
  provider: string | null;
  confidence: number | null;
}

export interface DetectorPattern {
  provider: string;
  cred_type: string;
  pattern: string | null;
  console_url: string;
  severity: "high" | "medium";
  requires_context: string | null;
}

export interface SecretMatch {
  provider: string;
  credType: string;
  value: string;
  start: number;
  end: number;
  consoleUrl: string;
  severity: "high" | "medium";
  via: "regex" | "context" | "entropy";
}

// ---------------------------------------------------------------------------
// Masking + fingerprints (prefix4 only)
// ---------------------------------------------------------------------------

export function maskKey(value: string): string {
  return value.slice(0, 4) + "…";
}

export function fingerprintOf(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex").slice(0, 16);
}

function safeEvidence(line: string, matches: SecretMatch[]): string {
  let evidence = line.trim();
  for (const m of matches) {
    evidence = evidence.split(m.value).join(maskKey(m.value));
  }
  if (evidence.length > 160) evidence = evidence.slice(0, 160) + "…";
  return evidence;
}

// ---------------------------------------------------------------------------
// Example / test-key filter — port of detectors/registry.py is_example_key.
// Never weaken: a marked value is not a real leak.
// ---------------------------------------------------------------------------

const EXAMPLE_MARKER_SUBSTRINGS = [
  "testfake", "demofake", "deadbeef",
  "example", "changeme", "placeholder", "redacted", "sample", "dummy",
  "changethis",
];
const EXAMPLE_WORD_TOKENS = [
  "test", "fake", "demo", "mock", "xxx", "none", "null", "todo",
  "insert", "replace", "your", "here",
];
const EXAMPLE_TEST_KEY_PREFIXES = [
  "sk_test_", "pk_test_", "rk_test_", "sk-test-", "-test-", "_test_",
];
const EXAMPLE_WORD_RE = new RegExp(
  "(?:^|[^a-z0-9])(" + EXAMPLE_WORD_TOKENS.join("|") + ")(?:[^a-z0-9]|$)",
  "i",
);

export function isExampleKey(value: string): boolean {
  if (!value) return false;
  const lowered = value.toLowerCase();
  if (EXAMPLE_MARKER_SUBSTRINGS.some((m) => lowered.includes(m))) return true;
  if (EXAMPLE_TEST_KEY_PREFIXES.some((p) => lowered.includes(p))) return true;
  return EXAMPLE_WORD_RE.test(value);
}

// ---------------------------------------------------------------------------
// Secret scanning from generated patterns (port of detectors.scan_line)
// ---------------------------------------------------------------------------

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const ENTROPY_THRESHOLD = 4.5;
const MIN_GENERIC_LENGTH = 16;

const PLACEHOLDER_WORDS = [
  "test", "fake", "example", "placeholder", "your-", "xxx", "dummy",
  "sample", "replace", "changeme", "todo", "none", "null", "redacted",
  "insert", "here", "demo",
];

const CONTEXT_PROVIDERS: Array<[string, string, string, string]> = [
  ["mistral", "Mistral", "API key (entropy-detected)", "https://console.mistral.ai/api-keys"],
  ["cohere", "Cohere", "API key (entropy-detected)", "https://dashboard.cohere.com/api-keys"],
  ["together", "Together AI", "API key (entropy-detected)", "https://api.together.ai/settings/api-keys"],
  ["openai", "OpenAI", "API key (entropy-detected)", "https://platform.openai.com/api-keys"],
  ["anthropic", "Anthropic", "API key (entropy-detected)", "https://console.anthropic.com/settings/keys"],
  ["gemini", "Google Gemini", "API key (entropy-detected)", "https://aistudio.google.com/api-keys"],
  ["google", "Google Gemini", "API key (entropy-detected)", "https://aistudio.google.com/api-keys"],
  ["groq", "Groq", "API key (entropy-detected)", "https://console.groq.com/keys"],
  ["openrouter", "OpenRouter", "API key (entropy-detected)", "https://openrouter.ai/keys"],
  ["deepseek", "DeepSeek", "API key (entropy-detected)", "https://platform.deepseek.com/api_keys"],
  ["xai", "xAI", "API key (entropy-detected)", "https://console.x.ai/"],
  ["perplexity", "Perplexity", "API key (entropy-detected)", "https://www.perplexity.ai/settings/api"],
  ["hugging", "Hugging Face", "API token (entropy-detected)", "https://huggingface.co/settings/tokens"],
  ["replicate", "Replicate", "API token (entropy-detected)", "https://replicate.com/account/api-tokens"],
];

const FALLBACK_RE =
  /(api[_-]?key|apikey|access[_-]?token|secret|password|passwd|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{16,})/gi;

function resolveOverlaps(matches: SecretMatch[]): SecretMatch[] {
  const ordered = [...matches].sort(
    (a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start),
  );
  const kept: SecretMatch[] = [];
  for (const m of ordered) {
    if (kept.some((k) => !(m.end <= k.start || m.start >= k.end))) continue;
    kept.push(m);
  }
  return kept;
}

function classifyContext(line: string): [string, string, string] {
  const low = line.toLowerCase();
  for (const [keyword, provider, credType, consoleUrl] of CONTEXT_PROVIDERS) {
    if (low.includes(keyword)) return [provider, credType, consoleUrl];
  }
  return ["Unknown (generic)", "Generic API key/token", ""];
}

function entropyFallback(line: string): SecretMatch | null {
  const re = new RegExp(FALLBACK_RE.source, "gi");
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) {
    const value = m[2].replace(/["' ]/g, "");
    if (value.length < MIN_GENERIC_LENGTH) continue;
    if (isExampleKey(value)) continue;
    const lowered = value.toLowerCase();
    if (PLACEHOLDER_WORDS.some((w) => lowered.includes(w))) continue;
    if (shannonEntropy(value) < ENTROPY_THRESHOLD) continue;
    const [provider, credType, consoleUrl] = classifyContext(line);
    const start = m.index + m[0].indexOf(m[2]);
    return {
      provider, credType, value, start, end: start + value.length,
      consoleUrl, severity: "medium", via: "entropy",
    };
  }
  return null;
}

/** Scan one line using patterns from detector-patterns.json. */
export function scanLineWithPatterns(
  line: string,
  patterns: DetectorPattern[],
): SecretMatch[] {
  const matches: SecretMatch[] = [];
  const low = line.toLowerCase();
  for (const det of patterns) {
    if (det.pattern === null) continue;
    if (det.requires_context && !low.includes(det.requires_context)) continue;
    const re = new RegExp(det.pattern, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
      const value = m[0];
      if (isExampleKey(value)) continue;
      matches.push({
        provider: det.provider,
        credType: det.cred_type,
        value,
        start: m.index,
        end: m.index + value.length,
        consoleUrl: det.console_url,
        severity: det.severity,
        via: det.requires_context ? "context" : "regex",
      });
      if (value.length === 0) re.lastIndex++;
    }
  }
  const resolved = resolveOverlaps(matches);
  if (resolved.length === 0) {
    const fallback = entropyFallback(line);
    if (fallback) resolved.push(fallback);
  }
  return resolved;
}

// ---------------------------------------------------------------------------
// Vibe config checks — TS port of vibe_checks.py (same ids/titles/severities)
// ---------------------------------------------------------------------------

function finding(
  id: string, title: string, severity: VibeSeverity,
  file: string, line: number, evidence: string, fix: string,
): VibeFinding {
  return {
    id, title, severity, file, line, evidence, fix,
    masked: null, fingerprint: null, provider: null, confidence: null,
  };
}

function baseName(path: string): string {
  return path.split("/").pop() ?? path;
}

function isEnvFile(path: string): boolean {
  const base = baseName(path);
  return base === ".env" || base.startsWith(".env.");
}

const FIREBASE_ALLOW_RE =
  /allow\s+(read|write|read\s*,\s*write|write\s*,\s*read)\s*:\s*if\s+true\b/i;

const NO_AUTH_URI_RE =
  /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb):\/\/(?!([^/\s:@]+):([^/\s:@]+)@)[^/\s@]+\//i;

const PUBLIC_STORAGE_RES = [
  /public[\s_-]?read\b/i,
  /"?public"?\s*:\s*true/i,
  /acl\s*[:=]\s*["']?public-read["']?/i,
];

const AUTH_WORDS = [
  "auth", "verifytoken", "requireauth", "authenticate", "jwt",
  "session", "middleware", "protected", "isauthenticated", "checkauth",
  "authorize", "permission", "apikey", "api-key",
];
const HANDLER_RES = [
  /export\s+(default\s+)?(async\s+)?function\s+\w*/,
  /export\s+default\s+/,
  /\b(app|router)\.(get|post|put|patch|delete|all)\s*\(/,
  /export\s+(const|async)\s+\w+\s*=\s*(async\s*)?\(/,
];

const CORS_RES = [
  /access-control-allow-origin\s*[:=]\s*["']?\*/i,
  /origin\s*:\s*["']\*+["']/i,
  /allow_origins\s*=\s*\[[\"']\*+[\"']\]/i,
  /allow_all_origins\s*=\s*true/i,
];

const PRIVATE_IP_RE =
  /https?:\/\/(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[0-9.]+(?::\d+)?(?:\/[^\s"']*)?/;

/** Run every vibe config check over one file's text. */
export function checkVibeFile(path: string, text: string): VibeFinding[] {
  const lines = text.split("\n");
  const findings: VibeFinding[] = [];
  const base = baseName(path).toLowerCase();

  // (b) committed .env / env files
  if (isEnvFile(path) && base !== ".env.example" && base !== ".env.sample") {
    findings.push(finding(
      "vibe-env-committed",
      "Committed .env file — secrets may be in git history",
      "high", path, 0, base,
      "Your app's secret settings file is saved in the project, so " +
      "anyone who can see the code can see the secrets. Move the " +
      "secrets into your hosting provider's settings (for example " +
      "Vercel → Settings → Environment Variables), delete the file " +
      "from the project, and add .env to .gitignore.",
    ));
  }

  // (c) Firebase open rules
  const isRulesFile =
    ["firestore.rules", "database.rules.json", "storage.rules", "firebase.json"].includes(base) ||
    base.endsWith(".rules");
  if (isRulesFile) {
    lines.forEach((line, idx) => {
      if (FIREBASE_ALLOW_RE.test(line)) {
        findings.push(finding(
          "vibe-firebase-open-rules",
          "Firebase rule lets anyone read or write your database",
          "critical", path, idx + 1, safeEvidence(line, []),
          "Your database is open to anyone on the internet. In the " +
          "Firebase console → Rules, change 'allow read: if true' " +
          "(and 'allow write: if true') to a rule that only lets " +
          "signed-in users in, for example " +
          "'allow read, write: if request.auth != null'.",
        ));
      }
    });
  }

  // (c) DB connection strings without auth + storage-public + CORS + IPs
  const isStorageFile =
    ["firebase.json", "storage.rules", "s3.json", "bucket.json", "terraform.tf", "main.tf"].includes(base) ||
    base.endsWith(".tf") || base.includes("storage") || base.includes("bucket");
  lines.forEach((line, idx) => {
    if (NO_AUTH_URI_RE.test(line)) {
      findings.push(finding(
        "vibe-db-no-auth",
        "Database connection has no username or password",
        "high", path, idx + 1, safeEvidence(line, []),
        "Your app connects to its database without a username or " +
        "password, so anyone who finds the address can open it. " +
        "In your database provider's dashboard, create a database " +
        "user with a strong password and put the full connection " +
        "address (with that username and password) in your " +
        "hosting provider's secret settings — never in the code.",
      ));
    }
    if (isStorageFile && PUBLIC_STORAGE_RES.some((rx) => rx.test(line)) && !FIREBASE_ALLOW_RE.test(line)) {
      findings.push(finding(
        "vibe-storage-public",
        "Storage bucket is set to public read",
        "high", path, idx + 1, safeEvidence(line, []),
        "Your file storage is set so anyone on the internet can " +
        "read the files in it. In your storage provider's " +
        "settings, turn off public access and only let signed-in " +
        "users (or signed links) open files.",
      ));
    }
    if (CORS_RES.some((rx) => rx.test(line))) {
      findings.push(finding(
        "vibe-cors-wildcard",
        "Any website may call your API (CORS allows *)",
        "medium", path, idx + 1, safeEvidence(line, []),
        "Your app tells browsers that any website on the internet " +
        "may call its API. Change the allowed website list to " +
        "just your own site's address (for example " +
        "https://your-app.com) instead of '*'.",
      ));
    }
    if (PRIVATE_IP_RE.test(line)) {
      findings.push(finding(
        "vibe-hardcoded-internal-url",
        "Hardcoded internal address in the code",
        "low", path, idx + 1, safeEvidence(line, []),
        "The code contains a private network address (something " +
        "like 192.168.x.x) that only works inside one office or " +
        "home network. Move the address into your hosting " +
        "provider's settings so the app works everywhere and the " +
        "internal address is not published with the code.",
      ));
    }
  });

  // (d) HEURISTIC: API route with no auth reference (one finding per file)
  const lowPath = path.replace(/\\/g, "/").toLowerCase();
  const isApiFile =
    lowPath.includes("/api/") || lowPath.includes("/routes/") ||
    lowPath.startsWith("api/") || lowPath.startsWith("routes/") ||
    base.includes("route.") || base.includes("handler");
  if (isApiFile && /\.(js|jsx|ts|tsx|py)$/.test(base)) {
    const hasHandler = HANDLER_RES.some((rx) => rx.test(text));
    if (hasHandler) {
      const squashed = text.toLowerCase().replace(/[^a-z0-9]+/g, "");
      const hasAuth = AUTH_WORDS.some((w) => squashed.includes(w));
      if (!hasAuth) {
        let firstHandler = 0;
        for (let i = 0; i < lines.length; i++) {
          if (HANDLER_RES.some((rx) => rx.test(lines[i]))) { firstHandler = i + 1; break; }
        }
        findings.push(finding(
          "vibe-api-no-auth",
          "API route shows no sign-in check (heuristic — please verify)",
          "medium", path, firstHandler, base,
          "This check is only a heuristic guess: it could not see any sign-in check " +
          "in this API file, so the endpoint may be open to anyone. Ask " +
          "your developer (or the AI tool that built the app) to confirm " +
          "the endpoint checks that the caller is signed in before it " +
          "returns or changes any data.",
        ));
      }
    }
  }

  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort(
    (a, b) => order[a.severity] - order[b.severity] ||
      a.file.localeCompare(b.file) || a.line - b.line,
  );
  return findings;
}

/** Scan one file's text for leaked secrets (patterns from JSON). */
export function scanVibeFileSecrets(
  path: string,
  text: string,
  patterns: DetectorPattern[],
): VibeFinding[] {
  const findings: VibeFinding[] = [];
  const seen = new Set<string>();
  text.split("\n").forEach((line, idx) => {
    for (const m of scanLineWithPatterns(line, patterns)) {
      if (seen.has(m.value)) continue;
      seen.add(m.value);
      findings.push({
        id: "vibe-leaked-secret",
        title: `Leaked ${m.provider} ${m.credType}`,
        severity: m.severity,
        file: path,
        line: idx + 1,
        evidence: safeEvidence(line, [m]),
        fix:
          "This secret key is visible in the code — anyone who sees the " +
          "project can copy it and use it as you. Revoke it now at " +
          `${m.consoleUrl || "the provider console"} and issue a new one, ` +
          "then take it out of the code (and out of git history) and " +
          "store the new key in your hosting provider's secret " +
          "settings instead.",
        masked: maskKey(m.value),
        fingerprint: fingerprintOf(m.value),
        provider: m.provider,
        confidence: null,
      });
    }
  });
  return findings;
}

// ---------------------------------------------------------------------------
// Repo URL validation — public GitHub only
// ---------------------------------------------------------------------------

/**
 * Accept "owner/repo" or a full https://github.com/owner/repo URL.
 * Reject anything else: other hosts, extra path segments (e.g. /tree/...),
 * ssh URLs, and empty input. A URL with extra segments looks private or
 * is not a repo root, so it is rejected rather than guessed at.
 */
export function parseVibeRepoUrl(
  input: string,
): { owner: string; repo: string } | null {
  const trimmed = input.trim().replace(/\/$/, "");
  if (!trimmed) return null;
  const full = trimmed.match(
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/,
  );
  if (full) return { owner: full[1], repo: full[2] };
  const short = trimmed.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  // Bare owner/repo: reject when the owner looks like a domain
  // ("example.com/foo" is not a repo slug).
  if (short && !short[1].includes(".")) return { owner: short[1], repo: short[2] };
  return null;
}

// ---------------------------------------------------------------------------
// Audit events (Pillar 3 schema) — field names byte-for-byte per spec
// ---------------------------------------------------------------------------

export interface VibeAuditEvent {
  event_id: string;
  event_type: "vibe.finding";
  timestamp: string;
  prev_hash: string;
  event_hash: string;
  principal_id: "anonymous";
  parent_agent_id: null;
  session_id: string;
  policy_id: "vibe-scan";
  ticket_of_record: null;
  model_run_id: null;
  agent_id: "vibe-scanner";
  agent_version: "0.1.0";
  model: null;
  tool: "vibe-scan";
  resource: string;
  arg_keys: ["repoUrl"];
  decision: { allow: true; policy: "vibe-scan"; reason: "public repo scan" };
  outcome: "success";
  correlation_id: string;
}

/** Canonical JSON: sorted keys, no spaces, recursive. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalJson(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

function randomUuid(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * One event per finding, hash-chained within the report (first event is
 * genesis: prev_hash is 64 zeros). Never includes file contents or
 * secret values — arg_keys and the repo URL only.
 */
export function buildVibeAuditEvents(
  findingCount: number,
  repoUrl: string,
  reportId: string,
): VibeAuditEvent[] {
  const events: VibeAuditEvent[] = [];
  let prev = "0".repeat(64);
  for (let i = 0; i < findingCount; i++) {
    const withoutHash: Omit<VibeAuditEvent, "event_hash"> = {
      event_id: randomUuid(),
      event_type: "vibe.finding",
      timestamp: new Date().toISOString(),
      prev_hash: prev,
      principal_id: "anonymous",
      parent_agent_id: null,
      session_id: reportId,
      policy_id: "vibe-scan",
      ticket_of_record: null,
      model_run_id: null,
      agent_id: "vibe-scanner",
      agent_version: "0.1.0",
      model: null,
      tool: "vibe-scan",
      resource: repoUrl,
      arg_keys: ["repoUrl"],
      decision: { allow: true, policy: "vibe-scan", reason: "public repo scan" },
      outcome: "success",
      correlation_id: reportId,
    };
    const eventHash = createHash("sha256")
      .update(canonicalJson(withoutHash) + prev, "utf-8")
      .digest("hex");
    events.push({ ...withoutHash, event_hash: eventHash });
    prev = eventHash;
  }
  return events;
}

/** Recompute the chain; true only when every hash links correctly. */
export function verifyVibeAuditChain(events: VibeAuditEvent[]): boolean {
  let prev = "0".repeat(64);
  for (const event of events) {
    if (event.prev_hash !== prev) return false;
    const { event_hash, ...rest } = event;
    const expected = createHash("sha256")
      .update(canonicalJson(rest) + prev, "utf-8")
      .digest("hex");
    if (expected !== event_hash) return false;
    prev = event_hash;
  }
  return true;
}
