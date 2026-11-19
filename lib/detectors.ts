// Detector registry — TypeScript port of the CLI prototype's
// detectors/registry.py + detectors/entropy.py.
// Same patterns, same ordering, same overlap resolution, same entropy
// fallback (threshold 4.5). Regex matches are always kept; placeholder
// words only gate the entropy fallback, exactly like the Python version.

export const ENTROPY_THRESHOLD = 4.5;
export const MIN_GENERIC_LENGTH = 16;

const PLACEHOLDER_WORDS = [
  "test", "fake", "example", "placeholder", "your-", "xxx", "dummy",
  "sample", "replace", "changeme", "todo", "none", "null", "redacted",
  "insert", "here", "demo",
];

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = s.length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

export interface Detector {
  provider: string;
  credType: string;
  pattern: RegExp | null; // null = entropy/context only, no fixed format
  consoleUrl: string;
  severity: "high" | "medium";
  requiresContext?: string; // substring that must appear in the line
}

// Ordered so more specific prefixes win. Overlap resolution keeps the
// longest match at a given start position.
export const DETECTORS: Detector[] = [
  { provider: "OpenAI", credType: "API key (project)", pattern: /sk-proj-[A-Za-z0-9_-]{20,}/, consoleUrl: "https://platform.openai.com/api-keys", severity: "high" },
  { provider: "OpenAI", credType: "API key (service account)", pattern: /sk-svcacct-[A-Za-z0-9_-]{20,}/, consoleUrl: "https://platform.openai.com/api-keys", severity: "high" },
  { provider: "OpenAI", credType: "API key (legacy)", pattern: /sk-(?!proj-|svcacct-|or-v1-|ant-)[A-Za-z0-9]{48}/, consoleUrl: "https://platform.openai.com/api-keys", severity: "high" },
  { provider: "Anthropic", credType: "API key", pattern: /sk-ant-api03-[A-Za-z0-9_-]{20,}/, consoleUrl: "https://console.anthropic.com/settings/keys", severity: "high" },
  { provider: "Google Gemini", credType: "API key", pattern: /AIza[0-9A-Za-z\-_]{35}/, consoleUrl: "https://aistudio.google.com/api-keys", severity: "high" },
  { provider: "Groq", credType: "API key", pattern: /gsk_[A-Za-z0-9]{20,}/, consoleUrl: "https://console.groq.com/keys", severity: "high" },
  { provider: "OpenRouter", credType: "API key", pattern: /sk-or-v1-[A-Za-z0-9]{32,}/, consoleUrl: "https://openrouter.ai/keys", severity: "high" },
  { provider: "DeepSeek", credType: "API key", pattern: /sk-[a-f0-9]{32}(?![A-Za-z0-9])/, consoleUrl: "https://platform.deepseek.com/api_keys", severity: "high" },
  { provider: "xAI", credType: "API key", pattern: /xai-[A-Za-z0-9]{20,}/, consoleUrl: "https://console.x.ai/", severity: "high" },
  { provider: "Perplexity", credType: "API key", pattern: /pplx-[A-Za-z0-9]{20,}/, consoleUrl: "https://www.perplexity.ai/settings/api", severity: "high" },
  { provider: "Hugging Face", credType: "API token", pattern: /hf_[A-Za-z0-9]{20,}/, consoleUrl: "https://huggingface.co/settings/tokens", severity: "high" },
  { provider: "Replicate", credType: "API token", pattern: /r8_[A-Za-z0-9]{20,}/, consoleUrl: "https://replicate.com/account/api-tokens", severity: "high" },
  // No fixed prefix: caught only when the provider name is in the line.
  { provider: "Together AI", credType: "API key", pattern: /(?<![A-Za-z0-9])[a-f0-9]{64}(?![A-Za-z0-9])/, consoleUrl: "https://api.together.ai/settings/api-keys", severity: "medium", requiresContext: "together" },
  // Entropy-only providers (no regex): handled by the fallback classifier.
  { provider: "Mistral", credType: "API key (entropy-detected)", pattern: null, consoleUrl: "https://console.mistral.ai/api-keys", severity: "medium" },
  { provider: "Cohere", credType: "API key (entropy-detected)", pattern: null, consoleUrl: "https://dashboard.cohere.com/api-keys", severity: "medium" },
];

// Provider keywords used to classify entropy-fallback findings, in order.
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
  /(api[_-]?key|apikey|access[_-]?token|secret|password|passwd|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{16,})/i;

export interface RawMatch {
  provider: string;
  credType: string;
  value: string;
  start: number;
  end: number;
  consoleUrl: string;
  severity: "high" | "medium";
  via: "regex" | "context" | "entropy";
}

function resolveOverlaps(matches: RawMatch[]): RawMatch[] {
  const ordered = [...matches].sort(
    (a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start),
  );
  const kept: RawMatch[] = [];
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

function entropyFallback(line: string): RawMatch | null {
  const re = new RegExp(FALLBACK_RE.source, "gi");
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) {
    const value = m[2].replace(/["' ]/g, "");
    if (value.length < MIN_GENERIC_LENGTH) continue;
    const lowered = value.toLowerCase();
    if (PLACEHOLDER_WORDS.some((w) => lowered.includes(w))) continue;
    if (shannonEntropy(value) < ENTROPY_THRESHOLD) continue;
    const [provider, credType, consoleUrl] = classifyContext(line);
    return {
      provider,
      credType,
      value,
      start: m.index + m[0].indexOf(m[2]),
      end: m.index + m[0].indexOf(m[2]) + value.length,
      consoleUrl,
      severity: "medium",
      via: "entropy",
    };
  }
  return null;
}

/** Return all credential candidates found in one line of text. */
export function scanLine(line: string): RawMatch[] {
  const matches: RawMatch[] = [];
  const low = line.toLowerCase();
  for (const det of DETECTORS) {
    if (det.pattern === null) continue;
    if (det.requiresContext && !low.includes(det.requiresContext)) continue;
    const re = new RegExp(det.pattern.source, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
      matches.push({
        provider: det.provider,
        credType: det.credType,
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        consoleUrl: det.consoleUrl,
        severity: det.severity,
        via: det.requiresContext ? "context" : "regex",
      });
      // Guard against zero-length matches looping forever.
      if (m[0].length === 0) re.lastIndex++;
    }
  }
  const resolved = resolveOverlaps(matches);
  if (resolved.length === 0) {
    const fallback = entropyFallback(line);
    if (fallback) resolved.push(fallback);
  }
  return resolved;
}

export function providerNames(): string[] {
  const seen: string[] = [];
  for (const det of DETECTORS) {
    if (!seen.includes(det.provider)) seen.push(det.provider);
  }
  return seen;
}

/** Mask a credential for display. Modes: "prefix4" (default) shows the first 4
 * chars and hides the rest; "ends" hides the first 5 and last 3 chars and
 * shows the middle — that exposes most of a key, so use it only for keys the
 * viewer owns, never for strangers' keys in shared reports. */
export type MaskMode = "prefix4" | "ends";
export function maskKey(value: string, mode: MaskMode = "prefix4"): string {
  if (mode === "ends") {
    if (value.length <= 8) return "*".repeat(value.length);
    return "*".repeat(5) + value.slice(5, -3) + "*".repeat(3);
  }
  return value.slice(0, 4) + "…";
}

/** Mask every detected credential inside a line of text. */
export function maskLine(line: string, mode: MaskMode = "prefix4"): string {
  const matches = scanLine(line);
  if (matches.length === 0) return line;
  let out = "";
  let cursor = 0;
  for (const m of [...matches].sort((a, b) => a.start - b.start)) {
    out += line.slice(cursor, m.start) + maskKey(m.value, mode);
    cursor = m.end;
  }
  out += line.slice(cursor);
  return out;
}
