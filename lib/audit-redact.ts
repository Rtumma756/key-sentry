// Audit-event schema + redaction, TypeScript mirror of the CLI
// (ai-key-scanner/audit/schema.py + audit/redact.py). Keep the two in
// sync: same EVENT_FIELDS, same hash formula, same redaction rules.
//
// Hash chain: event_hash = sha256_hex(canonical_json(event WITHOUT
// event_hash) + prev_hash), canonical_json = JSON with sorted keys and
// no whitespace. Genesis prev_hash is "0" * 64.
//
// Redaction runs BEFORE write (allowlist approach): only EVENT_FIELDS
// may be stored, argument VALUES are never stored (only key names in
// arg_keys), and free-text fields are scrubbed of secret-looking
// substrings. Validation is the backstop and rejects anything that
// still looks secret — including a secret split across fields.
//
// This file imports only node:crypto, so it can be unit-tested without
// a database (tests/audit.test.mjs). It must never be imported by
// client components — the page talks to the API routes instead.

import { createHash, randomUUID } from "node:crypto";

export const SCHEMA_VERSION = 1;
export const GENESIS_PREV_HASH = "0".repeat(64);
export const REDACTED = "[REDACTED]";

export const EVENT_FIELDS = [
  "event_id",
  "event_type",
  "timestamp",
  "prev_hash",
  "event_hash",
  "principal_id",
  "parent_agent_id",
  "session_id",
  "policy_id",
  "ticket_of_record",
  "model_run_id",
  "agent_id",
  "agent_version",
  "model",
  "tool",
  "resource",
  "arg_keys",
  "decision",
  "outcome",
  "correlation_id",
  "confidence",
] as const;

export const OUTCOMES = ["success", "denied", "error"] as const;

/** Fields whose values are hex digests by construction; excluded from
 * the cross-field secret scan. */
export const DIGEST_FIELDS = new Set(["event_id", "prev_hash", "event_hash"]);

export type AuditEvent = Record<string, unknown>;

/** The one canonical serialisation: sorted keys, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const s = JSON.stringify(value);
    return s === undefined ? "null" : s;
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalJson(v)).join(",") + "]";
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalJson(record[k]))
      .join(",") +
    "}"
  );
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** sha256 of canonical_json(event WITHOUT event_hash) + prev_hash.
 * `eventWithoutHash` must already include `prev_hash` as a field. */
export function computeEventHash(
  eventWithoutHash: AuditEvent,
  prevHash: string,
): string {
  return sha256Hex(canonicalJson(eventWithoutHash) + prevHash);
}

export function utcnowIso(): string {
  return new Date().toISOString();
}

// --- Secret detection (mirrors detectors/registry.py) -------------------

const PROVIDER_PATTERNS: RegExp[] = [
  /sk-proj-[A-Za-z0-9_-]{20,}/,
  /sk-svcacct-[A-Za-z0-9_-]{20,}/,
  /sk-(?!proj-|svcacct-|or-v1-|ant-)[A-Za-z0-9]{48}/,
  /sk-ant-api03-[A-Za-z0-9_-]{20,}/,
  /AIza[0-9A-Za-z\-_]{35}/,
  /gsk_[A-Za-z0-9]{20,}/,
  /sk-or-v1-[A-Za-z0-9]{32,}/,
  /sk-[a-f0-9]{32}(?![A-Za-z0-9])/,
  /xai-[A-Za-z0-9]{20,}/,
  /pplx-[A-Za-z0-9]{20,}/,
  /hf_[A-Za-z0-9]{20,}/,
  /r8_[A-Za-z0-9]{20,}/,
  // Together AI: 64 hex, only when the provider name is in the text.
  /(?<![A-Za-z0-9])[a-f0-9]{64}(?![A-Za-z0-9])/,
];

const FALLBACK_RE =
  /(api[_-]?key|apikey|access[_-]?token|secret|password|passwd|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{16,})["']?/i;

const TOKEN_RE = /[A-Za-z0-9_\-./+=]{16,}/g;
export const ENTROPY_THRESHOLD = 4.5;

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

/** Provider-pattern hits only (no generic entropy heuristic). Used for
 * the cross-field fused check: fusing fields without a separator
 * merges neighbouring values into one long token, which would trip the
 * entropy heuristic on innocent data. */
export function findPatternHits(text: string): string[] {
  if (!text) return [];
  const hits: string[] = [];
  for (const re of PROVIDER_PATTERNS) {
    // The 64-hex Together pattern is context-gated (last in the list).
    if (re === PROVIDER_PATTERNS[PROVIDER_PATTERNS.length - 1]) {
      if (!text.toLowerCase().includes("together")) continue;
    }
    const m = text.match(new RegExp(re.source, "g"));
    if (m) hits.push(...m);
  }
  const fallback = FALLBACK_RE.exec(text);
  if (fallback && fallback[2]) {
    const value = fallback[2];
    if (shannonEntropy(value) >= ENTROPY_THRESHOLD) hits.push(value);
  }
  return [...new Set(hits)];
}

/** Secret-looking substrings: provider patterns + the generic
 * high-entropy token heuristic. Example/test keys are NOT exempt here:
 * an audit log must not carry credential-shaped values at all. */
export function findSecretHits(text: string): string[] {
  if (!text) return [];
  const hits = findPatternHits(text);
  for (const token of text.match(TOKEN_RE) ?? []) {
    if (hits.includes(token)) continue;
    if (shannonEntropy(token) >= ENTROPY_THRESHOLD) hits.push(token);
  }
  return hits;
}

export function containsSecret(text: string): boolean {
  return findSecretHits(text).length > 0;
}

/** Replace every secret-looking substring with [REDACTED]. */
export function scrubText(text: string): string {
  if (!text) return text;
  const hits = [...new Set(findSecretHits(text))].sort(
    (a, b) => b.length - a.length,
  );
  let out = text;
  for (const hit of hits) out = out.split(hit).join(REDACTED);
  return out;
}

// --- Redaction -----------------------------------------------------------

function argKeysFrom(raw: Record<string, unknown>): string[] {
  const keys: string[] = [];
  for (const field of ["arg_keys", "args", "arguments"]) {
    const value = raw[field];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      keys.push(...Object.keys(value as Record<string, unknown>));
    } else if (Array.isArray(value)) {
      keys.push(...value.map((k) => String(k)));
    }
  }
  return [...new Set(keys)];
}

/** Build a storable event from untrusted input. Only allowlisted
 * schema fields survive; `args`/`arguments` contribute KEY NAMES only;
 * free-text fields are scrubbed; `event_hash`/`prev_hash` are never
 * accepted from input (the chain sets them); `event_id`/`timestamp`
 * are server-assigned when absent (uuid4 hex id, current UTC time). */
export function redactAuditEvent(raw: unknown): AuditEvent {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("event must be a JSON object");
  }
  const input = raw as Record<string, unknown>;
  const event: AuditEvent = {};
  for (const f of EVENT_FIELDS) {
    if (f === "event_hash" || f === "prev_hash") continue;
    if (f === "event_id") {
      event["event_id"] =
        typeof input["event_id"] === "string" && input["event_id"]
          ? input["event_id"]
          : randomUUID().replaceAll("-", "");
      continue;
    }
    if (f === "timestamp") {
      event["timestamp"] =
        typeof input["timestamp"] === "string" && input["timestamp"]
          ? input["timestamp"]
          : utcnowIso();
      continue;
    }
    if (f === "arg_keys") {
      event["arg_keys"] = argKeysFrom(input);
      continue;
    }
    if (f === "decision") {
      const decision =
        input["decision"] && typeof input["decision"] === "object"
          ? (input["decision"] as Record<string, unknown>)
          : {};
      let reason = decision["reason"];
      if (!reason && typeof input["error"] === "string") reason = input["error"];
      else if (!reason && typeof input["error_message"] === "string") {
        reason = input["error_message"];
      }
      event["decision"] = {
        allow: Boolean(decision["allow"] ?? true),
        policy: scrubText(String(decision["policy"] ?? "")),
        reason: scrubText(String(reason ?? "")),
      };
      continue;
    }
    if (f === "confidence") {
      const c = input["confidence"];
      event["confidence"] =
        typeof c === "number" && Number.isFinite(c) ? c : null;
      continue;
    }
    const value = input[f];
    event[f] = typeof value === "string" ? scrubText(value) : (value ?? "");
  }
  return event;
}

// --- Validation (backstop after redaction) -------------------------------

const HEX_32 = /^[0-9a-f]{32}$/;
const HEX_64 = /^[0-9a-f]{64}$/;

/** Validate an event dict. Returns error strings (empty = valid). */
export function validateAuditEvent(event: unknown): string[] {
  const errors: string[] = [];
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    return ["event must be a JSON object"];
  }
  const e = event as Record<string, unknown>;
  for (const f of EVENT_FIELDS) {
    if (f === "event_hash") continue;
    if (!(f in e)) errors.push(`missing required field: ${f}`);
  }
  if (errors.length > 0) return errors;

  if (typeof e["event_id"] !== "string" || !HEX_32.test(e["event_id"])) {
    errors.push("event_id must be a 32-char lowercase hex string (uuid4 hex)");
  }
  if (typeof e["event_type"] !== "string" || !e["event_type"]) {
    errors.push("event_type must be a non-empty string");
  }
  if (typeof e["timestamp"] !== "string" || Number.isNaN(Date.parse(e["timestamp"]))) {
    errors.push("timestamp must be an ISO-8601 string");
  }
  if (typeof e["prev_hash"] !== "string" || !HEX_64.test(e["prev_hash"])) {
    errors.push("prev_hash must be a 64-char lowercase hex string");
  }
  if (
    e["event_hash"] !== undefined &&
    e["event_hash"] !== "" &&
    e["event_hash"] !== null &&
    (typeof e["event_hash"] !== "string" || !HEX_64.test(e["event_hash"]))
  ) {
    errors.push("event_hash must be a 64-char lowercase hex string");
  }
  for (const f of [
    "principal_id",
    "parent_agent_id",
    "session_id",
    "policy_id",
    "ticket_of_record",
    "model_run_id",
    "agent_id",
    "agent_version",
    "model",
    "tool",
    "resource",
    "correlation_id",
  ]) {
    if (typeof e[f] !== "string") errors.push(`${f} must be a string`);
  }
  if (
    !Array.isArray(e["arg_keys"]) ||
    !e["arg_keys"].every((k) => typeof k === "string")
  ) {
    errors.push("arg_keys must be a list of strings");
  }
  const decision = e["decision"];
  if (!decision || typeof decision !== "object" || Array.isArray(decision)) {
    errors.push("decision must be an object");
  } else {
    const d = decision as Record<string, unknown>;
    if (typeof d["allow"] !== "boolean") {
      errors.push("decision.allow must be a boolean");
    }
    if (typeof d["policy"] !== "string") {
      errors.push("decision.policy must be a string");
    }
    if (typeof d["reason"] !== "string") {
      errors.push("decision.reason must be a string");
    }
  }
  if (!OUTCOMES.includes(e["outcome"] as (typeof OUTCOMES)[number])) {
    errors.push(`outcome must be one of ${OUTCOMES.join(", ")}`);
  }
  const confidence = e["confidence"];
  if (
    confidence !== null &&
    confidence !== undefined &&
    (typeof confidence !== "number" ||
      confidence < 0 ||
      confidence > 1)
  ) {
    errors.push("confidence must be null or a number between 0.0 and 1.0");
  }

  // Secret backstop: per-field scan, plus the fused cross-field scan
  // (patterns only) for a secret split across fields.
  for (const f of EVENT_FIELDS) {
    if (DIGEST_FIELDS.has(f)) continue;
    const value = e[f];
    if (typeof value === "string" && findSecretHits(value).length > 0) {
      errors.push(`field ${f} contains a secret-looking value`);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string" && findSecretHits(item).length > 0) {
          errors.push(`field ${f} contains a secret-looking value`);
          break;
        }
      }
    } else if (value && typeof value === "object") {
      for (const item of Object.values(value as Record<string, unknown>)) {
        if (typeof item === "string" && findSecretHits(item).length > 0) {
          errors.push(`field ${f} contains a secret-looking value`);
          break;
        }
      }
    }
  }
  const parts: string[] = [];
  for (const f of EVENT_FIELDS) {
    if (DIGEST_FIELDS.has(f)) continue;
    const value = e[f];
    if (typeof value === "string") parts.push(value);
    else if (Array.isArray(value)) {
      parts.push(...value.map((x) => String(x)));
    } else if (value && typeof value === "object") {
      parts.push(...Object.values(value as Record<string, unknown>).map((x) => String(x)));
    }
  }
  if (findPatternHits(parts.join("")).length > 0) {
    errors.push("event carries a secret-looking value split across fields");
  }
  return errors;
}

/** Recompute a chain held in memory. Mirrors audit/chain.py. */
export function verifyEvents(events: AuditEvent[]): {
  ok: boolean;
  count: number;
  firstBadIndex: number | null;
  continuedFromArchive: boolean;
  events: {
    index: number;
    eventId: unknown;
    ok: boolean;
    error: string | null;
    continued: boolean;
  }[];
} {
  const results: {
    index: number;
    eventId: unknown;
    ok: boolean;
    error: string | null;
    continued: boolean;
  }[] = [];
  let firstBad: number | null = null;
  let prevHash = GENESIS_PREV_HASH;
  let continued = false;
  events.forEach((event, index) => {
    let ok = true;
    let error: string | null = null;
    const storedHash = event["event_hash"];
    const eventPrev = event["prev_hash"];
    if (index === 0) {
      if (eventPrev === GENESIS_PREV_HASH) {
        // genesis
      } else if (typeof eventPrev === "string" && eventPrev.length === 64) {
        continued = true; // chain continues from an archived segment
      } else {
        ok = false;
        error = "first event prev_hash is neither genesis nor a hash";
      }
    } else if (eventPrev !== prevHash) {
      ok = false;
      error = `prev_hash does not match previous event_hash`;
    }
    if (ok) {
      const withoutHash: AuditEvent = {};
      for (const [k, v] of Object.entries(event)) {
        if (k !== "event_hash") withoutHash[k] = v;
      }
      const expected = computeEventHash(withoutHash, String(eventPrev));
      if (expected !== storedHash) {
        ok = false;
        error = "event_hash does not recompute (event tampered)";
      }
    }
    if (!ok && firstBad === null) firstBad = index;
    results.push({
      index,
      eventId: event["event_id"],
      ok,
      error,
      continued: continued && index === 0,
    });
    if (typeof storedHash === "string") prevHash = storedHash;
  });
  return {
    ok: firstBad === null,
    count: events.length,
    firstBadIndex: firstBad,
    continuedFromArchive: continued,
    events: results,
  };
}
