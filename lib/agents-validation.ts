// Pure validators for Pillar 1 agent registration (no imports, no DB).
// Kept separate from lib/agents-db.ts so these can be unit-tested with
// plain node (like tests/rate-limit.test.mjs) without pulling in the
// Postgres client. agents-db.ts re-exports them.

export interface AgentCredentialRow {
  provider: string;
  credentialType: string;
  fingerprint: string;
  masked: string;
  source: string;
  envVar: string;
}

export const MAX_AGENT_FIELD_LENGTH = 500;
export const MAX_CREDENTIALS_PER_AGENT = 100;

/** A fingerprint is exactly 16 lowercase hex chars (sha256 hex, first 16). */
export function isValidFingerprint(value: string): boolean {
  return /^[0-9a-f]{16}$/.test(value);
}

export function normalizeFingerprint(value: string): string {
  return value.trim().toLowerCase();
}

/** Trim a free-text agent field. Throws when it exceeds the limit. */
export function normalizeAgentField(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length > MAX_AGENT_FIELD_LENGTH) {
    throw new Error(
      `Agent field must be at most ${MAX_AGENT_FIELD_LENGTH} characters.`,
    );
  }
  return trimmed;
}

/**
 * Validate one credential record from a CLI registration payload.
 * Fingerprints, when present, must be 16 lowercase hex chars; masked
 * values must be prefix4 form ("xxxx...") or empty. Returns the
 * normalized record, or null when the record carries no usable
 * identity (no provider and no fingerprint and no env var).
 */
export function normalizeAgentCredential(
  raw: unknown,
): AgentCredentialRow | null {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw as Record<string, unknown>;
  const provider = typeof rec.provider === "string" ? rec.provider.trim() : "";
  const credentialType =
    typeof rec.credential_type === "string" ? rec.credential_type.trim() : "";
  const fingerprint =
    typeof rec.fingerprint === "string"
      ? normalizeFingerprint(rec.fingerprint)
      : "";
  const masked = typeof rec.masked === "string" ? rec.masked.trim() : "";
  const source = typeof rec.source === "string" ? rec.source.trim() : "";
  const envVar = typeof rec.env_var === "string" ? rec.env_var.trim() : "";
  if (fingerprint && !isValidFingerprint(fingerprint)) {
    throw new Error(
      "Credential fingerprint must be 16 lowercase hex chars " +
        "(SHA-256 of the key, first 16) — never send a raw key.",
    );
  }
  if (masked && !/^[ -~]{1,4}\.\.\.$/.test(masked)) {
    throw new Error("Masked value must be prefix4 form (first 4 chars + '...').");
  }
  if (!provider && !fingerprint && !envVar) return null;
  return { provider, credentialType, fingerprint, masked, source, envVar };
}
