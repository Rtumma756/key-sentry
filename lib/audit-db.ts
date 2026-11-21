// Agent audit trail store: Vercel Postgres (free tier, Neon-backed).
//
// One row per canonical audit event. The full event JSON is stored in
// `event_json` (already redacted + validated before insert — argument
// values never reach this table), with indexed columns for the timeline
// filters (agent_id / session_id / correlation_id) and the chain
// (event_hash / prev_hash).
//
// Tables are created on first use, following the ensureVaultTables /
// ensureFingerprintTables pattern. No database? Helpers throw
// VaultNotConfigured and the routes answer 503 instead of failing open.
//
// Timeline reads AND ingest are admin-gated (VAULT_ADMIN_PASS, same
// gate as the vault admin routes) — the timeline is passphrase-gated
// for the pilot, per the Pillar 3 plan.

import { sql } from "@vercel/postgres";
import { VaultNotConfigured } from "./vault-crypto";
import { requireDbConfigured } from "./vault-db";
import {
  computeEventHash,
  GENESIS_PREV_HASH,
  type AuditEvent,
} from "./audit-redact";

export interface AuditEventRow {
  id: number;
  eventId: string;
  eventType: string;
  timestamp: string;
  agentId: string;
  sessionId: string;
  correlationId: string;
  decisionAllow: boolean;
  outcome: string;
  eventHash: string;
  prevHash: string;
  event: AuditEvent;
  createdAt: string;
}

export async function ensureAuditTables(): Promise<void> {
  requireDbConfigured();
  await sql`
    CREATE TABLE IF NOT EXISTS audit_events (
      id SERIAL PRIMARY KEY,
      event_id TEXT NOT NULL UNIQUE,
      event_json JSONB NOT NULL,
      event_type TEXT NOT NULL DEFAULT '',
      agent_id TEXT NOT NULL DEFAULT '',
      session_id TEXT NOT NULL DEFAULT '',
      correlation_id TEXT NOT NULL DEFAULT '',
      decision_allow BOOLEAN NOT NULL DEFAULT true,
      outcome TEXT NOT NULL DEFAULT '',
      event_hash TEXT NOT NULL DEFAULT '',
      prev_hash TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
  await sql`
    CREATE INDEX IF NOT EXISTS audit_events_agent_idx
    ON audit_events (agent_id, created_at)`;
  await sql`
    CREATE INDEX IF NOT EXISTS audit_events_session_idx
    ON audit_events (session_id, created_at)`;
  await sql`
    CREATE INDEX IF NOT EXISTS audit_events_run_idx
    ON audit_events (correlation_id, created_at)`;
}

function rowToAuditEvent(row: Record<string, unknown>): AuditEventRow {
  const event =
    typeof row.event_json === "string"
      ? (JSON.parse(row.event_json) as AuditEvent)
      : (row.event_json as AuditEvent);
  const decision = (event["decision"] ?? {}) as Record<string, unknown>;
  return {
    id: Number(row.id),
    eventId: String(row.event_id),
    eventType: String(row.event_type ?? ""),
    // The event's own (server) timestamp; created_at is the DB receipt.
    timestamp: String(event["timestamp"] ?? row.created_at),
    agentId: String(row.agent_id ?? ""),
    sessionId: String(row.session_id ?? ""),
    correlationId: String(row.correlation_id ?? ""),
    decisionAllow: Boolean(decision["allow"] ?? row.decision_allow ?? true),
    outcome: String(row.outcome ?? ""),
    eventHash: String(row.event_hash ?? ""),
    prevHash: String(row.prev_hash ?? ""),
    event,
    createdAt: String(row.created_at),
  };
}

/** event_hash of the most recently stored event, or genesis. */
export async function lastAuditEventHash(): Promise<string> {
  await ensureAuditTables();
  const { rows } = await sql`
    SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1`;
  if (rows.length === 0) return GENESIS_PREV_HASH;
  return String(rows[0].event_hash || GENESIS_PREV_HASH);
}

/**
 * Insert one redacted + validated event, chaining it to the previous
 * hash. The caller must have run redactAuditEvent + validateAuditEvent
 * first; this function sets prev_hash / event_hash and stores the
 * chained event. Returns the row, or null when this event_id is already
 * stored (idempotent re-ingest).
 */
export async function insertAuditEvent(
  event: AuditEvent,
): Promise<AuditEventRow | null> {
  await ensureAuditTables();
  const prevHash = await lastAuditEventHash();
  const chained: AuditEvent = { ...event, prev_hash: prevHash };
  delete chained["event_hash"];
  const eventHash = computeEventHash(chained, prevHash);
  chained["event_hash"] = eventHash;
  const decision = (chained["decision"] ?? {}) as Record<string, unknown>;
  const { rows } = await sql`
    INSERT INTO audit_events
      (event_id, event_json, event_type, agent_id, session_id,
       correlation_id, decision_allow, outcome, event_hash, prev_hash)
    VALUES (${String(chained["event_id"])}, ${JSON.stringify(chained)},
            ${String(chained["event_type"] ?? "")},
            ${String(chained["agent_id"] ?? "")},
            ${String(chained["session_id"] ?? "")},
            ${String(chained["correlation_id"] ?? "")},
            ${decision["allow"] === true},
            ${String(chained["outcome"] ?? "")},
            ${eventHash}, ${prevHash})
    ON CONFLICT (event_id) DO NOTHING
    RETURNING id, event_id, event_json, event_type, agent_id, session_id,
              correlation_id, decision_allow, outcome, event_hash,
              prev_hash, created_at`;
  return rows.length > 0 ? rowToAuditEvent(rows[0]) : null;
}

export interface AuditListFilters {
  agent?: string;
  session?: string;
  run?: string;
  limit?: number;
}

/**
 * List events, newest first. Filters are applied in JS over the newest
 * `limit` rows (pilot-scale table; move the filters into SQL before
 * this grows past a few thousand rows).
 */
export async function listAuditEvents(
  filters: AuditListFilters = {},
): Promise<AuditEventRow[]> {
  await ensureAuditTables();
  const limit = Math.min(Math.max(filters.limit ?? 200, 1), 1000);
  const { rows } = await sql`
    SELECT id, event_id, event_json, event_type, agent_id, session_id,
           correlation_id, decision_allow, outcome, event_hash,
           prev_hash, created_at
    FROM audit_events ORDER BY id DESC LIMIT ${limit}`;
  let out = rows.map(rowToAuditEvent);
  if (filters.agent) out = out.filter((r) => r.agentId === filters.agent);
  if (filters.session) {
    out = out.filter((r) => r.sessionId === filters.session);
  }
  if (filters.run) out = out.filter((r) => r.correlationId === filters.run);
  return out;
}

/** All stored events in chain order (oldest first), for verification
 * and detection runs. */
export async function listAuditEventsChained(
  limit = 5000,
): Promise<AuditEvent[]> {
  await ensureAuditTables();
  const capped = Math.min(Math.max(limit, 1), 10000);
  const { rows } = await sql`
    SELECT event_json FROM audit_events
    ORDER BY id ASC LIMIT ${capped}`;
  return rows.map((row) => {
    const event = row.event_json;
    return typeof event === "string"
      ? (JSON.parse(event) as AuditEvent)
      : (event as AuditEvent);
  });
}

/** Number of stored events (for the export header). */
export async function countAuditEvents(): Promise<number> {
  await ensureAuditTables();
  const { rows } = await sql`
    SELECT COUNT(*)::int AS n FROM audit_events`;
  return Number(rows[0]?.n ?? 0);
}
