// Postgres-backed daily usage counters (pilot-grade plan limits).
//
// Table: usage_counters (key TEXT, day DATE, count INTEGER,
// PRIMARY KEY (key, day)). One row per counter per UTC day.
//
// Counters are global to the workspace: KeySentry has no user accounts,
// only the single VAULT_ADMIN_PASS admin gate, so these limits cap the
// workspace as a whole. Full per-workspace / per-plan enforcement needs
// accounts first — recorded as open in
// docs/commercial/COMMERCIAL-STATUS.md (item 7).
//
// Enforced limits (defaults fit a free pilot; override with env vars):
//   fingerprints added per day: KEYSENTRY_MAX_FINGERPRINTS_PER_DAY (20)
//   matches recorded per day:   KEYSENTRY_MAX_MATCHES_PER_DAY (500)
// A breach answers 429 naming the limit, with Retry-After set to
// seconds until midnight UTC.
//
// Pure policy helpers (env defaults, UTC-day math, the 429 response)
// live in lib/usage-policy.ts so plain-node tests can import them;
// this file holds only the Postgres-backed helpers.

import { sql } from "@vercel/postgres";
import { requireDbConfigured } from "./vault-db";
import { getClientIp } from "./rate-limit";

export {
  DEFAULT_MAX_FINGERPRINTS_PER_DAY,
  DEFAULT_MAX_MATCHES_PER_DAY,
  getMaxFingerprintsPerDay,
  getMaxMatchesPerDay,
  secondsUntilMidnightUtc,
  usageDay,
  usageLimitResponse,
  // Free-tier caps (FREE-TIER-CAPS.md): pure helpers, re-exported so
  // routes import everything caps-related from this one module.
  hashClientIp,
  resetsAtUtc,
  memoryDailyCounters,
  capHitResponse,
  type CapHitUpgrade,
  MemoryDailyCounters,
} from "./usage-policy";
import {
  hashClientIp,
  memoryDailyCounters,
  usageDay,
} from "./usage-policy";

/** Counter keys used in usage_counters. */
export const USAGE_KEY_FINGERPRINTS_ADDED = "fingerprints:added";
export const USAGE_KEY_MATCHES_RECORDED = "matches:recorded";
/** Free-tier daily caps (FREE-TIER-CAPS.md). The full counter key is
 * `<key>:<scope>` where scope is `ip:<sha256-16 of the client IP>`
 * for anonymous users (a raw IP is never stored) — see
 * scopeKeyForRequest. */
export const USAGE_KEY_VIBE_SCANS = "vibe-scans";
export const USAGE_KEY_DASHBOARD_SAVES = "dashboard-saves";
export const USAGE_KEY_AUDITS = "audits";

export async function ensureUsageTables(): Promise<void> {
  requireDbConfigured();
  await sql`
    CREATE TABLE IF NOT EXISTS usage_counters (
      key TEXT NOT NULL,
      day DATE NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (key, day)
    )`;
}

export async function getUsageCount(
  key: string,
  day: string = usageDay(),
): Promise<number> {
  await ensureUsageTables();
  const { rows } = await sql`
    SELECT count FROM usage_counters WHERE key = ${key} AND day = ${day}`;
  return rows.length > 0 ? Number(rows[0].count ?? 0) : 0;
}

export interface LimitCheck {
  allowed: boolean;
  count: number;
  limit: number;
  remaining: number;
}

/** Read today's count for `key` and say whether one more is allowed. */
export async function checkLimit(
  key: string,
  maxPerDay: number,
): Promise<LimitCheck> {
  const count = await getUsageCount(key);
  return {
    allowed: count < maxPerDay,
    count,
    limit: maxPerDay,
    remaining: Math.max(0, maxPerDay - count),
  };
}

/**
 * Record one use of `key` for today (upsert +1). Returns the new count.
 * Call only after the guarded operation succeeded.
 */
export async function recordUsage(key: string): Promise<number> {
  await ensureUsageTables();
  const day = usageDay();
  const { rows } = await sql`
    INSERT INTO usage_counters (key, day, count)
    VALUES (${key}, ${day}, 1)
    ON CONFLICT (key, day)
      DO UPDATE SET count = usage_counters.count + 1
    RETURNING count`;
  return Number(rows[0].count ?? 0);
}

// ---------------------------------------------------------------------------
// Free-tier daily counters (FREE-TIER-CAPS.md).
//
// Same usage_counters table, keyed `<resource>:<scope>` with the UTC
// day as the row's day column — a new day is a new row, so the
// midnight-UTC reset is automatic. When no database is configured
// (or it is unreachable) the counters fall back to the process-local
// in-memory store: the free layer keeps working, and the cap still
// applies per instance. Never throws.
// ---------------------------------------------------------------------------

/** Anonymous-cap scope for a request: `ip:<sha256-16 of the client
 * IP>`. The hash — never the raw IP — is what lands in the counter
 * key, so no request can be traced back to an address from storage. */
export function scopeKeyForRequest(req: Request): string {
  return `ip:${hashClientIp(getClientIp(req))}`;
}

/** Today's count for a daily-cap `key` (DB first, memory fallback). */
export async function getDailyCount(key: string): Promise<number> {
  try {
    return await getUsageCount(key);
  } catch {
    return memoryDailyCounters.get(key);
  }
}

/** Record one use of a daily-cap `key` today (DB first, memory
 * fallback). Returns the new count. Call only after the guarded
 * operation succeeded. */
export async function recordDailyCount(key: string): Promise<number> {
  try {
    return await recordUsage(key);
  } catch {
    return memoryDailyCounters.increment(key);
  }
}

/** Today's counts for several daily-cap keys at once. */
export async function getDailyCounts(
  keys: string[],
): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const key of keys) {
    out[key] = await getDailyCount(key);
  }
  return out;
}
