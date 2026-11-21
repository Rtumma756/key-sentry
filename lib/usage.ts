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

export {
  DEFAULT_MAX_FINGERPRINTS_PER_DAY,
  DEFAULT_MAX_MATCHES_PER_DAY,
  getMaxFingerprintsPerDay,
  getMaxMatchesPerDay,
  secondsUntilMidnightUtc,
  usageDay,
  usageLimitResponse,
} from "./usage-policy";
import { usageDay } from "./usage-policy";

/** Counter keys used in usage_counters. */
export const USAGE_KEY_FINGERPRINTS_ADDED = "fingerprints:added";
export const USAGE_KEY_MATCHES_RECORDED = "matches:recorded";

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
