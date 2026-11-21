// Pure usage-limit policy: env-var defaults, UTC-day math, and the
// 429 response. No imports, so plain-node tests can load this file
// directly (lib/usage.ts holds the Postgres helpers and re-exports
// everything from here).

import { createHash } from "node:crypto";

export const DEFAULT_MAX_FINGERPRINTS_PER_DAY = 20;
export const DEFAULT_MAX_MATCHES_PER_DAY = 500;

function readLimitEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function getMaxFingerprintsPerDay(): number {
  return readLimitEnv(
    "KEYSENTRY_MAX_FINGERPRINTS_PER_DAY",
    DEFAULT_MAX_FINGERPRINTS_PER_DAY,
  );
}

export function getMaxMatchesPerDay(): number {
  return readLimitEnv(
    "KEYSENTRY_MAX_MATCHES_PER_DAY",
    DEFAULT_MAX_MATCHES_PER_DAY,
  );
}

/** Current UTC day as YYYY-MM-DD (the counter bucket). */
export function usageDay(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

/** Seconds from `now` until midnight UTC (Retry-After for a daily limit). */
export function secondsUntilMidnightUtc(now: Date = new Date()): number {
  const midnight = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
  );
  return Math.max(1, Math.ceil((midnight - now.getTime()) / 1000));
}

/** 429 response naming the daily limit that was hit. */
export function usageLimitResponse(
  what: string,
  limit: number,
  count: number,
): Response {
  return new Response(
    JSON.stringify({
      error:
        `Daily limit reached: at most ${limit} ${what} per day ` +
        `(already ${count} today). Try again tomorrow.`,
      limit,
      count,
    }),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": String(secondsUntilMidnightUtc()),
      },
    },
  );
}

// ---------------------------------------------------------------------------
// Free-tier caps (FREE-TIER-CAPS.md): anonymous IP hashing, in-memory
// daily counters (the no-database fallback for lib/usage.ts), and the
// cap-hit 429 response. All pure, so plain-node tests can import them.
// ---------------------------------------------------------------------------

/** Hash a client IP for anonymous cap tracking: SHA-256, first 16 hex
 * chars (same shape as a key fingerprint). A raw IP is NEVER stored
 * — the counter key carries only this hash. Deterministic: the same
 * IP always maps to the same hash, so one IP's daily count is stable
 * across requests. */
export function hashClientIp(ip: string): string {
  return createHash("sha256").update(ip, "utf-8").digest("hex").slice(0, 16);
}

/** Next midnight UTC as an ISO timestamp (the `resetsAt` in cap-hit
 * responses and the counters endpoint). */
export function resetsAtUtc(now: Date = new Date()): string {
  const midnight = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
  );
  return new Date(midnight).toISOString();
}

/** In-memory daily counters: the no-database fallback for the
 * Postgres usage_counters table (lib/usage.ts). Same key shape
 * (`<resource>:<scope>`) and the same UTC-day bucketing — a new day
 * is a new key, so the midnight-UTC rollover is automatic. Process-
 * local like lib/rate-limit.ts (resets on cold start / redeploy);
 * pilot-grade, and the DB path is used whenever Postgres is
 * configured. */
export class MemoryDailyCounters {
  private counts = new Map<string, number>();

  private bucketKey(key: string, day: string): string {
    return `${day}|${key}`;
  }

  get(key: string, day: string = usageDay()): number {
    return this.counts.get(this.bucketKey(key, day)) ?? 0;
  }

  increment(key: string, day: string = usageDay()): number {
    const next = this.get(key, day) + 1;
    this.counts.set(this.bucketKey(key, day), next);
    return next;
  }

  /** Tests only: drop every stored count. */
  reset(): void {
    this.counts.clear();
  }
}

export const memoryDailyCounters = new MemoryDailyCounters();

export interface CapHitUpgrade {
  message: string;
  tier: string;
  price: string;
  unlocks: string;
}

/** 429 response for a free-tier daily-cap hit. The body always
 * carries the denial message (limit + upgrade + "come back
 * tomorrow"), the used/limit counts, when the cap resets, and the
 * structured upgrade prompt — never a bare error. */
export function capHitResponse(
  message: string,
  limit: number,
  used: number,
  upgrade: CapHitUpgrade | null,
  now: Date = new Date(),
): Response {
  return new Response(
    JSON.stringify({
      error: message,
      used,
      limit,
      resetsAt: resetsAtUtc(now),
      upgrade,
    }),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": String(secondsUntilMidnightUtc(now)),
      },
    },
  );
}
