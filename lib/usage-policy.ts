// Pure usage-limit policy: env-var defaults, UTC-day math, and the
// 429 response. No imports, so plain-node tests can load this file
// directly (lib/usage.ts holds the Postgres helpers and re-exports
// everything from here).

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
