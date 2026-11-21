// Standalone tests for the usage-limit policy helpers
// (lib/usage-policy.ts). No test runner is configured for this project,
// so this file runs with plain node and uses node:assert:
//
//   node tests/usage-limits.test.mjs   (also via `npm test`)
//
// Only the pure policy helpers are covered here. The Postgres-backed
// helpers in lib/usage.ts (checkLimit / recordUsage) need a database —
// no Postgres is reachable from this sandbox — so they are verified by
// `npm run build` (type check) and by the route wiring, not by this file.

import assert from "node:assert/strict";
import {
  DEFAULT_MAX_FINGERPRINTS_PER_DAY,
  DEFAULT_MAX_MATCHES_PER_DAY,
  getMaxFingerprintsPerDay,
  getMaxMatchesPerDay,
  secondsUntilMidnightUtc,
  usageDay,
  usageLimitResponse,
} from "../lib/usage-policy.ts";

let passed = 0;
function check(name, fn) {
  const result = fn();
  if (result instanceof Promise) return result.then(() => {
    passed++;
    console.log(`ok - ${name}`);
  });
  passed++;
  console.log(`ok - ${name}`);
}

const savedFingerprints = process.env.KEYSENTRY_MAX_FINGERPRINTS_PER_DAY;
const savedMatches = process.env.KEYSENTRY_MAX_MATCHES_PER_DAY;
function restoreEnv() {
  if (savedFingerprints === undefined) {
    delete process.env.KEYSENTRY_MAX_FINGERPRINTS_PER_DAY;
  } else {
    process.env.KEYSENTRY_MAX_FINGERPRINTS_PER_DAY = savedFingerprints;
  }
  if (savedMatches === undefined) {
    delete process.env.KEYSENTRY_MAX_MATCHES_PER_DAY;
  } else {
    process.env.KEYSENTRY_MAX_MATCHES_PER_DAY = savedMatches;
  }
}

await check("defaults are 20 fingerprints/day and 500 matches/day", () => {
  delete process.env.KEYSENTRY_MAX_FINGERPRINTS_PER_DAY;
  delete process.env.KEYSENTRY_MAX_MATCHES_PER_DAY;
  assert.equal(DEFAULT_MAX_FINGERPRINTS_PER_DAY, 20);
  assert.equal(DEFAULT_MAX_MATCHES_PER_DAY, 500);
  assert.equal(getMaxFingerprintsPerDay(), 20);
  assert.equal(getMaxMatchesPerDay(), 500);
});

await check("env vars override the defaults", () => {
  process.env.KEYSENTRY_MAX_FINGERPRINTS_PER_DAY = "5";
  process.env.KEYSENTRY_MAX_MATCHES_PER_DAY = "100";
  assert.equal(getMaxFingerprintsPerDay(), 5);
  assert.equal(getMaxMatchesPerDay(), 100);
  restoreEnv();
});

await check("invalid env values fall back to the defaults", () => {
  for (const bad of ["0", "-3", "abc", ""]) {
    process.env.KEYSENTRY_MAX_FINGERPRINTS_PER_DAY = bad;
    assert.equal(getMaxFingerprintsPerDay(), 20, `for ${JSON.stringify(bad)}`);
  }
  restoreEnv();
});

await check("usageDay is the UTC date", () => {
  assert.equal(usageDay(new Date("2026-11-21T05:00:00Z")), "2026-11-21");
  assert.equal(usageDay(new Date("2026-11-21T23:30:00Z")), "2026-11-21");
});

await check("secondsUntilMidnightUtc counts down to midnight UTC", () => {
  assert.equal(
    secondsUntilMidnightUtc(new Date("2026-11-21T00:00:00Z")),
    86400,
  );
  assert.equal(
    secondsUntilMidnightUtc(new Date("2026-11-21T23:00:00Z")),
    3600,
  );
  const mid = secondsUntilMidnightUtc(new Date("2026-11-21T12:00:00Z"));
  assert.equal(mid, 43200);
});

await check("usageLimitResponse is a 429 naming the limit", async () => {
  const res = usageLimitResponse("fingerprints added", 20, 20);
  assert.equal(res.status, 429);
  assert.ok(Number(res.headers.get("Retry-After")) > 0);
  const body = await res.json();
  assert.match(body.error, /at most 20 fingerprints added per day/);
  assert.match(body.error, /already 20 today/);
  assert.equal(body.limit, 20);
  assert.equal(body.count, 20);
});

restoreEnv();
console.log(`\nusage-limits: ${passed} checks passed`);
