// Standalone tests for the per-IP token-bucket rate limiter
// (lib/rate-limit.ts). No test runner is configured for this project,
// so this file runs with plain node and uses node:assert:
//
//   node tests/rate-limit.test.mjs   (also via `npm test`)
//
// Node's type stripping loads the .ts source directly; the limiter
// module uses only erasable TypeScript, so no build step is needed.

import assert from "node:assert/strict";
import {
  checkRateLimit,
  getClientIp,
  MUTATING_REQUESTS_PER_MINUTE,
  READ_REQUESTS_PER_MINUTE,
  rateLimitResponse,
  TokenBucketLimiter,
} from "../lib/rate-limit.ts";

let passed = 0;
async function check(name, fn) {
  await fn();
  passed++;
  console.log(`ok - ${name}`);
}

// A fresh limiter allows exactly maxRequests, then denies.
await check("allows up to the limit, then denies", () => {
  const limiter = new TokenBucketLimiter(3, 60_000);
  const t0 = 1_000_000;
  assert.equal(limiter.allow("1.2.3.4", t0).allowed, true);
  assert.equal(limiter.allow("1.2.3.4", t0).allowed, true);
  assert.equal(limiter.allow("1.2.3.4", t0).allowed, true);
  const denied = limiter.allow("1.2.3.4", t0);
  assert.equal(denied.allowed, false);
  assert.ok(denied.retryAfterSeconds >= 1);
  assert.ok(denied.retryAfterSeconds <= 60);
});

// Buckets are per key: one IP being limited does not affect another.
await check("limits are per IP", () => {
  const limiter = new TokenBucketLimiter(1, 60_000);
  const t0 = 2_000_000;
  assert.equal(limiter.allow("10.0.0.1", t0).allowed, true);
  assert.equal(limiter.allow("10.0.0.1", t0).allowed, false);
  assert.equal(limiter.allow("10.0.0.2", t0).allowed, true);
});

// Tokens refill continuously: after a full window the bucket is full.
await check("bucket refills after the window", () => {
  const limiter = new TokenBucketLimiter(2, 60_000);
  const t0 = 3_000_000;
  assert.equal(limiter.allow("9.9.9.9", t0).allowed, true);
  assert.equal(limiter.allow("9.9.9.9", t0).allowed, true);
  assert.equal(limiter.allow("9.9.9.9", t0).allowed, false);
  // Half a window later one token has refilled.
  assert.equal(limiter.allow("9.9.9.9", t0 + 30_000).allowed, true);
  assert.equal(limiter.allow("9.9.9.9", t0 + 30_000).allowed, false);
  // Another half window refills one more token (the bucket refills
  // continuously from the last spend, not from the first).
  assert.equal(limiter.allow("9.9.9.9", t0 + 60_000).allowed, true);
  assert.equal(limiter.allow("9.9.9.9", t0 + 60_000).allowed, false);
  // A full window after the last spend the bucket is full again.
  assert.equal(limiter.allow("9.9.9.9", t0 + 120_000).allowed, true);
  assert.equal(limiter.allow("9.9.9.9", t0 + 120_000).allowed, true);
});

// Partial refill: retryAfter shrinks as tokens come back.
await check("retryAfter reflects the refill rate", () => {
  const limiter = new TokenBucketLimiter(60, 60_000);
  const t0 = 4_000_000;
  for (let i = 0; i < 60; i++) {
    assert.equal(limiter.allow("7.7.7.7", t0).allowed, true);
  }
  const denied = limiter.allow("7.7.7.7", t0);
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfterSeconds, 1);
});

// Client IP: leftmost X-Forwarded-For entry wins.
await check("getClientIp prefers X-Forwarded-For", () => {
  const req = new Request("https://example.test/api/matches", {
    headers: {
      "x-forwarded-for": "203.0.113.5, 70.41.3.18, 150.172.238.4",
      "x-real-ip": "70.41.3.18",
    },
  });
  assert.equal(getClientIp(req), "203.0.113.5");
  const bare = new Request("https://example.test/api/matches");
  assert.equal(getClientIp(bare), "unknown");
});

// The 429 response carries the status, the Retry-After header, and a
// message naming the limit.
await check("rateLimitResponse is a 429 with Retry-After", async () => {
  const res = rateLimitResponse(42);
  assert.equal(res.status, 429);
  assert.equal(res.headers.get("Retry-After"), "42");
  const body = await res.json();
  assert.match(body.error, /Rate limit exceeded/);
});

// Route-level helper: first request passes (null), and the documented
// limits are 60/min mutating, 120/min read.
await check("checkRateLimit passes a fresh IP; limits are 60/120 per minute", () => {
  assert.equal(MUTATING_REQUESTS_PER_MINUTE, 60);
  assert.equal(READ_REQUESTS_PER_MINUTE, 120);
  const req = new Request("https://example.test/api/fingerprints", {
    headers: { "x-forwarded-for": "198.51.100.99" },
  });
  assert.equal(checkRateLimit(req, "mutate"), null);
  assert.equal(checkRateLimit(req, "read"), null);
});

console.log(`\nrate-limit: ${passed} checks passed`);
