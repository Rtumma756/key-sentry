// Per-IP token-bucket rate limiting for the KeySentry API (pilot-grade).
//
// This is a lightweight abuse guardrail, NOT a WAF: state lives in a
// process-local Map, so it resets on every cold start / redeploy and does
// not share counts across Vercel function instances. Good enough for a
// free pilot with a single admin; a multi-instance deployment that needs
// exact enforcement should move the buckets to Postgres (same table
// shape as lib/usage.ts) or a dedicated rate-limit service.
//
// Limits (see docs/commercial/SCHEDULED-SWEEPS.md for the full policy):
//   mutating routes (/api/fingerprints, /api/matches, /api/vault/*):
//     60 requests/minute per IP
//   GET routes: 120 requests/minute per IP
// Over the limit the route answers 429 with a Retry-After header.
//
// This module imports nothing: it uses only the global Response, so it
// can be imported by route handlers and by plain-node unit tests alike.
// It uses only erasable TypeScript syntax (no enums, no parameter
// properties) so Node's type stripping can load it directly.

export interface RateLimitDecision {
  allowed: boolean;
  /** Seconds to wait before retrying (0 when allowed). */
  retryAfterSeconds: number;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

const MAX_TRACKED_IPS = 5000;
const EPSILON = 1e-9;

/** A token bucket that refills continuously over `windowMs`. */
export class TokenBucketLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private readonly refillPerMs: number;
  private buckets: Map<string, Bucket>;

  constructor(maxRequests: number, windowMs: number) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.refillPerMs = maxRequests / windowMs;
    this.buckets = new Map();
  }

  /** Spend one token for `key`. `now` is injectable so tests can fake time. */
  allow(key: string, now: number = Date.now()): RateLimitDecision {
    this.prune(now);
    const bucket = this.buckets.get(key) ?? {
      tokens: this.maxRequests,
      updatedAt: now,
    };
    const elapsed = Math.max(0, now - bucket.updatedAt);
    bucket.tokens = Math.min(
      this.maxRequests,
      bucket.tokens + elapsed * this.refillPerMs,
    );
    bucket.updatedAt = now;
    // Epsilon: without it, floating-point dust (e.g. 0.9999999999 tokens
    // after exactly half a window) would deny a request that has
    // refilled exactly one token.
    if (bucket.tokens + EPSILON >= 1) {
      bucket.tokens = Math.max(0, bucket.tokens - 1);
      this.buckets.set(key, bucket);
      return { allowed: true, retryAfterSeconds: 0 };
    }
    this.buckets.set(key, bucket);
    const missing = 1 - bucket.tokens;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil(missing / this.refillPerMs / 1000),
    );
    return { allowed: false, retryAfterSeconds };
  }

  /** Number of IPs currently tracked (tests / debugging only). */
  get size(): number {
    return this.buckets.size;
  }

  /** Drop buckets idle for a full window, so the map stays bounded. */
  private prune(now: number): void {
    if (this.buckets.size <= MAX_TRACKED_IPS) return;
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.updatedAt >= this.windowMs) {
        this.buckets.delete(key);
      }
    }
  }
}

/** First client IP: the leftmost entry of X-Forwarded-For (Vercel sets it). */
export function getClientIp(req: Request): string {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }
  const realIp = req.headers.get("x-real-ip");
  if (realIp?.trim()) return realIp.trim();
  return "unknown";
}

export const MUTATING_REQUESTS_PER_MINUTE = 60;
export const READ_REQUESTS_PER_MINUTE = 120;
const WINDOW_MS = 60_000;

const mutatingLimiter = new TokenBucketLimiter(
  MUTATING_REQUESTS_PER_MINUTE,
  WINDOW_MS,
);
const readLimiter = new TokenBucketLimiter(
  READ_REQUESTS_PER_MINUTE,
  WINDOW_MS,
);

/** 429 response naming the limit, with a Retry-After header. */
export function rateLimitResponse(retryAfterSeconds: number): Response {
  return new Response(
    JSON.stringify({
      error:
        `Rate limit exceeded. Try again in ${retryAfterSeconds} ` +
        `second${retryAfterSeconds === 1 ? "" : "s"}.`,
    }),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": String(retryAfterSeconds),
      },
    },
  );
}

/**
 * Check the per-IP rate limit for one request. Returns null when the
 * request may proceed, or a 429 Response to return immediately.
 * `kind` is "mutate" for POST/PATCH/DELETE and "read" for GET.
 */
export function checkRateLimit(
  req: Request,
  kind: "read" | "mutate",
): Response | null {
  const limiter = kind === "mutate" ? mutatingLimiter : readLimiter;
  const decision = limiter.allow(getClientIp(req));
  if (decision.allowed) return null;
  return rateLimitResponse(decision.retryAfterSeconds);
}
