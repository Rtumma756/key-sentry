// Stripe billing stub — NO Stripe SDK, no new dependencies, no real
// keys anywhere. Only env-var PLACEHOLDER names appear here.
//
// State of the world: Stripe is NOT connected. buildCheckoutPayload
// returns the exact request body that WOULD be POSTed to
// api.stripe.com/v1/checkout/sessions once STRIPE_SECRET_KEY exists;
// the checkout route only performs that POST when
// KEYSENTRY_BILLING_LIVE=1 (default off — dry-run otherwise).
// verifyWebhookSignature implements Stripe's v1 HMAC-SHA256 scheme
// with node:crypto so the webhook route can be tested end to end
// before any Stripe account exists.
//
// Env vars (names only — values are never logged or stored here):
//   STRIPE_SECRET_KEY      secret key (sk_...) — enables live checkout
//   STRIPE_WEBHOOK_SECRET  webhook signing secret (whsec_...)
//   STRIPE_PRICE_MAKER / STRIPE_PRICE_STARTER / STRIPE_PRICE_PREMIUM /
//   STRIPE_PRICE_TEAM / STRIPE_PRICE_PREMIUM_PLUS / STRIPE_PRICE_BUSINESS
//                          Price IDs (price_...) per paid tier
//   KEYSENTRY_APP_URL      public app URL for success/cancel redirects
//   KEYSENTRY_BILLING_LIVE=1  actually call api.stripe.com (default off)

import { createHmac, timingSafeEqual } from "node:crypto";

/** Paid tiers that have a checkout. Free has nothing to buy;
 * Enterprise is custom pricing (out of scope for this stub). */
export const CHECKOUT_TIERS = [
  "maker",
  "starter",
  "premium",
  "team",
  "premium_plus",
  "business",
] as const;
export type CheckoutTier = (typeof CHECKOUT_TIERS)[number];

const PRICE_ENV: Record<CheckoutTier, string> = {
  maker: "STRIPE_PRICE_MAKER",
  starter: "STRIPE_PRICE_STARTER",
  premium: "STRIPE_PRICE_PREMIUM",
  team: "STRIPE_PRICE_TEAM",
  premium_plus: "STRIPE_PRICE_PREMIUM_PLUS",
  business: "STRIPE_PRICE_BUSINESS",
};

/** Placeholder Price ID used when the env var is unset — clearly not
 * a real Stripe ID, so a dry-run payload can never charge anyone. */
export function pricePlaceholder(tier: CheckoutTier): string {
  return `price_${tier}_placeholder`;
}

export function priceIdForTier(tier: CheckoutTier): string {
  return process.env[PRICE_ENV[tier]] || pricePlaceholder(tier);
}

export function isPriceConfigured(tier: CheckoutTier): boolean {
  return Boolean(process.env[PRICE_ENV[tier]]);
}

export function isBillingConfigured(): boolean {
  return Boolean(process.env.STRIPE_SECRET_KEY);
}

export function isWebhookConfigured(): boolean {
  return Boolean(process.env.STRIPE_WEBHOOK_SECRET);
}

export function isBillingLive(): boolean {
  return process.env.KEYSENTRY_BILLING_LIVE === "1";
}

export function appBaseUrl(): string {
  return (
    process.env.KEYSENTRY_APP_URL || "https://key-sentry-inky.vercel.app"
  ).replace(/\/$/, "");
}

/** Typed error raised when billing is not configured. Routes answer
 * 503 billing_not_connected instead of crashing. */
export class BillingNotConfigured extends Error {
  code = "billing_not_connected";
  constructor(message?: string) {
    super(
      message ??
        "Stripe billing is not connected. Set STRIPE_SECRET_KEY (and " +
          "STRIPE_WEBHOOK_SECRET for webhooks) in Vercel → Settings → " +
          "Environment Variables, then redeploy. The free layer is " +
          "unaffected.",
    );
    this.name = "BillingNotConfigured";
  }
}

export function requireBillingConfigured(): void {
  if (!isBillingConfigured()) throw new BillingNotConfigured();
}

export function requireWebhookConfigured(): void {
  if (!isWebhookConfigured()) {
    throw new BillingNotConfigured(
      "Stripe webhook signing is not configured. Set " +
        "STRIPE_WEBHOOK_SECRET in Vercel → Settings → Environment " +
        "Variables, then redeploy.",
    );
  }
}

/** Setup instructions returned with every 503 billing_not_connected,
 * so the operator (and the dashboard banner) always know the next
 * step. The free layer is unaffected — this is never a dead end. */
export const BILLING_SETUP_INSTRUCTIONS =
  "Stripe billing is not connected. To connect it: in Vercel, set " +
  "STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET (from the Stripe " +
  "dashboard), plus STRIPE_PRICE_MAKER, STRIPE_PRICE_STARTER, " +
  "STRIPE_PRICE_PREMIUM, STRIPE_PRICE_TEAM, STRIPE_PRICE_PREMIUM_PLUS " +
  "and STRIPE_PRICE_BUSINESS (the Price IDs for the $19 / $49 / $99 / " +
  "$149 / $299 / $499 tiers), then redeploy. Until then the free layer " +
  "keeps working exactly as before — no checkout, no charges.";

export function billingNotConnectedResponse(): Response {
  return new Response(
    JSON.stringify({
      error: "billing_not_connected",
      message: BILLING_SETUP_INSTRUCTIONS,
      free_layer_unaffected: true,
    }),
    { status: 503, headers: { "Content-Type": "application/json" } },
  );
}

export interface CheckoutPayload {
  mode: "subscription";
  line_items: [{ price: string; quantity: 1 }];
  success_url: string;
  cancel_url: string;
  metadata: { tier: CheckoutTier; workspace_id: string };
  allow_promotion_codes: boolean;
}

/**
 * The exact request body that would be POSTed to
 * api.stripe.com/v1/checkout/sessions for `tier` (form-encoded on the
 * wire — see checkoutPayloadToFormBody). Throws for Free (nothing to
 * buy) and Enterprise (custom pricing, no self-serve checkout).
 */
export function buildCheckoutPayload(
  tier: string,
  opts: { workspaceId?: string } = {},
): CheckoutPayload {
  if (tier === "free") {
    throw new Error("The Free plan ($0) has no checkout — nothing to buy.");
  }
  if (tier === "enterprise") {
    throw new Error(
      "Enterprise is custom pricing — contact us instead of checking out.",
    );
  }
  if (!(CHECKOUT_TIERS as readonly string[]).includes(tier)) {
    throw new Error(`Unknown tier for checkout: ${tier}`);
  }
  const checkoutTier = tier as CheckoutTier;
  const base = appBaseUrl();
  return {
    mode: "subscription",
    line_items: [{ price: priceIdForTier(checkoutTier), quantity: 1 }],
    success_url: `${base}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${base}/billing/cancelled`,
    metadata: {
      tier: checkoutTier,
      workspace_id: opts.workspaceId ?? "default",
    },
    allow_promotion_codes: true,
  };
}

/** Encode a checkout payload the way Stripe expects it:
 * application/x-www-form-urlencoded with bracket notation. */
export function checkoutPayloadToFormBody(
  payload: CheckoutPayload,
): URLSearchParams {
  const body = new URLSearchParams();
  body.set("mode", payload.mode);
  body.set("line_items[0][price]", payload.line_items[0].price);
  body.set("line_items[0][quantity]", "1");
  body.set("success_url", payload.success_url);
  body.set("cancel_url", payload.cancel_url);
  body.set("metadata[tier]", payload.metadata.tier);
  body.set("metadata[workspace_id]", payload.metadata.workspace_id);
  body.set("allow_promotion_codes", "true");
  return body;
}

/** Map a Stripe Price ID back to its tier (env-configured prices).
 * Returns null for unknown/placeholder prices. */
export function tierForPriceId(priceId: string): CheckoutTier | null {
  for (const tier of CHECKOUT_TIERS) {
    if (process.env[PRICE_ENV[tier]] && process.env[PRICE_ENV[tier]] === priceId) {
      return tier;
    }
  }
  return null;
}

// --- Webhook signature verification (Stripe v1 scheme) --------------

/** Parse a Stripe-Signature header: "t=<ts>,v1=<hex>,v1=<hex>". */
export function parseStripeSignatureHeader(
  header: string,
): { timestamp: number | null; signatures: string[] } {
  let timestamp: number | null = null;
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const [key, ...rest] = part.split("=");
    const value = rest.join("=");
    if (key === "t") {
      const parsed = Number.parseInt(value, 10);
      timestamp = Number.isFinite(parsed) ? parsed : null;
    } else if (key === "v1" && value) {
      signatures.push(value);
    }
  }
  return { timestamp, signatures };
}

const WEBHOOK_TOLERANCE_SECONDS = 300; // Stripe's 5-minute window

/**
 * Verify a Stripe webhook signature (v1 HMAC-SHA256 scheme).
 * expected = HMAC_SHA256(secret, "<unix ts>.<raw body>"), compared in
 * constant time against any v1 signature in the header; the timestamp
 * must be within the tolerance window. Returns false (never throws)
 * for a missing/malformed header, a bad signature, or a stale event.
 */
export function verifyWebhookSignature(
  rawBody: string,
  signatureHeader: string,
  secret: string,
  toleranceSeconds: number = WEBHOOK_TOLERANCE_SECONDS,
  nowMs: number = Date.now(),
): boolean {
  if (!rawBody || !signatureHeader || !secret) return false;
  const { timestamp, signatures } = parseStripeSignatureHeader(signatureHeader);
  if (timestamp === null || signatures.length === 0) return false;
  if (Math.abs(nowMs / 1000 - timestamp) > toleranceSeconds) return false;
  const signedPayload = `${timestamp}.${rawBody}`;
  const expected = createHmac("sha256", secret)
    .update(signedPayload, "utf8")
    .digest("hex");
  for (const sig of signatures) {
    let a: Buffer;
    let b: Buffer;
    try {
      a = Buffer.from(sig, "hex");
      b = Buffer.from(expected, "hex");
    } catch {
      continue;
    }
    if (a.length === b.length && timingSafeEqual(a, b)) return true;
  }
  return false;
}
