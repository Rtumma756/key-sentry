// Billing checkout stub.
// POST /api/billing/checkout { tier } -> a Stripe Checkout Session.
//   * Stripe NOT connected (no STRIPE_SECRET_KEY): 503
//     billing_not_connected with setup instructions — the free layer is
//     unaffected, never a dead end.
//   * Connected, KEYSENTRY_BILLING_LIVE != 1 (default): 200 dry-run
//     with the exact payload that would be POSTed to Stripe, so the
//     path is testable without charging anyone.
//   * Connected + KEYSENTRY_BILLING_LIVE=1: the payload is POSTed to
//     api.stripe.com/v1/checkout/sessions and Stripe's response is
//     returned.
// GET /api/billing/checkout -> documentation for the checkout flow
// (what the dashboard UpgradeBanner links to). No live checkout button
// exists while Stripe is unconnected.

import { NextResponse } from "next/server";
import {
  billingNotConnectedResponse,
  buildCheckoutPayload,
  CHECKOUT_TIERS,
  checkoutPayloadToFormBody,
  isBillingConfigured,
  isBillingLive,
} from "@/lib/billing";
import { getAllPlans } from "@/lib/plans";

export const dynamic = "force-dynamic";

const STRIPE_CHECKOUT_SESSIONS_URL =
  "https://api.stripe.com/v1/checkout/sessions";

export async function GET() {
  return NextResponse.json({
    documentation: "KeySentry billing checkout (stub — Stripe not connected).",
    tiers: getAllPlans().map((t) => ({
      id: t.id,
      name: t.name,
      price: t.price_label,
      summary: t.summary,
    })),
    checkout_tiers: [...CHECKOUT_TIERS],
    how_it_works: [
      "POST /api/billing/checkout with { tier } (maker, starter, premium, team, premium_plus, or business).",
      "Without STRIPE_SECRET_KEY the route answers 503 billing_not_connected and the free layer keeps working.",
      "With the key set but KEYSENTRY_BILLING_LIVE unset, it returns a dry-run of the exact Stripe payload.",
      "With KEYSENTRY_BILLING_LIVE=1 it creates a real Stripe Checkout Session.",
      "A completed checkout is applied by the Stripe webhook (POST /api/billing/webhook) — no route sets a plan directly.",
    ],
    env_vars: [
      "STRIPE_SECRET_KEY",
      "STRIPE_WEBHOOK_SECRET",
      "STRIPE_PRICE_STARTER",
      "STRIPE_PRICE_TEAM",
      "STRIPE_PRICE_BUSINESS",
      "KEYSENTRY_APP_URL",
      "KEYSENTRY_BILLING_LIVE",
    ],
    billing_connected: isBillingConfigured(),
    billing_live: isBillingLive(),
  });
}

export async function POST(req: Request) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body — want { tier }." },
      { status: 400 },
    );
  }
  const tier = typeof (body as { tier?: unknown })?.tier === "string"
    ? (body as { tier: string }).tier
    : "";
  if (!tier) {
    return NextResponse.json(
      { error: "Missing tier — want { tier: 'maker' | 'starter' | 'premium' | 'team' | 'premium_plus' | 'business' }." },
      { status: 400 },
    );
  }
  let payload;
  try {
    payload = buildCheckoutPayload(tier);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Invalid tier." },
      { status: 400 },
    );
  }
  if (!isBillingConfigured()) {
    return billingNotConnectedResponse();
  }
  if (!isBillingLive()) {
    // Dry-run (default): return the exact payload, call nothing.
    return NextResponse.json({
      mode: "dry-run",
      tier,
      payload,
      note:
        "Stripe is configured but KEYSENTRY_BILLING_LIVE is not 1, so no " +
        "call was made. Set KEYSENTRY_BILLING_LIVE=1 to create a real " +
        "Checkout Session.",
    });
  }
  // Live path — the only place api.stripe.com is ever called.
  // Automatic tax is on in the payload (Stripe Tax, CA GST/HST
  // registered Nov 21, 2026); prices are tax-exclusive.
  const res = await fetch(STRIPE_CHECKOUT_SESSIONS_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: checkoutPayloadToFormBody(payload),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message =
      typeof (data as { error?: { message?: unknown } })?.error?.message ===
      "string"
        ? (data as { error: { message: string } }).error.message
        : `Stripe answered HTTP ${res.status}.`;
    return NextResponse.json(
      { error: "stripe_error", message },
      { status: 502 },
    );
  }
  return NextResponse.json({ mode: "live", tier, session: data });
}
