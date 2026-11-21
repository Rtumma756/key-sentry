// Stripe webhook stub.
// POST /api/billing/webhook — Stripe posts subscription events here.
//   * No STRIPE_WEBHOOK_SECRET: 503 billing_not_connected.
//   * Bad signature: 400 invalid_signature (nothing is applied).
//   * checkout.session.completed: upserts workspace_plans from the
//     session metadata { tier, workspace_id }.
//   * customer.subscription.updated: upserts workspace_plans, tier from
//     the subscription metadata, else from the Price ID.
//   * Any other event type: 200 { received: true, ignored: true }.
// Plan changes come ONLY via this webhook (or a local dev override) —
// no route sets a plan directly. No network calls to Stripe are made
// here; the signature is verified locally with node:crypto.

import { NextResponse } from "next/server";
import { VaultNotConfigured } from "@/lib/vault-crypto";
import {
  billingNotConnectedResponse,
  isWebhookConfigured,
  tierForPriceId,
  verifyWebhookSignature,
} from "@/lib/billing";
import { getPlanId, type PlanId } from "@/lib/plans";
import { upsertWorkspacePlan } from "@/lib/billing-db";

export const dynamic = "force-dynamic";

type StripeEvent = {
  type?: string;
  data?: { object?: Record<string, unknown> };
};

function eventWorkspaceId(obj: Record<string, unknown>): string {
  const meta = obj.metadata as Record<string, unknown> | undefined;
  const workspaceId = meta?.workspace_id;
  return typeof workspaceId === "string" && workspaceId
    ? workspaceId
    : "default";
}

function eventTier(obj: Record<string, unknown>): PlanId | null {
  const meta = obj.metadata as Record<string, unknown> | undefined;
  if (typeof meta?.tier === "string") {
    return getPlanId(meta.tier) as PlanId;
  }
  // customer.subscription.updated: find the tier from the first item's
  // Price ID (env-configured STRIPE_PRICE_*).
  const items = obj.items as
    | { data?: { price?: { id?: string } }[] }
    | undefined;
  const priceId = items?.data?.[0]?.price?.id;
  if (typeof priceId === "string") {
    return tierForPriceId(priceId);
  }
  return null;
}

function eventCustomerId(obj: Record<string, unknown>): string | null {
  return typeof obj.customer === "string" ? obj.customer : null;
}

export async function POST(req: Request) {
  if (!isWebhookConfigured()) {
    return billingNotConnectedResponse();
  }
  const rawBody = await req.text();
  const signature = req.headers.get("stripe-signature") ?? "";
  const secret = process.env.STRIPE_WEBHOOK_SECRET ?? "";
  if (!verifyWebhookSignature(rawBody, signature, secret)) {
    return NextResponse.json(
      { error: "invalid_signature" },
      { status: 400 },
    );
  }
  let event: StripeEvent;
  try {
    event = JSON.parse(rawBody) as StripeEvent;
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body." },
      { status: 400 },
    );
  }
  const type = event.type ?? "";
  if (
    type !== "checkout.session.completed" &&
    type !== "customer.subscription.updated"
  ) {
    return NextResponse.json({ received: true, ignored: true });
  }
  const obj = event.data?.object ?? {};
  const tier = eventTier(obj);
  if (tier === null) {
    return NextResponse.json(
      { error: "Could not determine the tier from this event." },
      { status: 400 },
    );
  }
  const workspaceId = eventWorkspaceId(obj);
  const status =
    type === "checkout.session.completed"
      ? "active"
      : typeof obj.status === "string"
        ? obj.status
        : "active";
  try {
    const row = await upsertWorkspacePlan(
      workspaceId,
      tier,
      eventCustomerId(obj),
      status,
    );
    return NextResponse.json({
      received: true,
      workspace: row.workspaceId,
      plan: row.plan,
      status: row.status,
    });
  } catch (err) {
    if (err instanceof VaultNotConfigured) {
      return NextResponse.json(
        {
          error:
            "Billing database is not configured: no Postgres database " +
            "is connected. In Vercel: Storage → Create → Postgres " +
            "(free tier), then redeploy.",
        },
        { status: 503 },
      );
    }
    return NextResponse.json(
      { error: "Failed to record the plan change." },
      { status: 500 },
    );
  }
}
