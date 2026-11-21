// Current workspace plan.
// GET /api/billing/plan?workspace=<id> -> { workspace, plan, ... }.
// Defaults to Free when no row exists — and when no database is
// configured at all, so the dashboard banner never breaks because
// billing is unconfigured. Plan changes come ONLY via the Stripe
// webhook (or a local dev override) — this route never sets a plan.

import { NextResponse } from "next/server";
import { VaultNotConfigured } from "@/lib/vault-crypto";
import { isBillingConfigured } from "@/lib/billing";
import { getPlan } from "@/lib/plans";
import {
  defaultWorkspacePlan,
  getWorkspacePlan,
} from "@/lib/billing-db";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const workspaceId =
    new URL(req.url).searchParams.get("workspace") || "default";
  let row = defaultWorkspacePlan(workspaceId);
  try {
    row = (await getWorkspacePlan(workspaceId)) ?? row;
  } catch (err) {
    // No database configured (or DB unreachable): stay on the Free
    // default. Billing being unconfigured must never break the read.
    if (!(err instanceof VaultNotConfigured)) {
      return NextResponse.json(
        { error: "Failed to read the workspace plan." },
        { status: 500 },
      );
    }
  }
  const plan = getPlan(row.plan);
  return NextResponse.json({
    workspace: row.workspaceId,
    plan: plan.id,
    name: plan.name,
    price: plan.price_label,
    limits: plan.limits,
    features: plan.features,
    status: row.status,
    billing_connected: isBillingConfigured(),
  });
}
