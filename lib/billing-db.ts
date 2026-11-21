// Workspace plan store: Vercel Postgres (free tier, Neon-backed).
//
// One row per workspace: which plan it is on, the Stripe customer id
// (when billing is connected), and the subscription status. Plan
// changes come ONLY via the Stripe webhook (or a local dev override) —
// no route sets a plan directly.
//
// Tables are created on first use, following the ensureFingerprintTables
// pattern in lib/fingerprints-db.ts. No database? Helpers throw
// VaultNotConfigured and the routes answer 503 / fall back to the Free
// default instead of failing open.

import { sql } from "@vercel/postgres";
import { requireDbConfigured } from "./vault-db";
import { defaultWorkspacePlan } from "./plans";

export { defaultWorkspacePlan };

export interface WorkspacePlanRow {
  workspaceId: string;
  plan: string;
  stripeCustomerId: string | null;
  status: string;
  updatedAt: string;
}

export async function ensureWorkspacePlanTables(): Promise<void> {
  requireDbConfigured();
  await sql`
    CREATE TABLE IF NOT EXISTS workspace_plans (
      workspace_id TEXT PRIMARY KEY,
      plan TEXT NOT NULL DEFAULT 'free',
      stripe_customer_id TEXT,
      status TEXT NOT NULL DEFAULT 'free',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
}

function rowToWorkspacePlan(row: Record<string, unknown>): WorkspacePlanRow {
  return {
    workspaceId: String(row.workspace_id),
    plan: String(row.plan ?? "free"),
    stripeCustomerId:
      row.stripe_customer_id === null
        ? null
        : String(row.stripe_customer_id),
    status: String(row.status ?? "free"),
    updatedAt: String(row.updated_at),
  };
}

/** Current plan row for a workspace, or null when none is stored. */
export async function getWorkspacePlan(
  workspaceId = "default",
): Promise<WorkspacePlanRow | null> {
  await ensureWorkspacePlanTables();
  const { rows } = await sql`
    SELECT workspace_id, plan, stripe_customer_id, status, updated_at
    FROM workspace_plans
    WHERE workspace_id = ${workspaceId}`;
  return rows.length > 0 ? rowToWorkspacePlan(rows[0]) : null;
}

/**
 * Upsert a workspace plan (webhook-only in production). Returns the
 * stored row. Unknown plan ids are stored as-is — the read path
 * (lib/plans.ts getPlan) resolves anything unknown to Free.
 */
export async function upsertWorkspacePlan(
  workspaceId: string,
  plan: string,
  stripeCustomerId: string | null = null,
  status = "active",
): Promise<WorkspacePlanRow> {
  await ensureWorkspacePlanTables();
  const { rows } = await sql`
    INSERT INTO workspace_plans
      (workspace_id, plan, stripe_customer_id, status)
    VALUES (${workspaceId}, ${plan}, ${stripeCustomerId}, ${status})
    ON CONFLICT (workspace_id) DO UPDATE
      SET plan = EXCLUDED.plan,
          stripe_customer_id = COALESCE(
            EXCLUDED.stripe_customer_id,
            workspace_plans.stripe_customer_id),
          status = EXCLUDED.status,
          updated_at = now()
    RETURNING workspace_id, plan, stripe_customer_id, status, updated_at`;
  return rowToWorkspacePlan(rows[0]);
}
