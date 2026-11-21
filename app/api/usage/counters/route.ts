// Today's free-tier usage counters for the workspace (or hashed IP).
// GET /api/usage/counters -> { plan, planName, day, resetsAt, counters }
//   No auth needed for anonymous users — the caps are the same with or
//   without an account (the account saves history + badge; it is lead
//   capture, not a bigger free tier). Anonymous users are tracked by
//   hashed IP (never a raw IP); the response carries counts only.
//
//   counters.vibe_scans / audits / dashboard_saves: today's used +
//   the plan's daily limit (null = unlimited).
//   counters.mcp_queries: used is null — MCP queries are counted
//   locally by the MCP server (mcp_server.py), the web app cannot see
//   them; the limit is the plan's.
//   counters.audit_timeline / fingerprints / reports: the plan's
//   allowance (not a daily count).
//   Missing/unknown plan state defaults to Free with all free
//   capabilities working — the counters never break the dashboard.

import { NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/rate-limit";
import { getPlan } from "@/lib/plans";
import { resolveWorkspacePlanId } from "@/lib/plan-enforcement";
import {
  getDailyCounts,
  resetsAtUtc,
  scopeKeyForRequest,
  USAGE_KEY_AUDITS,
  USAGE_KEY_DASHBOARD_SAVES,
  USAGE_KEY_VIBE_SCANS,
} from "@/lib/usage";
import { usageDay } from "@/lib/usage-policy";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const limited = checkRateLimit(req, "read");
  if (limited) return limited;
  const planId = await resolveWorkspacePlanId("default");
  const plan = getPlan(planId);
  const scope = scopeKeyForRequest(req);
  const scanKey = `${USAGE_KEY_VIBE_SCANS}:${scope}`;
  const auditKey = `${USAGE_KEY_AUDITS}:${scope}`;
  const saveKey = `${USAGE_KEY_DASHBOARD_SAVES}:${scope}`;
  const counts = await getDailyCounts([scanKey, auditKey, saveKey]);
  return NextResponse.json({
    plan: planId,
    planName: plan.name,
    day: usageDay(),
    resetsAt: resetsAtUtc(),
    counters: {
      vibe_scans: { used: counts[scanKey] ?? 0, limit: plan.limits.scans_per_day },
      audits: { used: counts[auditKey] ?? 0, limit: plan.limits.audits_per_day },
      dashboard_saves: {
        used: counts[saveKey] ?? 0,
        limit: plan.limits.dashboard_saves_per_day,
      },
      mcp_queries: {
        used: null,
        limit: plan.limits.mcp_queries_per_day,
        note: "Tracked locally by the MCP server — the web app cannot see these queries.",
      },
      audit_timeline: {
        agentsLimit: plan.limits.audit_timeline_agents,
        daysLimit: plan.limits.audit_timeline_days,
      },
      fingerprints: { limit: plan.limits.fingerprints },
      reports: { limit: plan.limits.shareable_reports },
    },
  });
}
