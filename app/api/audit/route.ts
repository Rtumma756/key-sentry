// Audit timeline API.
// GET    /api/audit?agent=&session=&run=&limit=  -> timeline events
//         (admin passphrase required — timeline read is passphrase-gated
//         for the pilot, same VAULT_ADMIN_PASS gate as the vault)
// POST   /api/audit { event, adminPass }          -> ingest one event
//         (server-side redaction + validation, hash-chained on insert)
//
// Events are redacted BEFORE write: argument values never reach the
// table, only key names in arg_keys. An event that still looks secret
// after redaction is rejected with 400 and stored nowhere.

import { NextResponse } from "next/server";
import { VaultNotConfigured, verifyAdminPass } from "@/lib/vault-crypto";
import { checkRateLimit } from "@/lib/rate-limit";
import { restrictAuditTimeline } from "@/lib/plans";
import { resolveWorkspacePlanId } from "@/lib/plan-enforcement";
import {
  insertAuditEvent,
  listAuditEvents,
} from "@/lib/audit-db";
import {
  redactAuditEvent,
  validateAuditEvent,
} from "@/lib/audit-redact";

export const dynamic = "force-dynamic";

function notConfiguredResponse() {
  return NextResponse.json(
    {
      error:
        "Audit trail is not configured: no Postgres database is " +
        "connected. In Vercel: Storage → Create → Postgres (free tier), " +
        "then redeploy.",
    },
    { status: 503 },
  );
}

function errorResponse(err: unknown) {
  if (err instanceof VaultNotConfigured) {
    return notConfiguredResponse();
  }
  return NextResponse.json(
    { error: "Audit operation failed." },
    { status: 500 },
  );
}

/** Admin passphrase from the x-admin-pass header, else the adminPass
 * query param (GET) / body field (POST). */
function adminPassFrom(req: Request, body?: Record<string, unknown>): string {
  const header = req.headers.get("x-admin-pass");
  if (header) return header;
  const query = new URL(req.url).searchParams.get("adminPass");
  if (query) return query;
  if (body && typeof body["adminPass"] === "string") {
    return body["adminPass"] as string;
  }
  return "";
}

export async function GET(req: Request) {
  const limited = checkRateLimit(req, "read");
  if (limited) return limited;
  try {
    if (!verifyAdminPass(adminPassFrom(req))) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    const params = new URL(req.url).searchParams;
    const rows = await listAuditEvents({
      agent: params.get("agent") ?? undefined,
      session: params.get("session") ?? undefined,
      run: params.get("run") ?? undefined,
      limit: params.get("limit") ? Number(params.get("limit")) : undefined,
    });
    // Free-tier timeline restriction (FREE-TIER-CAPS.md): Free sees
    // one agent and the last 7 days of events; paid tiers see their
    // own limits. Events outside the allowance are excluded — never
    // an error, never a dead end — and the response names the upgrade
    // that lifts the wall (Team for a 2nd agent, Maker for older
    // events on Free).
    const planId = await resolveWorkspacePlanId("default");
    const restricted = restrictAuditTimeline(
      rows.map((r) => r.event), planId);
    return NextResponse.json({
      events: restricted.events,
      restricted: {
        allowedAgent: restricted.allowedAgent,
        windowDays: restricted.windowDays,
        excludedAgents: restricted.excludedAgents,
        excludedOlder: restricted.excludedOlder,
      },
      upgrade: restricted.upgrade,
    });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: Request) {
  const limited = checkRateLimit(req, "mutate");
  if (limited) return limited;
  try {
    const body = (await req.json()) as Record<string, unknown>;
    if (!verifyAdminPass(adminPassFrom(req, body))) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    if (!body || typeof body["event"] !== "object" || body["event"] === null) {
      return NextResponse.json(
        { error: "Ingest needs an event object." },
        { status: 400 },
      );
    }
    // Redaction BEFORE write, then validation as the backstop.
    let redacted;
    try {
      redacted = redactAuditEvent(body["event"]);
    } catch (err) {
      return NextResponse.json(
        { error: err instanceof Error ? err.message : "Bad event." },
        { status: 400 },
      );
    }
    // The chain sets prev_hash / event_hash at insert; supply the
    // genesis hash here so validation can run on the full shape.
    redacted["prev_hash"] = "0".repeat(64);
    const errors = validateAuditEvent(redacted);
    if (errors.length > 0) {
      return NextResponse.json(
        { error: "Event rejected: " + errors.join("; ") },
        { status: 400 },
      );
    }
    delete redacted["prev_hash"];
    const row = await insertAuditEvent(redacted);
    if (!row) {
      return NextResponse.json(
        { duplicate: true, event: redacted },
        { status: 200 },
      );
    }
    return NextResponse.json({ event: row.event }, { status: 201 });
  } catch (err) {
    return errorResponse(err);
  }
}
