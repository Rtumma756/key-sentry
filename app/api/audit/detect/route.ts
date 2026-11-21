// Audit detections API.
// GET /api/audit/detect (admin passphrase required) -> run the five
// first detections over the stored events and return the alerts.

import { NextResponse } from "next/server";
import { VaultNotConfigured, verifyAdminPass } from "@/lib/vault-crypto";
import { checkRateLimit } from "@/lib/rate-limit";
import { listAuditEventsChained } from "@/lib/audit-db";
import { runAllDetections } from "@/lib/audit-detections";

export const dynamic = "force-dynamic";

function adminPassFrom(req: Request): string {
  return (
    req.headers.get("x-admin-pass") ??
    new URL(req.url).searchParams.get("adminPass") ??
    ""
  );
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
    const events = await listAuditEventsChained();
    const alerts = runAllDetections(events);
    return NextResponse.json({ eventCount: events.length, alerts });
  } catch (err) {
    if (err instanceof VaultNotConfigured) {
      return NextResponse.json(
        {
          error:
            "Audit trail is not configured: no Postgres database is " +
            "connected. In Vercel: Storage → Create → Postgres (free " +
            "tier), then redeploy.",
        },
        { status: 503 },
      );
    }
    return NextResponse.json(
      { error: "Audit detection run failed." },
      { status: 500 },
    );
  }
}
