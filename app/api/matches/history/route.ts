// Status history for one fingerprint match.
// GET /api/matches/history?id=123 -> { history: MatchStatusHistoryRow[] }
// No admin gate: history rows carry statuses, assignee names and notes
// only — no key material — the same as listing matches (GET /api/matches).
// Only fingerprints are handled here, never raw keys.

import { NextResponse } from "next/server";
import { VaultNotConfigured } from "@/lib/vault-crypto";
import { checkRateLimit } from "@/lib/rate-limit";
import { getMatchHistory } from "@/lib/fingerprints-db";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const limited = checkRateLimit(req, "read");
  if (limited) return limited;
  try {
    const id = Number(new URL(req.url).searchParams.get("id"));
    if (!Number.isFinite(id)) {
      return NextResponse.json(
        { error: "Missing match id." },
        { status: 400 },
      );
    }
    const history = await getMatchHistory(id);
    return NextResponse.json({ history });
  } catch (err) {
    if (err instanceof VaultNotConfigured) {
      return NextResponse.json(
        {
          error:
            "Fingerprint monitoring is not configured: no Postgres " +
            "database is connected. In Vercel: Storage → Create → " +
            "Postgres (free tier), then redeploy.",
        },
        { status: 503 },
      );
    }
    return NextResponse.json(
      { error: "History lookup failed." },
      { status: 500 },
    );
  }
}
