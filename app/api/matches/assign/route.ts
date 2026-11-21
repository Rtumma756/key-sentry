// Assign a fingerprint match to a team member.
// POST /api/matches/assign -> { id, assignee, adminPass } (admin only)
//   assignee is a free-text team-member name (max 100 chars, trimmed);
//   an empty string clears the assignment.
// Returns the updated match plus its status history.
// Only fingerprints are handled here, never raw keys.

import { NextResponse } from "next/server";
import { VaultNotConfigured, verifyAdminPass } from "@/lib/vault-crypto";
import {
  assignMatch,
  getMatchHistory,
  MAX_ASSIGNEE_LENGTH,
} from "@/lib/fingerprints-db";

export const dynamic = "force-dynamic";

function notConfiguredResponse() {
  return NextResponse.json(
    {
      error:
        "Fingerprint monitoring is not configured: no Postgres database " +
        "is connected. In Vercel: Storage → Create → Postgres (free tier), " +
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
    { error: "Match operation failed." },
    { status: 500 },
  );
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const id = typeof body?.id === "number" ? body.id : NaN;
    const assignee = typeof body?.assignee === "string" ? body.assignee : "";
    const adminPass = typeof body?.adminPass === "string" ? body.adminPass : "";
    if (!Number.isFinite(id)) {
      return NextResponse.json({ error: "Missing match id." }, { status: 400 });
    }
    if (typeof body?.assignee !== "string") {
      return NextResponse.json(
        { error: "assignee must be a string." },
        { status: 400 },
      );
    }
    if (assignee.trim().length > MAX_ASSIGNEE_LENGTH) {
      return NextResponse.json(
        {
          error: `assignee must be at most ${MAX_ASSIGNEE_LENGTH} characters.`,
        },
        { status: 400 },
      );
    }
    if (!verifyAdminPass(adminPass)) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    const match = await assignMatch(id, assignee);
    if (!match) {
      return NextResponse.json({ error: "No such match." }, { status: 404 });
    }
    const history = await getMatchHistory(id);
    return NextResponse.json({ match, history });
  } catch (err) {
    return errorResponse(err);
  }
}
