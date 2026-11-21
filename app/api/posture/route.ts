// Per-repo remediation posture.
// GET /api/posture -> { repos: [...], summary: {...} } (no passphrase)
// Counts only — no key material, no fingerprints beyond the 16-hex
// hashes already listed by /api/matches. Matches carry no confidence
// score, so open matches are bucketed by age of first_seen instead
// (<7d, 7-30d, >30d).

import { NextResponse } from "next/server";
import { VaultNotConfigured } from "@/lib/vault-crypto";
import { getPosture } from "@/lib/fingerprints-db";

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

export async function GET() {
  try {
    const posture = await getPosture();
    return NextResponse.json(posture);
  } catch (err) {
    if (err instanceof VaultNotConfigured) {
      return notConfiguredResponse();
    }
    return NextResponse.json(
      { error: "Posture report failed." },
      { status: 500 },
    );
  }
}
