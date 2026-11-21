// Public read of one stored vibe-scan report (masked only).
// GET /api/vibe-scan/[id] -> stored report, or 404.

import { NextResponse } from "next/server";
import { VaultNotConfigured } from "@/lib/vault-crypto";
import { checkRateLimit } from "@/lib/rate-limit";
import { getVibeReport } from "@/lib/vibe-reports-db";

export const dynamic = "force-dynamic";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const limited = checkRateLimit(req, "read");
  if (limited) return limited;
  try {
    const { id } = await params;
    const report = await getVibeReport(id);
    if (!report) {
      return NextResponse.json(
        { error: "Vibe report not found." },
        { status: 404 },
      );
    }
    return NextResponse.json(report);
  } catch (err) {
    if (err instanceof VaultNotConfigured) {
      return NextResponse.json(
        {
          error:
            "Vibe reports are not configured: no Postgres database is " +
            "connected. In Vercel: Storage → Create → Postgres (free " +
            "tier), then redeploy.",
        },
        { status: 503 },
      );
    }
    return NextResponse.json(
      { error: "Could not load the vibe report." },
      { status: 500 },
    );
  }
}
