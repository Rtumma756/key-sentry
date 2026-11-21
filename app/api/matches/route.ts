// Fingerprint matches API.
// GET   /api/matches                 -> matches, optional ?status=new|acknowledged|resolved
// POST  /api/matches                 -> record a sighting { fingerprint, provider, repo, file, line, adminPass }
//                                       (admin only — same VAULT_ADMIN_PASS gate as the vault admin routes)
// PATCH /api/matches                 -> change status { id, status: acknowledged|resolved, adminPass } (admin only)
// A brand-new match fires a Slack-compatible webhook alert when
// KEYSENTRY_ALERT_WEBHOOK is set (see lib/alerts.ts). Alert delivery
// failures never fail the recording — the match is stored first.
// Only fingerprints are accepted/transmitted here, never raw keys.

import { NextResponse } from "next/server";
import { VaultNotConfigured, verifyAdminPass } from "@/lib/vault-crypto";
import { sendMatchAlert } from "@/lib/alerts";
import { checkRateLimit } from "@/lib/rate-limit";
import {
  checkLimit,
  getMaxMatchesPerDay,
  recordUsage,
  USAGE_KEY_MATCHES_RECORDED,
  usageLimitResponse,
} from "@/lib/usage";
import {
  isValidFingerprint,
  listMatches,
  normalizeFingerprint,
  recordMatch,
  setMatchStatus,
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

export async function GET(req: Request) {
  try {
    const status = new URL(req.url).searchParams.get("status") ?? undefined;
    if (status && !["new", "acknowledged", "resolved"].includes(status)) {
      return NextResponse.json(
        { error: "status must be new, acknowledged, or resolved." },
        { status: 400 },
      );
    }
    const matches = await listMatches(status);
    return NextResponse.json({ matches });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: Request) {
  const limited = checkRateLimit(req, "mutate");
  if (limited) return limited;
  try {
    const body = await req.json();
    const fingerprint = normalizeFingerprint(
      typeof body?.fingerprint === "string" ? body.fingerprint : "",
    );
    const provider = typeof body?.provider === "string" ? body.provider : "";
    const repo = typeof body?.repo === "string" ? body.repo : "";
    const file = typeof body?.file === "string" ? body.file : "";
    const line = typeof body?.line === "number" ? body.line : 0;
    const adminPass = typeof body?.adminPass === "string" ? body.adminPass : "";
    if (!fingerprint) {
      return NextResponse.json(
        { error: "Record needs a fingerprint." },
        { status: 400 },
      );
    }
    if (!isValidFingerprint(fingerprint)) {
      return NextResponse.json(
        { error: "Fingerprint must be 16 lowercase hex chars." },
        { status: 400 },
      );
    }
    if (!verifyAdminPass(adminPass)) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    // Daily usage cap (default 500/day, KEYSENTRY_MAX_MATCHES_PER_DAY).
    // Checked after the admin gate so unauthenticated callers cannot burn
    // the quota or probe the limit.
    const maxMatches = getMaxMatchesPerDay();
    const usage = await checkLimit(USAGE_KEY_MATCHES_RECORDED, maxMatches);
    if (!usage.allowed) {
      return usageLimitResponse("matches recorded", maxMatches, usage.count);
    }
    const { match, isNew } = await recordMatch({
      fingerprint,
      provider,
      repo,
      file,
      line,
    });
    await recordUsage(USAGE_KEY_MATCHES_RECORDED);
    // Alert on first sighting only; a repeat sighting just refreshes
    // last_seen. Alert failure is best-effort and never fails the record.
    const alerted = isNew ? await sendMatchAlert(match) : false;
    return NextResponse.json({ match, isNew, alerted }, { status: 201 });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function PATCH(req: Request) {
  try {
    const body = await req.json();
    const id = typeof body?.id === "number" ? body.id : NaN;
    const status = typeof body?.status === "string" ? body.status : "";
    const adminPass = typeof body?.adminPass === "string" ? body.adminPass : "";
    if (!Number.isFinite(id)) {
      return NextResponse.json({ error: "Missing match id." }, { status: 400 });
    }
    if (status !== "acknowledged" && status !== "resolved") {
      return NextResponse.json(
        { error: "status must be acknowledged or resolved." },
        { status: 400 },
      );
    }
    if (!verifyAdminPass(adminPass)) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    const ok = await setMatchStatus(id, status);
    if (!ok) {
      return NextResponse.json({ error: "No such match." }, { status: 404 });
    }
    return NextResponse.json({ ok: true });
  } catch (err) {
    return errorResponse(err);
  }
}
