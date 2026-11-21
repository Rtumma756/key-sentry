// Fingerprint watch list API.
// GET    /api/fingerprints            -> active watched fingerprints (no passphrase: hashes only, safe to list)
// POST   /api/fingerprints            -> add { fingerprint, provider, label, adminPass } (admin only)
// DELETE /api/fingerprints            -> remove { fingerprint, adminPass } (admin only, soft delete)
// Fingerprints are SHA-256 first-16-hex of a key — a one-way hash, never
// a raw key. The admin gate reuses verifyAdminPass (VAULT_ADMIN_PASS),
// the same pattern as the vault admin routes.

import { NextResponse } from "next/server";
import { VaultNotConfigured, verifyAdminPass } from "@/lib/vault-crypto";
import { checkRateLimit } from "@/lib/rate-limit";
import {
  checkLimit,
  getMaxFingerprintsPerDay,
  recordUsage,
  USAGE_KEY_FINGERPRINTS_ADDED,
  usageLimitResponse,
} from "@/lib/usage";
import {
  addFingerprint,
  isValidFingerprint,
  listFingerprints,
  normalizeFingerprint,
  removeFingerprint,
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
    { error: "Fingerprint operation failed." },
    { status: 500 },
  );
}

export async function GET(req: Request) {
  const limited = checkRateLimit(req, "read");
  if (limited) return limited;
  try {
    const includeRemoved =
      new URL(req.url).searchParams.get("includeRemoved") === "1";
    const fingerprints = await listFingerprints(includeRemoved);
    return NextResponse.json({ fingerprints });
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
    const label = typeof body?.label === "string" ? body.label : "";
    const adminPass = typeof body?.adminPass === "string" ? body.adminPass : "";
    if (!fingerprint || !provider) {
      return NextResponse.json(
        { error: "Add needs a fingerprint and a provider." },
        { status: 400 },
      );
    }
    if (!isValidFingerprint(fingerprint)) {
      return NextResponse.json(
        {
          error:
            "Fingerprint must be 16 lowercase hex chars (SHA-256 of the " +
            "key, first 16). Use the CLI `fingerprint_watch.py hash` to " +
            "compute one — never send a raw key here.",
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
    // Daily usage cap (default 20/day, KEYSENTRY_MAX_FINGERPRINTS_PER_DAY).
    // Checked after the admin gate so unauthenticated callers cannot burn
    // the quota or probe the limit.
    const maxFingerprints = getMaxFingerprintsPerDay();
    const usage = await checkLimit(
      USAGE_KEY_FINGERPRINTS_ADDED,
      maxFingerprints,
    );
    if (!usage.allowed) {
      return usageLimitResponse(
        "fingerprints added",
        maxFingerprints,
        usage.count,
      );
    }
    const row = await addFingerprint(fingerprint, provider, label);
    if (!row) {
      return NextResponse.json(
        { error: "Could not add fingerprint." },
        { status: 500 },
      );
    }
    await recordUsage(USAGE_KEY_FINGERPRINTS_ADDED);
    return NextResponse.json({ fingerprint: row }, { status: 201 });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function DELETE(req: Request) {
  const limited = checkRateLimit(req, "mutate");
  if (limited) return limited;
  try {
    const body = await req.json();
    const fingerprint = normalizeFingerprint(
      typeof body?.fingerprint === "string" ? body.fingerprint : "",
    );
    const adminPass = typeof body?.adminPass === "string" ? body.adminPass : "";
    if (!fingerprint) {
      return NextResponse.json(
        { error: "Missing fingerprint." },
        { status: 400 },
      );
    }
    if (!verifyAdminPass(adminPass)) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    const removed = await removeFingerprint(fingerprint);
    if (!removed) {
      return NextResponse.json(
        { error: "No such active fingerprint." },
        { status: 404 },
      );
    }
    return NextResponse.json({ ok: true });
  } catch (err) {
    return errorResponse(err);
  }
}
