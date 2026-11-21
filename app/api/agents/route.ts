// Agent identity API (Pillar 1).
// GET  /api/agents -> registered agents with their credentials
//                    (fingerprints + masked values only) and exposed
//                    counts. No passphrase: no key material is served.
// POST /api/agents -> register one agent from CLI JSON, as produced by
//                    `aiscan agents inventory --json` / `agents map
//                    --json`: { name, type, config_path, repo, owner,
//                    credentials: [{ provider, credential_type,
//                    fingerprint, masked, source, env_var }] }.
//                    Fingerprints must be 16 lowercase hex chars;
//                    anything key-shaped is rejected.
//                    Free-tier cap (FREE-TIER-CAPS.md): 2 agent
//                    identity audits/day on Free (Starter: unlimited),
//                    tracked per hashed client IP for anonymous users.
//                    A cap hit answers 429 with the upgrade prompt.

import { NextResponse } from "next/server";
import { VaultNotConfigured } from "@/lib/vault-crypto";
import { checkRateLimit } from "@/lib/rate-limit";
import {
  capHitResponse,
  recordDailyCount,
  scopeKeyForRequest,
  USAGE_KEY_AUDITS,
} from "@/lib/usage";
import {
  enforceDailyCap,
  resolveWorkspacePlanId,
} from "@/lib/plan-enforcement";
import {
  listAgents,
  normalizeAgentCredential,
  registerAgent,
} from "@/lib/agents-db";

export const dynamic = "force-dynamic";

function notConfiguredResponse() {
  return NextResponse.json(
    {
      error:
        "Agent inventory is not configured: no Postgres database " +
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
  if (err instanceof Error) {
    return NextResponse.json({ error: err.message }, { status: 400 });
  }
  return NextResponse.json(
    { error: "Agent operation failed." },
    { status: 500 },
  );
}

export async function GET(req: Request) {
  const limited = checkRateLimit(req, "read");
  if (limited) return limited;
  try {
    const agents = await listAgents();
    return NextResponse.json({ agents });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: Request) {
  const limited = checkRateLimit(req, "mutate");
  if (limited) return limited;
  try {
    const body = await req.json();
    const name = typeof body?.name === "string" ? body.name : "";
    const type = typeof body?.type === "string" ? body.type : "";
    const configPath =
      typeof body?.config_path === "string" ? body.config_path : "";
    const repo = typeof body?.repo === "string" ? body.repo : "";
    const owner = typeof body?.owner === "string" ? body.owner : "";
    const rawCreds = Array.isArray(body?.credentials)
      ? body.credentials
      : [];
    const credentials = [];
    for (const raw of rawCreds) {
      const cred = normalizeAgentCredential(raw);
      if (cred) credentials.push(cred);
    }
    // Free-tier daily cap: 2 agent identity audits/day on Free.
    // Checked before the write, recorded only after it succeeds.
    const planId = await resolveWorkspacePlanId("default");
    const auditKey = `${USAGE_KEY_AUDITS}:${scopeKeyForRequest(req)}`;
    const auditCap = await enforceDailyCap(
      "default", planId, "audits_per_day", auditKey);
    if (!auditCap.allowed) {
      return capHitResponse(
        auditCap.message, auditCap.limit ?? 0, auditCap.used,
        auditCap.upgrade);
    }
    const agent = await registerAgent({
      name,
      type,
      configPath,
      repo,
      owner,
      credentials,
    });
    const auditsUsed = await recordDailyCount(auditKey);
    return NextResponse.json(
      {
        agent,
        usage: {
          audits: {
            used: auditsUsed,
            limit: auditCap.limit,
            resetsAt: auditCap.resetsAt,
          },
        },
      },
      { status: 201 },
    );
  } catch (err) {
    return errorResponse(err);
  }
}
