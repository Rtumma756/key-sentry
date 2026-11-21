// Vault API: list (masked) + store.
// GET  /api/vault        -> masked entries, no passphrase needed
// POST /api/vault        -> store one finding (explicit user action only)
// The full key is accepted ONLY in the POST body, encrypted server-side
// with AES-256-GCM, and never logged or returned. Masked value and
// fingerprint are recomputed server-side from the value — the client is
// not trusted to label them.

import { NextResponse } from "next/server";
import { randomUUID } from "node:crypto";
import { maskKey } from "@/lib/detectors";
import {
  encryptSecret,
  sha256Hex,
  vaultSetupStatus,
  VaultNotConfigured,
} from "@/lib/vault-crypto";
import {
  insertAudit,
  insertVaultEntry,
  listVaultEntries,
} from "@/lib/vault-db";

export const dynamic = "force-dynamic";

function notConfiguredResponse() {
  const status = vaultSetupStatus();
  return NextResponse.json(
    { error: "Vault is not configured.", setup: status },
    { status: 503 },
  );
}

function errorResponse(err: unknown) {
  if (err instanceof VaultNotConfigured) {
    return notConfiguredResponse();
  }
  // Never leak internals (or key material) in an error body.
  return NextResponse.json(
    { error: "Vault operation failed." },
    { status: 500 },
  );
}

export async function GET() {
  try {
    const status = vaultSetupStatus();
    if (!status.configured) return notConfiguredResponse();
    const entries = await listVaultEntries();
    return NextResponse.json({ entries });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: Request) {
  try {
    const status = vaultSetupStatus();
    if (!status.configured) return notConfiguredResponse();
    const body = await req.json();
    const value = typeof body?.value === "string" ? body.value : "";
    const provider = typeof body?.provider === "string" ? body.provider : "";
    if (!value || !provider) {
      return NextResponse.json(
        { error: "Store needs a provider and a key value." },
        { status: 400 },
      );
    }
    // Scope boundary, server-side: the UI only offers "Store in vault" for
    // findings from a scan the user ran themselves (paste or their own
    // repo). Demo TESTFAKE keys are fine. Never auto-store repo-scan
    // findings — the button click is the explicit consent.
    const sealed = encryptSecret(value);
    const entry = {
      id: `vlt_${randomUUID().replace(/-/g, "").slice(0, 12)}`,
      provider,
      masked: maskKey(value),
      fingerprint: sha256Hex(value).slice(0, 16),
      source: typeof body?.source === "string" ? body.source : "",
      file: typeof body?.file === "string" ? body.file : "",
      line: typeof body?.line === "number" ? body.line : 0,
      severity: typeof body?.severity === "string" ? body.severity : "high",
      iv: sealed.iv,
      ciphertext: sealed.data,
    };
    await insertVaultEntry(entry);
    await insertAudit(entry.id, "store", "user",
      `${provider} key stored from ${entry.source || "scan"}`);
    const { iv: _iv, ciphertext: _ct, ...publicEntry } = entry;
    return NextResponse.json({ entry: publicEntry }, { status: 201 });
  } catch (err) {
    return errorResponse(err);
  }
}
