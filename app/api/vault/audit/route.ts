// Vault API: append-only audit log (masked only — never holds a full key).
// GET /api/vault/audit -> { entries: [...] }

import { NextResponse } from "next/server";
import { vaultSetupStatus, VaultNotConfigured } from "@/lib/vault-crypto";
import { listAudit } from "@/lib/vault-db";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const status = vaultSetupStatus();
    if (!status.configured) {
      return NextResponse.json(
        { error: "Vault is not configured.", setup: status },
        { status: 503 },
      );
    }
    const entries = await listAudit();
    return NextResponse.json({ entries });
  } catch (err) {
    if (err instanceof VaultNotConfigured) {
      return NextResponse.json(
        { error: "Vault is not configured.", setup: vaultSetupStatus() },
        { status: 503 },
      );
    }
    return NextResponse.json(
      { error: "Vault operation failed." },
      { status: 500 },
    );
  }
}
