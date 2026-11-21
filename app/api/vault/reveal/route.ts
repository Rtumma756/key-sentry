// Vault API: reveal one full key (admin only, audit-logged).
// POST /api/vault/reveal  { id, adminPass } -> { value }
// The full key is returned exactly once, in this response body, and is
// never written to any log. A wrong passphrase answers 401 and is NOT
// audit-logged with the key (only the failed attempt is recorded, with no
// key material).

import { NextResponse } from "next/server";
import {
  decryptSecret,
  vaultSetupStatus,
  VaultNotConfigured,
  verifyAdminPass,
} from "@/lib/vault-crypto";
import { getVaultEntrySealed, insertAudit } from "@/lib/vault-db";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  try {
    const status = vaultSetupStatus();
    if (!status.configured) {
      return NextResponse.json(
        { error: "Vault is not configured.", setup: status },
        { status: 503 },
      );
    }
    const body = await req.json();
    const id = typeof body?.id === "string" ? body.id : "";
    const adminPass = typeof body?.adminPass === "string" ? body.adminPass : "";
    if (!id) {
      return NextResponse.json({ error: "Missing entry id." }, { status: 400 });
    }
    if (!verifyAdminPass(adminPass)) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    const sealed = await getVaultEntrySealed(id);
    if (!sealed) {
      return NextResponse.json({ error: "No such vault entry." }, { status: 404 });
    }
    const value = decryptSecret({ iv: sealed.iv, data: sealed.ciphertext });
    await insertAudit(id, "reveal", "admin",
      `${sealed.entry.provider} key revealed by admin`);
    return NextResponse.json({ value });
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
