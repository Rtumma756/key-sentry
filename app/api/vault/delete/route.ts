// Vault API: permanently remove one entry (admin only, audit-logged).
// POST /api/vault/delete { id, adminPass } -> { ok: true }
// The row (ciphertext included) is deleted; nothing about the key is
// returned. Unknown id answers 404; wrong passphrase answers 401.
// Use it to clear demo keys after a trial run, or to purge an entry
// that should never have been vaulted.

import { NextResponse } from "next/server";
import {
  vaultSetupStatus,
  VaultNotConfigured,
  verifyAdminPass,
} from "@/lib/vault-crypto";
import { deleteVaultEntry, insertAudit } from "@/lib/vault-db";

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
    const provider = await deleteVaultEntry(id);
    if (provider === null) {
      return NextResponse.json({ error: "No such vault entry." }, { status: 404 });
    }
    await insertAudit(id, "delete", "admin",
      `${provider} key removed from vault by admin`);
    return NextResponse.json({ ok: true });
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
