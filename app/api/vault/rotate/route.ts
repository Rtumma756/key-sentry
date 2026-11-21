// Vault API: mark an entry rotated or expired (admin only, audit-logged).
// POST /api/vault/rotate { id, adminPass, status: "rotated" | "expired" }

import { NextResponse } from "next/server";
import {
  vaultSetupStatus,
  VaultNotConfigured,
  verifyAdminPass,
} from "@/lib/vault-crypto";
import { insertAudit, setVaultEntryStatus } from "@/lib/vault-db";

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
    const newStatus = body?.status;
    if (!id || (newStatus !== "rotated" && newStatus !== "expired")) {
      return NextResponse.json(
        { error: "Need an entry id and status rotated|expired." },
        { status: 400 },
      );
    }
    if (!verifyAdminPass(adminPass)) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    const updated = await setVaultEntryStatus(id, newStatus);
    if (!updated) {
      return NextResponse.json({ error: "No such vault entry." }, { status: 404 });
    }
    await insertAudit(id, newStatus, "admin", `entry marked ${newStatus}`);
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
