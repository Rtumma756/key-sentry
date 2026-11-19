// Server-only vault store: Vercel Postgres (free tier, Neon-backed).
//
// Tables are created on first use. The ciphertext is the only secret
// column; every read path that leaves this module strips it out, so list
// and audit responses are masked by construction. Full values are
// decrypted only inside the reveal route, after the admin check.
//
// No database? Every helper throws VaultNotConfigured and the routes
// answer 503 with setup instructions instead of failing open.

import { sql } from "@vercel/postgres";
import { VaultNotConfigured } from "./vault-crypto";

export interface VaultEntryRow {
  id: string;
  provider: string;
  masked: string;
  fingerprint: string;
  source: string;
  file: string;
  line: number;
  severity: string;
  status: "active" | "rotated" | "expired";
  storedAt: string;
  rotatedAt: string | null;
}

export interface VaultAuditRow {
  id: number;
  entryId: string | null;
  action: string;
  actor: string;
  detail: string;
  createdAt: string;
}

export function isDbConfigured(): boolean {
  return Boolean(process.env.POSTGRES_URL || process.env.DATABASE_URL);
}

export function requireDbConfigured(): void {
  if (!isDbConfigured()) {
    throw new VaultNotConfigured(
      "No Postgres database is connected. In Vercel: Storage → Create → " +
        "Postgres (free tier), then redeploy.",
    );
  }
}

export async function ensureVaultTables(): Promise<void> {
  requireDbConfigured();
  await sql`
    CREATE TABLE IF NOT EXISTS vault_entries (
      id TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      masked TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT '',
      file_path TEXT NOT NULL DEFAULT '',
      line_no INTEGER NOT NULL DEFAULT 0,
      severity TEXT NOT NULL DEFAULT 'high',
      status TEXT NOT NULL DEFAULT 'active',
      iv TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      rotated_at TIMESTAMPTZ
    )`;
  await sql`
    CREATE TABLE IF NOT EXISTS vault_audit (
      id SERIAL PRIMARY KEY,
      entry_id TEXT,
      action TEXT NOT NULL,
      actor TEXT NOT NULL DEFAULT 'admin',
      detail TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
  // One entry per distinct key (dedup by fingerprint, like the CLI).
  await sql`
    CREATE UNIQUE INDEX IF NOT EXISTS vault_entries_fingerprint_idx
    ON vault_entries (fingerprint)`;
}

function rowToEntry(row: Record<string, unknown>): VaultEntryRow {
  return {
    id: String(row.id),
    provider: String(row.provider),
    masked: String(row.masked),
    fingerprint: String(row.fingerprint),
    source: String(row.source ?? ""),
    file: String(row.file_path ?? ""),
    line: Number(row.line_no ?? 0),
    severity: String(row.severity ?? "high"),
    status: String(row.status ?? "active") as VaultEntryRow["status"],
    storedAt: String(row.created_at),
    rotatedAt: row.rotated_at ? String(row.rotated_at) : null,
  };
}

export async function listVaultEntries(): Promise<VaultEntryRow[]> {
  await ensureVaultTables();
  const { rows } = await sql`
    SELECT id, provider, masked, fingerprint, source, file_path, line_no,
           severity, status, created_at, rotated_at
    FROM vault_entries ORDER BY created_at DESC`;
  return rows.map(rowToEntry);
}

export async function insertVaultEntry(entry: {
  id: string;
  provider: string;
  masked: string;
  fingerprint: string;
  source: string;
  file: string;
  line: number;
  severity: string;
  iv: string;
  ciphertext: string;
}): Promise<void> {
  await ensureVaultTables();
  await sql`
    INSERT INTO vault_entries
      (id, provider, masked, fingerprint, source, file_path, line_no,
       severity, status, iv, ciphertext)
    VALUES (${entry.id}, ${entry.provider}, ${entry.masked},
            ${entry.fingerprint}, ${entry.source}, ${entry.file},
            ${entry.line}, ${entry.severity}, 'active',
            ${entry.iv}, ${entry.ciphertext})
    ON CONFLICT (fingerprint) DO NOTHING`;
}

/** Full row INCLUDING the sealed secret — reveal route only. */
export async function getVaultEntrySealed(
  id: string,
): Promise<{ entry: VaultEntryRow; iv: string; ciphertext: string } | null> {
  await ensureVaultTables();
  const { rows } = await sql`
    SELECT id, provider, masked, fingerprint, source, file_path, line_no,
           severity, status, created_at, rotated_at, iv, ciphertext
    FROM vault_entries WHERE id = ${id}`;
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    entry: rowToEntry(row),
    iv: String(row.iv),
    ciphertext: String(row.ciphertext),
  };
}

export async function setVaultEntryStatus(
  id: string,
  status: "rotated" | "expired",
): Promise<boolean> {
  await ensureVaultTables();
  const { rowCount } = await sql`
    UPDATE vault_entries
    SET status = ${status}, rotated_at = now()
    WHERE id = ${id}`;
  return (rowCount ?? 0) > 0;
}

export async function insertAudit(
  entryId: string | null,
  action: string,
  actor: string,
  detail: string,
): Promise<void> {
  await ensureVaultTables();
  await sql`
    INSERT INTO vault_audit (entry_id, action, actor, detail)
    VALUES (${entryId}, ${action}, ${actor}, ${detail})`;
}

export async function listAudit(limit = 100): Promise<VaultAuditRow[]> {
  await ensureVaultTables();
  const { rows } = await sql`
    SELECT id, entry_id, action, actor, detail, created_at
    FROM vault_audit ORDER BY created_at DESC, id DESC LIMIT ${limit}`;
  return rows.map((r) => ({
    id: Number(r.id),
    entryId: r.entry_id ? String(r.entry_id) : null,
    action: String(r.action),
    actor: String(r.actor),
    detail: String(r.detail ?? ""),
    createdAt: String(r.created_at),
  }));
}
