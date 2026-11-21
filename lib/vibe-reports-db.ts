// Vibe-scan report store: Vercel Postgres (free tier, Neon-backed).
//
// One row per scan: repo URL, masked-only findings, summary, and the
// Pillar 3 audit events (one per finding). Findings carry masked values
// (prefix4) + SHA-256 fingerprints only — NEVER a raw key, by
// construction: the scan pipeline never puts a full value in a finding.
//
// Tables are created on first use, following the ensureFingerprintTables
// pattern in lib/fingerprints-db.ts. No database? Helpers throw
// VaultNotConfigured and the routes answer 503 instead of failing open.

import { sql } from "@vercel/postgres";
import { requireDbConfigured } from "./vault-db";
import type { VibeAuditEvent, VibeFinding } from "./vibe-checks";

export interface VibeReportSummary {
  total: number;
  bySeverity: Record<string, number>;
}

export interface VibeReportRow {
  id: string;
  repoUrl: string;
  summary: VibeReportSummary;
  findings: VibeFinding[];
  auditEvents: VibeAuditEvent[];
  filesScanned: number;
  createdAt: string;
}

export async function ensureVibeReportTables(): Promise<void> {
  requireDbConfigured();
  await sql`
    CREATE TABLE IF NOT EXISTS vibe_reports (
      id TEXT PRIMARY KEY,
      repo_url TEXT NOT NULL,
      summary JSONB NOT NULL,
      findings JSONB NOT NULL,
      audit_events JSONB NOT NULL,
      files_scanned INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
  await sql`
    CREATE INDEX IF NOT EXISTS vibe_reports_repo_idx
    ON vibe_reports (repo_url, created_at DESC)`;
}

function rowToReport(row: Record<string, unknown>): VibeReportRow {
  const parse = (v: unknown): unknown =>
    typeof v === "string" ? JSON.parse(v) : v;
  return {
    id: String(row.id),
    repoUrl: String(row.repo_url),
    summary: parse(row.summary) as VibeReportSummary,
    findings: parse(row.findings) as VibeFinding[],
    auditEvents: parse(row.audit_events) as VibeAuditEvent[],
    filesScanned: Number(row.files_scanned ?? 0),
    createdAt: String(row.created_at),
  };
}

/** Store a completed scan report (masked-only by construction). */
export async function saveVibeReport(report: {
  id: string;
  repoUrl: string;
  summary: VibeReportSummary;
  findings: VibeFinding[];
  auditEvents: VibeAuditEvent[];
  filesScanned: number;
}): Promise<VibeReportRow> {
  await ensureVibeReportTables();
  const { rows } = await sql`
    INSERT INTO vibe_reports
      (id, repo_url, summary, findings, audit_events, files_scanned)
    VALUES (${report.id}, ${report.repoUrl},
            ${JSON.stringify(report.summary)},
            ${JSON.stringify(report.findings)},
            ${JSON.stringify(report.auditEvents)},
            ${report.filesScanned})
    RETURNING id, repo_url, summary, findings, audit_events,
              files_scanned, created_at`;
  return rowToReport(rows[0]);
}

/** Public read of one stored report (masked only). Null when missing. */
export async function getVibeReport(
  id: string,
): Promise<VibeReportRow | null> {
  await ensureVibeReportTables();
  const { rows } = await sql`
    SELECT id, repo_url, summary, findings, audit_events,
           files_scanned, created_at
    FROM vibe_reports WHERE id = ${id}`;
  if (rows.length === 0) return null;
  return rowToReport(rows[0]);
}
