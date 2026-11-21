// Fingerprint monitoring store: Vercel Postgres (free tier, Neon-backed).
//
// Only SHA-256 fingerprints (first 16 hex chars) are stored — NEVER a raw
// key. A fingerprint is a one-way hash: listing it is safe, which is why
// GET /api/fingerprints needs no passphrase. Adding, removing, and
// acknowledging matches are admin-only (VAULT_ADMIN_PASS, same gate as
// the vault admin routes).
//
// Tables are created on first use, following the ensureVaultTables
// pattern in lib/vault-db.ts. No database? Helpers throw
// VaultNotConfigured and the routes answer 503 instead of failing open.

import { sql } from "@vercel/postgres";
import { requireDbConfigured } from "./vault-db";

export interface FingerprintRow {
  id: number;
  fingerprint: string;
  provider: string;
  label: string;
  status: "active" | "removed";
  createdAt: string;
}

export interface FingerprintMatchRow {
  id: number;
  fingerprint: string;
  provider: string;
  repo: string;
  file: string;
  line: number;
  firstSeen: string;
  lastSeen: string;
  status: "new" | "acknowledged" | "resolved";
  /** Free-text team-member name the match is assigned to ('' = unassigned). */
  assignee: string;
}

export interface MatchStatusHistoryRow {
  id: number;
  matchId: number;
  oldStatus: string;
  newStatus: string;
  changedBy: string;
  note: string;
  changedAt: string;
}

export interface PostureRepo {
  repo: string;
  total: number;
  open: number;
  resolved: number;
  /** Counts by provider (all statuses). */
  byProvider: Record<string, number>;
  /** Open matches by age of first_seen. */
  openByAge: { lt7d: number; d7to30: number; gt30d: number };
  /** first_seen of the oldest still-open match, or null when none open. */
  oldestOpen: string | null;
}

export interface Posture {
  repos: PostureRepo[];
  summary: {
    totalMatches: number;
    openMatches: number;
    resolvedMatches: number;
    repoCount: number;
    /** openMatches / totalMatches, 0 when there are no matches. */
    openRate: number;
  };
}

/** A fingerprint is exactly 16 lowercase hex chars (sha256 hex, first 16). */
export function isValidFingerprint(value: string): boolean {
  return /^[0-9a-f]{16}$/.test(value);
}

export function normalizeFingerprint(value: string): string {
  return value.trim().toLowerCase();
}

export async function ensureFingerprintTables(): Promise<void> {
  requireDbConfigured();
  await sql`
    CREATE TABLE IF NOT EXISTS fingerprints (
      id SERIAL PRIMARY KEY,
      fingerprint TEXT NOT NULL UNIQUE,
      provider TEXT NOT NULL DEFAULT '',
      label TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
  await sql`
    CREATE TABLE IF NOT EXISTS fingerprint_matches (
      id SERIAL PRIMARY KEY,
      fingerprint TEXT NOT NULL,
      provider TEXT NOT NULL DEFAULT '',
      repo TEXT NOT NULL DEFAULT '',
      file TEXT NOT NULL DEFAULT '',
      line_no INTEGER NOT NULL DEFAULT 0,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
      status TEXT NOT NULL DEFAULT 'new'
    )`;
  // One open sighting per (key, location): repeat sightings of the same
  // key in the same file just refresh last_seen instead of piling up rows.
  await sql`
    CREATE UNIQUE INDEX IF NOT EXISTS fingerprint_matches_location_idx
    ON fingerprint_matches (fingerprint, repo, file, line_no)`;
  // Team basics (Nov 2026): assignee on matches + status history.
  // ALTER ... ADD COLUMN IF NOT EXISTS keeps this backward-compatible
  // with tables created before the column existed.
  await sql`
    ALTER TABLE fingerprint_matches
    ADD COLUMN IF NOT EXISTS assignee TEXT NOT NULL DEFAULT ''`;
  await sql`
    CREATE TABLE IF NOT EXISTS match_status_history (
      id SERIAL PRIMARY KEY,
      match_id INTEGER NOT NULL,
      old_status TEXT NOT NULL DEFAULT '',
      new_status TEXT NOT NULL DEFAULT '',
      changed_by TEXT NOT NULL DEFAULT 'admin',
      note TEXT NOT NULL DEFAULT '',
      changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
  await sql`
    CREATE INDEX IF NOT EXISTS match_status_history_match_idx
    ON match_status_history (match_id, changed_at)`;
}

function rowToFingerprint(row: Record<string, unknown>): FingerprintRow {
  return {
    id: Number(row.id),
    fingerprint: String(row.fingerprint),
    provider: String(row.provider ?? ""),
    label: String(row.label ?? ""),
    status: String(row.status ?? "active") as FingerprintRow["status"],
    createdAt: String(row.created_at),
  };
}

function rowToMatch(row: Record<string, unknown>): FingerprintMatchRow {
  return {
    id: Number(row.id),
    fingerprint: String(row.fingerprint),
    provider: String(row.provider ?? ""),
    repo: String(row.repo ?? ""),
    file: String(row.file ?? ""),
    line: Number(row.line_no ?? 0),
    firstSeen: String(row.first_seen),
    lastSeen: String(row.last_seen),
    status: String(row.status ?? "new") as FingerprintMatchRow["status"],
    assignee: String(row.assignee ?? ""),
  };
}

function rowToHistory(row: Record<string, unknown>): MatchStatusHistoryRow {
  return {
    id: Number(row.id),
    matchId: Number(row.match_id),
    oldStatus: String(row.old_status ?? ""),
    newStatus: String(row.new_status ?? ""),
    changedBy: String(row.changed_by ?? "admin"),
    note: String(row.note ?? ""),
    changedAt: String(row.changed_at),
  };
}

/** Max length for a free-text assignee name (enforced by assignMatch). */
export const MAX_ASSIGNEE_LENGTH = 100;

/** Trim an assignee name. Throws when it exceeds MAX_ASSIGNEE_LENGTH. */
export function normalizeAssignee(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length > MAX_ASSIGNEE_LENGTH) {
    throw new Error(
      `Assignee must be at most ${MAX_ASSIGNEE_LENGTH} characters.`,
    );
  }
  return trimmed;
}

/** Insert one history row. oldStatus == newStatus marks a non-status change (e.g. assignment). */
async function recordHistory(
  matchId: number,
  oldStatus: string,
  newStatus: string,
  changedBy: string,
  note: string,
): Promise<void> {
  await sql`
    INSERT INTO match_status_history
      (match_id, old_status, new_status, changed_by, note)
    VALUES (${matchId}, ${oldStatus}, ${newStatus}, ${changedBy}, ${note})`;
}

/** Status history for one match, oldest first. */
export async function getMatchHistory(
  matchId: number,
): Promise<MatchStatusHistoryRow[]> {
  await ensureFingerprintTables();
  const { rows } = await sql`
    SELECT id, match_id, old_status, new_status, changed_by, note, changed_at
    FROM match_status_history
    WHERE match_id = ${matchId}
    ORDER BY changed_at ASC, id ASC`;
  return rows.map(rowToHistory);
}

export async function listFingerprints(
  includeRemoved = false,
): Promise<FingerprintRow[]> {
  await ensureFingerprintTables();
  const { rows } = includeRemoved
    ? await sql`
        SELECT id, fingerprint, provider, label, status, created_at
        FROM fingerprints ORDER BY created_at DESC`
    : await sql`
        SELECT id, fingerprint, provider, label, status, created_at
        FROM fingerprints WHERE status = 'active' ORDER BY created_at DESC`;
  return rows.map(rowToFingerprint);
}

/**
 * Add a fingerprint to watch. Returns the row, or null when this
 * fingerprint is already watched (re-activates a previously removed one).
 */
export async function addFingerprint(
  fingerprint: string,
  provider: string,
  label: string,
): Promise<FingerprintRow | null> {
  await ensureFingerprintTables();
  const { rows } = await sql`
    INSERT INTO fingerprints (fingerprint, provider, label, status)
    VALUES (${fingerprint}, ${provider}, ${label}, 'active')
    ON CONFLICT (fingerprint) DO UPDATE
      SET provider = EXCLUDED.provider,
          label = EXCLUDED.label,
          status = 'active'
    RETURNING id, fingerprint, provider, label, status, created_at`;
  return rows.length > 0 ? rowToFingerprint(rows[0]) : null;
}

/**
 * Remove a fingerprint from the watch list (soft delete: status ->
 * 'removed', so past matches stay traceable). Returns false when the
 * fingerprint was not on the list.
 */
export async function removeFingerprint(
  fingerprint: string,
): Promise<boolean> {
  await ensureFingerprintTables();
  const { rowCount } = await sql`
    UPDATE fingerprints SET status = 'removed'
    WHERE fingerprint = ${fingerprint} AND status = 'active'`;
  return (rowCount ?? 0) > 0;
}

export async function listMatches(
  status?: string,
  limit = 200,
): Promise<FingerprintMatchRow[]> {
  await ensureFingerprintTables();
  const { rows } = status
    ? await sql`
        SELECT id, fingerprint, provider, repo, file, line_no,
               first_seen, last_seen, status, assignee
        FROM fingerprint_matches
        WHERE status = ${status}
        ORDER BY last_seen DESC LIMIT ${limit}`
    : await sql`
        SELECT id, fingerprint, provider, repo, file, line_no,
               first_seen, last_seen, status, assignee
        FROM fingerprint_matches
        ORDER BY last_seen DESC LIMIT ${limit}`;
  return rows.map(rowToMatch);
}

export interface RecordedMatch {
  match: FingerprintMatchRow;
  /** True only when this sighting created a brand-new match row. */
  isNew: boolean;
}

/**
 * Record a sighting of a watched fingerprint. Same (fingerprint, repo,
 * file, line) seen again only refreshes last_seen — and re-opens a
 * resolved match back to 'new', since the key is exposed again.
 * Returns the match row plus whether it is new (drives alerting).
 */
export async function recordMatch(match: {
  fingerprint: string;
  provider: string;
  repo: string;
  file: string;
  line: number;
}): Promise<RecordedMatch> {
  await ensureFingerprintTables();
  const existing = await sql`
    SELECT id, fingerprint, provider, repo, file, line_no,
           first_seen, last_seen, status, assignee
    FROM fingerprint_matches
    WHERE fingerprint = ${match.fingerprint}
      AND repo = ${match.repo}
      AND file = ${match.file}
      AND line_no = ${match.line}`;
  if (existing.rows.length > 0) {
    const oldStatus = String(existing.rows[0].status ?? "new");
    const { rows } = await sql`
      UPDATE fingerprint_matches
      SET last_seen = now(),
          status = CASE WHEN status = 'resolved' THEN 'new' ELSE status END
      WHERE fingerprint = ${match.fingerprint}
        AND repo = ${match.repo}
        AND file = ${match.file}
        AND line_no = ${match.line}
      RETURNING id, fingerprint, provider, repo, file, line_no,
                first_seen, last_seen, status, assignee`;
    const updated = rowToMatch(rows[0]);
    // Re-sighting a resolved key re-opens it — a status change, so it
    // gets a history row like any other.
    if (oldStatus === "resolved" && updated.status === "new") {
      await recordHistory(
        updated.id,
        "resolved",
        "new",
        "system",
        "re-sighted in a later scan after resolution",
      );
    }
    return { match: updated, isNew: false };
  }
  const { rows } = await sql`
    INSERT INTO fingerprint_matches
      (fingerprint, provider, repo, file, line_no)
    VALUES (${match.fingerprint}, ${match.provider}, ${match.repo},
            ${match.file}, ${match.line})
    RETURNING id, fingerprint, provider, repo, file, line_no,
              first_seen, last_seen, status, assignee`;
  return { match: rowToMatch(rows[0]), isNew: true };
}

/**
 * Change a match's status and record it in match_status_history.
 * Returns null when no such match exists. A no-op (same status) still
 * returns the row but records no history.
 */
export async function setMatchStatus(
  id: number,
  status: "acknowledged" | "resolved",
  changedBy = "admin",
  note = "",
): Promise<FingerprintMatchRow | null> {
  await ensureFingerprintTables();
  const current = await sql`
    SELECT id, fingerprint, provider, repo, file, line_no,
           first_seen, last_seen, status, assignee
    FROM fingerprint_matches WHERE id = ${id}`;
  if (current.rows.length === 0) return null;
  const oldStatus = String(current.rows[0].status ?? "new");
  const { rows } = await sql`
    UPDATE fingerprint_matches SET status = ${status} WHERE id = ${id}
    RETURNING id, fingerprint, provider, repo, file, line_no,
              first_seen, last_seen, status, assignee`;
  const updated = rowToMatch(rows[0]);
  if (oldStatus !== status) {
    await recordHistory(id, oldStatus, status, changedBy, note);
  }
  return updated;
}

/**
 * Assign a match to a team member (free-text name, max 100 chars after
 * trimming; empty string clears the assignment). Records a history row
 * with the assignment as its note (status itself does not change).
 * Returns null when no such match exists.
 */
export async function assignMatch(
  id: number,
  assignee: string,
  changedBy = "admin",
): Promise<FingerprintMatchRow | null> {
  const name = normalizeAssignee(assignee);
  await ensureFingerprintTables();
  const current = await sql`
    SELECT id, fingerprint, provider, repo, file, line_no,
           first_seen, last_seen, status, assignee
    FROM fingerprint_matches WHERE id = ${id}`;
  if (current.rows.length === 0) return null;
  const oldAssignee = String(current.rows[0].assignee ?? "");
  const status = String(current.rows[0].status ?? "new");
  const { rows } = await sql`
    UPDATE fingerprint_matches SET assignee = ${name} WHERE id = ${id}
    RETURNING id, fingerprint, provider, repo, file, line_no,
              first_seen, last_seen, status, assignee`;
  const updated = rowToMatch(rows[0]);
  if (oldAssignee !== name) {
    await recordHistory(
      id,
      status,
      status,
      changedBy,
      name ? `assigned to ${name}` : "assignment cleared",
    );
  }
  return updated;
}

/**
 * Per-repo remediation posture, aggregated in SQL. Counts only — no key
 * material leaves the database. Matches carry no confidence score, so
 * open matches are bucketed by age of first_seen instead.
 */
export async function getPosture(): Promise<Posture> {
  await ensureFingerprintTables();
  // Per (repo, provider, status) counts.
  const byRepoProvider = await sql`
    SELECT repo, provider, status, COUNT(*)::int AS n
    FROM fingerprint_matches
    GROUP BY repo, provider, status`;
  // Per-repo totals, open-age buckets, and oldest open match.
  const byRepo = await sql`
    SELECT repo,
      COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE status IN ('new', 'acknowledged'))::int AS open,
      COUNT(*) FILTER (WHERE status = 'resolved')::int AS resolved,
      COUNT(*) FILTER (WHERE status IN ('new', 'acknowledged')
        AND first_seen > now() - interval '7 days')::int AS open_lt7d,
      COUNT(*) FILTER (WHERE status IN ('new', 'acknowledged')
        AND first_seen <= now() - interval '7 days'
        AND first_seen > now() - interval '30 days')::int AS open_7to30d,
      COUNT(*) FILTER (WHERE status IN ('new', 'acknowledged')
        AND first_seen <= now() - interval '30 days')::int AS open_gt30d,
      MIN(first_seen) FILTER
        (WHERE status IN ('new', 'acknowledged')) AS oldest_open
    FROM fingerprint_matches
    GROUP BY repo
    ORDER BY open DESC, total DESC`;

  const byProviderByRepo = new Map<string, Record<string, number>>();
  for (const row of byRepoProvider.rows) {
    const repo = String(row.repo ?? "");
    const provider = String(row.provider ?? "") || "(unknown)";
    const entry = byProviderByRepo.get(repo) ?? {};
    entry[provider] = (entry[provider] ?? 0) + Number(row.n ?? 0);
    byProviderByRepo.set(repo, entry);
  }

  const repos: PostureRepo[] = byRepo.rows.map((row) => {
    const repo = String(row.repo ?? "");
    return {
      repo,
      total: Number(row.total ?? 0),
      open: Number(row.open ?? 0),
      resolved: Number(row.resolved ?? 0),
      byProvider: byProviderByRepo.get(repo) ?? {},
      openByAge: {
        lt7d: Number(row.open_lt7d ?? 0),
        d7to30: Number(row.open_7to30d ?? 0),
        gt30d: Number(row.open_gt30d ?? 0),
      },
      oldestOpen: row.oldest_open ? String(row.oldest_open) : null,
    };
  });

  const totalMatches = repos.reduce((sum, r) => sum + r.total, 0);
  const openMatches = repos.reduce((sum, r) => sum + r.open, 0);
  const resolvedMatches = repos.reduce((sum, r) => sum + r.resolved, 0);
  return {
    repos,
    summary: {
      totalMatches,
      openMatches,
      resolvedMatches,
      repoCount: repos.length,
      openRate: totalMatches > 0 ? openMatches / totalMatches : 0,
    },
  };
}
