// Agent identity store: Vercel Postgres (free tier, Neon-backed).
//
// Pillar 1 — which agent holds which credential. Only SHA-256
// fingerprints (first 16 hex chars) and prefix4-masked values are
// stored — NEVER a raw key. Tables are created on first use, following
// the ensureFingerprintTables pattern in lib/fingerprints-db.ts.
// No database? Helpers throw VaultNotConfigured and the routes answer
// 503 instead of failing open.

import { sql } from "@vercel/postgres";
import { requireDbConfigured } from "./vault-db";
import {
  MAX_AGENT_FIELD_LENGTH,
  MAX_CREDENTIALS_PER_AGENT,
  normalizeAgentCredential,
  normalizeAgentField,
  type AgentCredentialRow,
} from "./agents-validation";

export {
  MAX_AGENT_FIELD_LENGTH,
  MAX_CREDENTIALS_PER_AGENT,
  normalizeAgentCredential,
  normalizeAgentField,
  type AgentCredentialRow,
};

export interface AgentRow {
  id: number;
  name: string;
  type: string;
  configPath: string;
  repo: string;
  owner: string;
  credentials: AgentCredentialRow[];
  /** Credentials whose fingerprint also appears in fingerprint_matches. */
  exposedCount: number;
  createdAt: string;
  updatedAt: string;
}

export async function ensureAgentTables(): Promise<void> {
  requireDbConfigured();
  await sql`
    CREATE TABLE IF NOT EXISTS agents (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT '',
      config_path TEXT NOT NULL DEFAULT '',
      repo TEXT NOT NULL DEFAULT '',
      owner TEXT NOT NULL DEFAULT 'unknown',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
  // One row per (agent name, config path): re-registering the same
  // agent from the CLI upserts instead of duplicating it.
  await sql`
    CREATE UNIQUE INDEX IF NOT EXISTS agents_name_config_idx
    ON agents (name, config_path)`;
  await sql`
    CREATE TABLE IF NOT EXISTS agent_credentials (
      id SERIAL PRIMARY KEY,
      agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
      provider TEXT NOT NULL DEFAULT '',
      credential_type TEXT NOT NULL DEFAULT '',
      fingerprint TEXT NOT NULL DEFAULT '',
      masked TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL DEFAULT '',
      env_var TEXT NOT NULL DEFAULT ''
    )`;
  await sql`
    CREATE INDEX IF NOT EXISTS agent_credentials_agent_idx
    ON agent_credentials (agent_id)`;
  await sql`
    CREATE INDEX IF NOT EXISTS agent_credentials_fingerprint_idx
    ON agent_credentials (fingerprint)`;
}

function rowToCredential(row: Record<string, unknown>): AgentCredentialRow {
  return {
    provider: String(row.provider ?? ""),
    credentialType: String(row.credential_type ?? ""),
    fingerprint: String(row.fingerprint ?? ""),
    masked: String(row.masked ?? ""),
    source: String(row.source ?? ""),
    envVar: String(row.env_var ?? ""),
  };
}

export interface RegisterAgentInput {
  name: string;
  type: string;
  configPath: string;
  repo: string;
  owner: string;
  credentials: AgentCredentialRow[];
}

export async function listAgents(): Promise<AgentRow[]> {
  await ensureAgentTables();
  const { rows } = await sql`
    SELECT a.id, a.name, a.type, a.config_path, a.repo, a.owner,
           a.created_at, a.updated_at,
           COALESCE(
             (SELECT COUNT(DISTINCT fm.fingerprint)
              FROM fingerprint_matches fm
              WHERE fm.fingerprint IN
                (SELECT fingerprint FROM agent_credentials ac
                 WHERE ac.agent_id = a.id AND ac.fingerprint <> '')),
             0)::int AS exposed_count
    FROM agents a
    ORDER BY a.updated_at DESC, a.id DESC`;
  const agents: AgentRow[] = [];
  for (const row of rows) {
    const creds = await sql`
      SELECT provider, credential_type, fingerprint, masked, source, env_var
      FROM agent_credentials
      WHERE agent_id = ${Number(row.id)}
      ORDER BY id ASC`;
    agents.push({
      id: Number(row.id),
      name: String(row.name),
      type: String(row.type ?? ""),
      configPath: String(row.config_path ?? ""),
      repo: String(row.repo ?? ""),
      owner: String(row.owner ?? "unknown"),
      credentials: creds.rows.map(rowToCredential),
      exposedCount: Number(row.exposed_count ?? 0),
      createdAt: String(row.created_at),
      updatedAt: String(row.updated_at),
    });
  }
  return agents;
}

/**
 * Register (upsert) one agent with its credentials, as produced by
 * `aiscan agents inventory --json` / `agents map --json`. Credentials
 * are replaced wholesale on re-registration. Returns the stored row.
 */
export async function registerAgent(
  input: RegisterAgentInput,
): Promise<AgentRow> {
  await ensureAgentTables();
  const name = normalizeAgentField(input.name);
  const type = normalizeAgentField(input.type);
  const configPath = normalizeAgentField(input.configPath);
  const repo = normalizeAgentField(input.repo);
  const owner = normalizeAgentField(input.owner) || "unknown";
  if (!name) throw new Error("Agent registration needs a name.");
  if (input.credentials.length > MAX_CREDENTIALS_PER_AGENT) {
    throw new Error(
      `At most ${MAX_CREDENTIALS_PER_AGENT} credentials per agent.`,
    );
  }
  const { rows } = await sql`
    INSERT INTO agents (name, type, config_path, repo, owner)
    VALUES (${name}, ${type}, ${configPath}, ${repo}, ${owner})
    ON CONFLICT (name, config_path) DO UPDATE
      SET type = EXCLUDED.type,
          repo = EXCLUDED.repo,
          owner = EXCLUDED.owner,
          updated_at = now()
    RETURNING id, name, type, config_path, repo, owner,
              created_at, updated_at`;
  const agent = rows[0];
  const agentId = Number(agent.id);
  await sql`DELETE FROM agent_credentials WHERE agent_id = ${agentId}`;
  for (const cred of input.credentials) {
    await sql`
      INSERT INTO agent_credentials
        (agent_id, provider, credential_type, fingerprint, masked,
         source, env_var)
      VALUES (${agentId}, ${cred.provider}, ${cred.credentialType},
              ${cred.fingerprint}, ${cred.masked}, ${cred.source},
              ${cred.envVar})`;
  }
  return {
    id: agentId,
    name: String(agent.name),
    type: String(agent.type ?? ""),
    configPath: String(agent.config_path ?? ""),
    repo: String(agent.repo ?? ""),
    owner: String(agent.owner ?? "unknown"),
    credentials: input.credentials,
    exposedCount: 0,
    createdAt: String(agent.created_at),
    updatedAt: String(agent.updated_at),
  };
}
