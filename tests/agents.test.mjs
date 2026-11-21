// Tests for Pillar 1 — Agent Identity (lib/agents-db.ts,
// app/api/agents/route.ts, app/agents/page.tsx, and the optional
// `agent` field on POST /api/fingerprints).
//
// No live database is needed: the DB helpers are checked by SQL
// string sanity (the CREATE TABLE / index statements the module
// issues), the route and page by file shape, and the pure validators
// (normalizeAgentCredential, normalizeAgentField) by direct import.
// Node's type stripping loads the .ts sources directly; the modules
// use only erasable TypeScript, so no build step is needed.
//
//   node tests/agents.test.mjs

import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import {
  normalizeAgentCredential,
  normalizeAgentField,
  MAX_AGENT_FIELD_LENGTH,
  MAX_CREDENTIALS_PER_AGENT,
} from "../lib/agents-validation.ts";

let passed = 0;
async function check(name, fn) {
  await fn();
  passed++;
  console.log(`ok - ${name}`);
}

const agentsDbSrc = readFileSync(
  new URL("../lib/agents-db.ts", import.meta.url),
  "utf-8",
);
const agentsRouteSrc = readFileSync(
  new URL("../app/api/agents/route.ts", import.meta.url),
  "utf-8",
);
const agentsPageSrc = readFileSync(
  new URL("../app/agents/page.tsx", import.meta.url),
  "utf-8",
);
const fingerprintsRouteSrc = readFileSync(
  new URL("../app/api/fingerprints/route.ts", import.meta.url),
  "utf-8",
);

// --- SQL sanity (string checks, no live DB) -------------------------------
await check("agents table SQL creates agents + agent_credentials", () => {
  assert.ok(agentsDbSrc.includes("CREATE TABLE IF NOT EXISTS agents"));
  assert.ok(
    agentsDbSrc.includes("CREATE TABLE IF NOT EXISTS agent_credentials"),
  );
  assert.ok(agentsDbSrc.includes("ON DELETE CASCADE"));
  assert.ok(agentsDbSrc.includes("agents_name_config_idx"));
  assert.ok(agentsDbSrc.includes("agent_credentials_fingerprint_idx"));
});

await check("agent tables use requireDbConfigured (503 when no DB)", () => {
  assert.ok(agentsDbSrc.includes("requireDbConfigured()"));
  assert.ok(agentsDbSrc.includes("VaultNotConfigured"));
});

await check("exposed count joins fingerprint_matches (counts only)", () => {
  assert.ok(agentsDbSrc.includes("fingerprint_matches"));
  assert.ok(agentsDbSrc.includes("COUNT(DISTINCT fm.fingerprint)"));
});

await check("register upserts on (name, config_path), replaces creds", () => {
  assert.ok(agentsDbSrc.includes("ON CONFLICT (name, config_path)"));
  assert.ok(
    agentsDbSrc.includes("DELETE FROM agent_credentials WHERE agent_id"),
  );
});

// --- Pure validators -------------------------------------------------------
await check("normalizeAgentCredential accepts fingerprint + masked", () => {
  const cred = normalizeAgentCredential({
    provider: "Groq",
    credential_type: "API key",
    fingerprint: "0123456789abcdef",
    masked: "gsk_...",
    source: "mcp-server-env",
    env_var: "",
  });
  assert.equal(cred.provider, "Groq");
  assert.equal(cred.fingerprint, "0123456789abcdef");
  assert.equal(cred.masked, "gsk_...");
});

await check("normalizeAgentCredential accepts env-var reference", () => {
  const cred = normalizeAgentCredential({
    provider: "OpenAI",
    fingerprint: "",
    masked: "",
    env_var: "OPENAI_API_KEY",
  });
  assert.equal(cred.envVar, "OPENAI_API_KEY");
  assert.equal(cred.fingerprint, "");
});

await check("normalizeAgentCredential rejects a raw key as fingerprint", () => {
  assert.throws(
    () =>
      normalizeAgentCredential({
        provider: "OpenAI",
        fingerprint: "sk-proj-abcdefghij1234567890",
      }),
    /16 lowercase hex/,
  );
});

await check("normalizeAgentCredential rejects non-prefix4 masked", () => {
  assert.throws(
    () =>
      normalizeAgentCredential({
        provider: "Groq",
        fingerprint: "0123456789abcdef",
        masked: "gsk_fullkeyvalue1234",
      }),
    /prefix4/,
  );
});

await check("normalizeAgentCredential drops empty records", () => {
  assert.equal(
    normalizeAgentCredential({ provider: "", fingerprint: "", env_var: "" }),
    null,
  );
  assert.equal(normalizeAgentCredential(null), null);
});

await check("normalizeAgentField enforces the length cap", () => {
  assert.equal(normalizeAgentField("  claude-code  "), "claude-code");
  assert.throws(
    () => normalizeAgentField("x".repeat(MAX_AGENT_FIELD_LENGTH + 1)),
    /at most/,
  );
  assert.ok(MAX_CREDENTIALS_PER_AGENT > 0);
});

// --- API route shape -------------------------------------------------------
await check("agents route exists with GET list + POST register", () => {
  assert.ok(existsSync(new URL("../app/api/agents/route.ts", import.meta.url)));
  assert.ok(agentsRouteSrc.includes("export async function GET"));
  assert.ok(agentsRouteSrc.includes("export async function POST"));
  assert.ok(agentsRouteSrc.includes("listAgents"));
  assert.ok(agentsRouteSrc.includes("registerAgent"));
  assert.ok(agentsRouteSrc.includes("normalizeAgentCredential"));
  assert.ok(agentsRouteSrc.includes("force-dynamic"));
});

await check("agents route answers 503 when no DB is configured", () => {
  assert.ok(agentsRouteSrc.includes("notConfiguredResponse"));
  assert.ok(agentsRouteSrc.includes("VaultNotConfigured"));
});

// --- Dashboard page shape --------------------------------------------------
await check("agents page exists and renders the required columns", () => {
  assert.ok(existsSync(new URL("../app/agents/page.tsx", import.meta.url)));
  for (const heading of ["Agent", "Type", "Credentials", "Exposed", "Owner"]) {
    assert.ok(agentsPageSrc.includes(`<th>${heading}</th>`), heading);
  }
  assert.ok(agentsPageSrc.includes('fetch("/api/agents")'));
  assert.ok(agentsPageSrc.includes("exposedCount"));
  assert.ok(agentsPageSrc.includes("fingerprint"));
});

// --- Fingerprints route: optional `agent` field ---------------------------
await check("fingerprints POST accepts optional agent, label wins", () => {
  assert.ok(fingerprintsRouteSrc.includes("body?.agent"));
  assert.ok(fingerprintsRouteSrc.includes("label || agent"));
  assert.ok(
    fingerprintsRouteSrc.includes(
      "Agent tag must be at most 100 characters.",
    ),
  );
  // No other change to the fingerprints routes: GET/DELETE untouched.
  assert.ok(fingerprintsRouteSrc.includes("export async function GET"));
  assert.ok(fingerprintsRouteSrc.includes("export async function DELETE"));
  assert.ok(fingerprintsRouteSrc.includes("addFingerprint(fingerprint"));
});

console.log(`\nagents.test.mjs: ${passed} checks passed.`);
