// Standalone tests for the Pillar 2 vibe-code scanner (lib/vibe-checks.ts).
// No test runner is configured for this project, so this file runs with
// plain node and uses node:assert:
//
//   node tests/vibe-scan.test.mjs   (also via `npm test`)
//
// Node's type stripping loads the .ts source directly; the module uses
// only erasable TypeScript, so no build step is needed.
//
// Fixture strings are read from the Python CLI's fixtures
// (../ai-key-scanner/tests/fixtures/vibe/) so both implementations are
// checked against the SAME files with the SAME expected check ids.
// The leaked-key value is built at runtime from a hash — no real-looking
// credential literal sits in this repo.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildVibeAuditEvents,
  canonicalJson,
  checkVibeFile,
  isExampleKey,
  parseVibeRepoUrl,
  scanLineWithPatterns,
  scanVibeFileSecrets,
  verifyVibeAuditChain,
} from "../lib/vibe-checks.ts";

const here = join(fileURLToPath(import.meta.url), "..");
const vibeFixtures = join(
  here, "..", "..", "ai-key-scanner", "tests", "fixtures", "vibe",
);
const patterns = JSON.parse(
  readFileSync(join(here, "..", "lib", "detector-patterns.json"), "utf-8"),
).detectors;

let passed = 0;
async function check(name, fn) {
  await fn();
  passed++;
  console.log(`ok - ${name}`);
}

function readFixture(name) {
  return readFileSync(join(vibeFixtures, name), "utf-8");
}

function ids(findings) {
  return new Set(findings.map((f) => f.id));
}

// --- vibe config checks: same fixtures, same check ids as Python --------

await check("firebase open read flagged (critical)", () => {
  const findings = checkVibeFile(
    "firestore.rules", readFixture("firestore.rules"),
  );
  assert.ok(ids(findings).has("vibe-firebase-open-rules"));
  const f = findings.find((x) => x.id === "vibe-firebase-open-rules");
  assert.equal(f.severity, "critical");
  assert.ok(f.fix.length > 20);
});

await check("CORS wildcard flagged", () => {
  const findings = checkVibeFile("server.js", readFixture("server.js"));
  assert.ok(ids(findings).has("vibe-cors-wildcard"));
});

await check("mongo URI without auth flagged", () => {
  const findings = checkVibeFile("config.js", readFixture("config.js"));
  assert.ok(ids(findings).has("vibe-db-no-auth"));
});

await check("hardcoded internal IP flagged", () => {
  const findings = checkVibeFile("config.js", readFixture("config.js"));
  assert.ok(ids(findings).has("vibe-hardcoded-internal-url"));
});

await check("API route without auth is labelled heuristic", () => {
  const findings = checkVibeFile(
    "api/hello.js", readFixture("api/hello.js"),
  );
  assert.ok(ids(findings).has("vibe-api-no-auth"));
  const f = findings.find((x) => x.id === "vibe-api-no-auth");
  assert.match(f.title.toLowerCase(), /heuristic/);
  assert.match(f.fix.toLowerCase(), /heuristic/);
});

await check("API route with auth passes", () => {
  const text =
    "import { verifyToken } from './auth';\n" +
    "export default async function handler(req, res) {\n" +
    "  const user = verifyToken(req);\n" +
    "  res.status(200).json({ ok: true });\n}\n";
  assert.ok(!ids(checkVibeFile("api/me.js", text)).has("vibe-api-no-auth"));
});

await check("committed .env flagged", () => {
  const findings = checkVibeFile(".env", readFixture(".env"));
  assert.ok(ids(findings).has("vibe-env-committed"));
});

await check("every finding carries a plain-language fix", () => {
  for (const name of ["firestore.rules", "server.js", "config.js", "api/hello.js", ".env"]) {
    for (const f of checkVibeFile(name, readFixture(name))) {
      assert.ok(f.fix && f.fix.length > 20, `${f.id} needs a fix`);
      assert.ok(["critical", "high", "medium", "low"].includes(f.severity));
    }
  }
});

// --- secret scanning from generated patterns ------------------------------

await check("generated patterns all compile as RegExp", () => {
  assert.ok(patterns.length >= 13, `expected 13+ patterns, got ${patterns.length}`);
  for (const det of patterns) {
    if (det.pattern !== null) new RegExp(det.pattern, "g");
  }
});

await check("TESTFAKE key is filtered, not reported as a leak", () => {
  assert.ok(isExampleKey("sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4"));
  const findings = scanVibeFileSecrets(".env", readFixture(".env"), patterns);
  assert.equal(findings.length, 0);
  assert.equal(scanLineWithPatterns("OPENAI_API_KEY=sk-proj-TESTFAKEabc123", patterns).length, 0);
});

await check("synthetic leaked key is found, masked-only", () => {
  // Built at runtime from a hash — never a literal in this file.
  const synthetic = "gsk_" + createHash("sha256").update("vibe-test-key").digest("hex").slice(0, 32);
  const findings = scanVibeFileSecrets(
    "app.py", `GROQ_API_KEY = "${synthetic}"\n`, patterns,
  );
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.id, "vibe-leaked-secret");
  assert.equal(f.provider, "Groq");
  assert.ok(f.masked.startsWith("gsk_"));
  assert.equal(f.masked, "gsk_…");
  assert.equal(
    f.fingerprint,
    createHash("sha256").update(synthetic).digest("hex").slice(0, 16),
  );
  assert.match(f.fingerprint, /^[0-9a-f]{16}$/);
  assert.ok(!JSON.stringify(findings).includes(synthetic),
    "raw secret leaked into findings JSON");
});

// --- repo URL validation ---------------------------------------------------

await check("accepts owner/repo and full GitHub URLs", () => {
  assert.deepEqual(parseVibeRepoUrl("owner/repo"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseVibeRepoUrl("https://github.com/owner/repo"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseVibeRepoUrl("https://github.com/owner/repo.git"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseVibeRepoUrl("  owner/repo  "), { owner: "owner", repo: "repo" });
});

await check("rejects non-GitHub URLs", () => {
  for (const bad of [
    "https://gitlab.com/owner/repo",
    "https://bitbucket.org/owner/repo",
    "https://example.com/owner/repo",
    "https://github.com.evil.com/owner/repo",
    "not a url at all",
    "",
  ]) {
    assert.equal(parseVibeRepoUrl(bad), null, `for ${JSON.stringify(bad)}`);
  }
});

await check("rejects private-looking and non-repo URLs", () => {
  for (const bad of [
    "git@github.com:owner/repo.git",
    "https://github.com/owner/repo/tree/main",
    "https://github.com/owner/repo/issues/1",
    "https://github.com/owner",
    "https://github.com/",
    "example.com/foo",
    "owner/repo/extra",
  ]) {
    assert.equal(parseVibeRepoUrl(bad), null, `for ${JSON.stringify(bad)}`);
  }
});

// --- audit events ----------------------------------------------------------

await check("audit events chain, genesis first, exact schema", () => {
  const events = buildVibeAuditEvents(2, "https://github.com/o/r", "report123");
  assert.equal(events.length, 2);
  assert.equal(events[0].prev_hash, "0".repeat(64));
  assert.equal(events[1].prev_hash, events[0].event_hash);
  assert.ok(verifyVibeAuditChain(events));
  const required = new Set([
    "event_id", "event_type", "timestamp", "prev_hash", "event_hash",
    "principal_id", "parent_agent_id", "session_id", "policy_id",
    "ticket_of_record", "model_run_id", "agent_id", "agent_version",
    "model", "tool", "resource", "arg_keys", "decision", "outcome",
    "correlation_id",
  ]);
  for (const event of events) {
    assert.deepEqual(new Set(Object.keys(event)), required);
    assert.equal(event.event_type, "vibe.finding");
    assert.equal(event.principal_id, "anonymous");
    assert.equal(event.parent_agent_id, null);
    assert.equal(event.agent_id, "vibe-scanner");
    assert.equal(event.agent_version, "0.1.0");
    assert.equal(event.policy_id, "vibe-scan");
    assert.deepEqual(event.arg_keys, ["repoUrl"]);
    assert.equal(event.session_id, "report123");
    assert.equal(event.correlation_id, "report123");
    assert.deepEqual(event.decision, {
      allow: true, policy: "vibe-scan", reason: "public repo scan",
    });
    assert.equal(event.outcome, "success");
    assert.equal(event.resource, "https://github.com/o/r");
    // Hash recomputes from canonical JSON + prev_hash.
    const { event_hash, ...rest } = event;
    const expected = createHash("sha256")
      .update(canonicalJson(rest) + event.prev_hash, "utf-8")
      .digest("hex");
    assert.equal(event_hash, expected);
    assert.ok(!JSON.stringify(event).includes("sk-"));
  }
});

console.log(`\nvibe-scan: ${passed} passed`);
