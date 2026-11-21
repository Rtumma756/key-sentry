// Tests for the Pillar 3 audit trail, TypeScript side
// (lib/audit-redact.ts, lib/audit-detections.ts, lib/audit-export.ts).
// No test runner is configured for this project, so this file runs with
// plain node and uses node:assert (same pattern as
// tests/rate-limit.test.mjs):
//
//   node tests/audit.test.mjs   (also via `npm test`)
//
// Node's type stripping loads the .ts sources directly; the lib modules
// use only erasable TypeScript, so no build step is needed.
//
// Secret values below are SYNTHETIC test data, built at runtime from
// repetition — never real credentials.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  canonicalJson,
  computeEventHash,
  GENESIS_PREV_HASH,
  redactAuditEvent,
  scrubText,
  validateAuditEvent,
  verifyEvents,
  findSecretHits,
} from "../lib/audit-redact.ts";
import {
  detectConfidenceFloor,
  detectCostSpike,
  detectCrossTenantAccess,
  detectSubagentFanout,
  detectToolSetDrift,
  runAllDetections,
} from "../lib/audit-detections.ts";
import {
  DISCLAIMER,
  euAiActReport,
  iso27001Report,
  renderMarkdown,
  siemExport,
  soc2Report,
  SOC2_CONTROLS,
  ISO27001_CONTROLS,
} from "../lib/audit-export.ts";

let passed = 0;
async function check(name, fn) {
  await fn();
  passed++;
  console.log(`ok - ${name}`);
}

// --- Synthetic secrets (built at runtime, never real credentials) -------
const OPENAI_KEY = "sk-" + "Ab3dEf7h".repeat(6); // sk- + 48 alphanumerics
const GROQ_KEY = "gsk_" + "Qw7xZr2pLm9vBn4".repeat(2);
const HF_TOKEN = "hf_" + "Kp3mN8wQ2xZ6vR4tY7u".repeat(2);
const PASSWORD = "Sup3rSecretPassw0rd!";
const SPLIT_FIRST = "sk-" + "A".repeat(24);
const SPLIT_SECOND = "B".repeat(24);

function baseEvent(overrides = {}) {
  return {
    event_id: randomUUID().replaceAll("-", ""),
    event_type: "mcp.tool_call",
    timestamp: new Date().toISOString(),
    prev_hash: GENESIS_PREV_HASH,
    principal_id: "human-1",
    parent_agent_id: "",
    session_id: "sess-001",
    policy_id: "pol-default",
    ticket_of_record: "TKT-1",
    model_run_id: "run-001",
    agent_id: "agent-1",
    agent_version: "1.0.0",
    model: "gpt-4o-mini",
    tool: "read_file",
    resource: "repo/src/app.py",
    arg_keys: ["path"],
    decision: { allow: true, policy: "pol-default", reason: "ok" },
    outcome: "success",
    correlation_id: "task-001",
    confidence: null,
    ...overrides,
  };
}

function timedEvent(ts, overrides = {}) {
  return baseEvent({ timestamp: ts, ...overrides });
}

// --- Redaction: smuggle attempts (TS parity with the Python tests) ------

await check("smuggle (a): OpenAI key in an argument value is dropped", () => {
  const raw = baseEvent();
  raw.args = { api_key: OPENAI_KEY, model: "gpt-4o-mini" };
  const redacted = redactAuditEvent(raw);
  assert.deepEqual(redacted.arg_keys, ["path", "api_key", "model"]);
  assert.ok(!canonicalJson(redacted).includes(OPENAI_KEY));
});

await check("smuggle (b): token in an error message is scrubbed", () => {
  const raw = baseEvent();
  raw.decision = {
    allow: false,
    policy: "pol-default",
    reason: `upstream 401: token ${GROQ_KEY} rejected`,
  };
  const redacted = redactAuditEvent(raw);
  assert.ok(!redacted.decision.reason.includes(GROQ_KEY));
  assert.ok(redacted.decision.reason.includes("[REDACTED]"));
});

await check("smuggle (c): password field keeps the name, never the value", () => {
  const raw = baseEvent();
  raw.args = { username: "alice", password: PASSWORD };
  const redacted = redactAuditEvent(raw);
  assert.deepEqual(redacted.arg_keys, ["path", "username", "password"]);
  assert.ok(!canonicalJson(redacted).includes(PASSWORD));
});

await check("smuggle (d): JSON blob with a secret inside arg values", () => {
  const raw = baseEvent();
  raw.args = { config: JSON.stringify({ api_key: OPENAI_KEY, timeout: 30 }) };
  const redacted = redactAuditEvent(raw);
  assert.deepEqual(redacted.arg_keys, ["path", "config"]);
  assert.ok(!canonicalJson(redacted).includes(OPENAI_KEY));
});

await check("smuggle (e): secret split across fields is rejected", () => {
  const raw = baseEvent({ tool: SPLIT_FIRST, resource: SPLIT_SECOND });
  const redacted = redactAuditEvent(raw);
  // Validation runs after the chain sets prev_hash; supply the genesis
  // hash here so the secret checks are reached.
  redacted.prev_hash = GENESIS_PREV_HASH;
  const errors = validateAuditEvent(redacted);
  assert.ok(errors.some((e) => e.includes("split")), JSON.stringify(errors));
});

await check("scrubText replaces hits, leaves plain text alone", () => {
  const scrubbed = scrubText(`leaked ${HF_TOKEN} here`);
  assert.ok(!scrubbed.includes(HF_TOKEN));
  assert.ok(scrubbed.includes("[REDACTED]"));
  assert.deepEqual(findSecretHits("plain english words only"), []);
});

await check("redact assigns event_id + timestamp when absent", () => {
  const raw = baseEvent();
  delete raw.event_id;
  delete raw.timestamp;
  const redacted = redactAuditEvent(raw);
  assert.equal(String(redacted.event_id).length, 32);
  assert.ok(redacted.timestamp);
  redacted.prev_hash = GENESIS_PREV_HASH;
  assert.deepEqual(validateAuditEvent(redacted), []);
});

await check("redact drops unknown fields and never accepts hashes", () => {
  const raw = baseEvent();
  raw.api_key = OPENAI_KEY;
  raw.nested = { token: GROQ_KEY };
  raw.prev_hash = "f".repeat(64); // chain-owned: must not survive
  const redacted = redactAuditEvent(raw);
  assert.ok(!("api_key" in redacted));
  assert.ok(!("nested" in redacted));
  assert.ok(!("prev_hash" in redacted));
  assert.ok(!canonicalJson(redacted).includes(OPENAI_KEY));
  assert.ok(!canonicalJson(redacted).includes(GROQ_KEY));
});

// --- Validation ----------------------------------------------------------

await check("valid event passes validation", () => {
  assert.deepEqual(validateAuditEvent(baseEvent()), []);
});

await check("missing field / bad outcome / bad confidence rejected", () => {
  const missing = baseEvent();
  delete missing.tool;
  assert.ok(validateAuditEvent(missing).length > 0);
  assert.ok(validateAuditEvent(baseEvent({ outcome: "maybe" })).length > 0);
  assert.ok(validateAuditEvent(baseEvent({ confidence: 1.5 })).length > 0);
  assert.deepEqual(validateAuditEvent(baseEvent({ confidence: 0.5 })), []);
});

await check("secret in a plain field is rejected", () => {
  assert.ok(validateAuditEvent(baseEvent({ tool: OPENAI_KEY })).length > 0);
});

// --- Hash chain ----------------------------------------------------------

function chainEvents(n) {
  const events = [];
  let prev = GENESIS_PREV_HASH;
  for (let i = 0; i < n; i++) {
    const e = baseEvent({ tool: `tool_${i}` });
    e.prev_hash = prev;
    const { event_hash: _dropped, ...withoutHash } = e;
    e.event_hash = computeEventHash(withoutHash, prev);
    prev = e.event_hash;
    events.push(e);
  }
  return events;
}

await check("chain: append N events, verify passes, genesis correct", () => {
  const events = chainEvents(5);
  assert.equal(events[0].prev_hash, "0".repeat(64));
  const { event_hash: _dropped, ...withoutHash } = events[0];
  assert.equal(
    events[0].event_hash,
    computeEventHash(withoutHash, events[0].prev_hash),
  );
  const result = verifyEvents(events);
  assert.equal(result.ok, true);
  assert.equal(result.count, 5);
  assert.equal(result.firstBadIndex, null);
});

await check("chain: tamper one event, verify fails at exactly that index", () => {
  const events = chainEvents(5);
  events[2].tool = "tool_X";
  const result = verifyEvents(events);
  assert.equal(result.ok, false);
  assert.equal(result.firstBadIndex, 2);
  assert.equal(result.events[0].ok, true);
  assert.equal(result.events[1].ok, true);
  assert.equal(result.events[2].ok, false);
});

// --- Detections ----------------------------------------------------------

await check("detector tool_set_drift: positive + negative", () => {
  const events = [];
  for (let i = 0; i < 5; i++) {
    events.push(timedEvent(`2026-11-21T10:0${i}:00+00:00`, { tool: "read_file" }));
  }
  events.push(timedEvent("2026-11-21T10:05:00+00:00", { tool: "exec_shell" }));
  const alerts = detectToolSetDrift(events);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].detector, "tool_set_drift");
  assert.ok(alerts[0].summary.includes("exec_shell"));
  const clean = events.slice(0, 5);
  assert.deepEqual(detectToolSetDrift([...clean, ...clean.slice(0, 3)]), []);
});

await check("detector cost_spike: positive + negative", () => {
  const spike = [];
  for (const [hour, count] of [[10, 5], [11, 5], [12, 30]]) {
    for (let i = 0; i < count; i++) {
      spike.push(timedEvent(`2026-11-21T${hour}:${String(i % 60).padStart(2, "0")}:00+00:00`));
    }
  }
  const alerts = detectCostSpike(spike);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].detector, "cost_spike");
  assert.equal(alerts[0].severity, "high");
  const flat = [];
  for (const [hour, count] of [[10, 5], [11, 5], [12, 12]]) {
    for (let i = 0; i < count; i++) {
      flat.push(timedEvent(`2026-11-21T${hour}:${String(i % 60).padStart(2, "0")}:00+00:00`));
    }
  }
  assert.deepEqual(detectCostSpike(flat), []);
});

await check("detector confidence_floor_breach: positive + negative", () => {
  const alerts = detectConfidenceFloor([
    baseEvent({ confidence: 0.9 }),
    baseEvent({ confidence: 0.65 }),
    baseEvent({ confidence: 0.4 }),
  ]);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].detector, "confidence_floor_breach");
  assert.equal(alerts[0].evidence_event_ids.length, 2);
  assert.deepEqual(
    detectConfidenceFloor([
      baseEvent({ confidence: 0.9 }),
      baseEvent({ confidence: 0.7 }),
      baseEvent({ confidence: null }),
    ]),
    [],
  );
});

await check("detector cross_tenant_access: positive + negative", () => {
  const alerts = detectCrossTenantAccess([
    baseEvent({ resource: "tenant:acme/db/users" }),
    baseEvent({ resource: "tenant:globex/db/users" }),
  ]);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].detector, "cross_tenant_access");
  assert.deepEqual(
    detectCrossTenantAccess([
      baseEvent({ resource: "tenant:acme/db/users" }),
      baseEvent({ resource: "tenant:acme/db/orders" }),
    ]),
    [],
  );
});

await check("detector sub_agent_fanout: positive + negative", () => {
  const fanout = [];
  for (let i = 0; i < 6; i++) {
    fanout.push(
      timedEvent(`2026-11-21T10:0${i}:00+00:00`, {
        parent_agent_id: "parent-1",
        agent_id: `child-${i}`,
      }),
    );
  }
  const alerts = detectSubagentFanout(fanout);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].detector, "sub_agent_fanout");
  assert.deepEqual(detectSubagentFanout(fanout.slice(0, 5)), []);
});

await check("runAllDetections runs all five", () => {
  const events = [];
  for (let i = 0; i < 5; i++) {
    events.push(timedEvent(`2026-11-21T10:0${i}:00+00:00`, { tool: "read_file" }));
  }
  events.push(timedEvent("2026-11-21T10:05:00+00:00", { tool: "exec_shell" }));
  const alerts = runAllDetections(events);
  assert.ok(alerts.some((a) => a.detector === "tool_set_drift"));
});

// --- Export mappings -----------------------------------------------------

await check("export: SOC 2 mapping present with disclaimer", () => {
  const events = [
    baseEvent({ event_type: "mcp.tool_call" }),
    baseEvent({
      event_type: "agent.action",
      decision: { allow: false, policy: "p", reason: "denied" },
      outcome: "denied",
    }),
  ];
  const report = soc2Report(events);
  assert.ok(report.disclaimer.includes("Mapping template only"));
  assert.ok(DISCLAIMER.includes("NOT a certification claim"));
  const controls = new Map(report.controls.map((c) => [c.control, c]));
  assert.equal(controls.get("CC7.2").eventsMatched, 2);
  assert.equal(controls.get("CC6.1").eventsMatched, 2);
  assert.ok(SOC2_CONTROLS.some((c) => c.control === "CC8.1"));
});

await check("export: ISO 27001 mapping present", () => {
  const report = iso27001Report([baseEvent()]);
  const controls = new Set(report.controls.map((c) => c.control));
  assert.ok(controls.has("A.12.4.1"));
  assert.ok(controls.has("A.12.4.2"));
  assert.ok(controls.has("A.9.2.1"));
  assert.ok(ISO27001_CONTROLS.some((c) => c.control === "A.8.15"));
});

await check("export: EU AI Act Article 12 fields", () => {
  const report = euAiActReport([baseEvent()]);
  assert.equal(report.article, "12");
  const record = report.records[0];
  assert.equal(record.actor.agentId, "agent-1");
  assert.equal(record.operation.tool, "read_file");
  assert.equal(record.decision.allow, true);
  assert.equal(record.outcome, "success");
  assert.ok(record.timestamp);
  const md = renderMarkdown(report);
  assert.ok(md.includes("EU AI Act") && md.includes("Article 12"));
});

await check("export: SIEM JSONL parses, one object per line, no secrets", () => {
  const raw = baseEvent();
  raw.decision = { allow: true, policy: "p", reason: `saw ${OPENAI_KEY} in output` };
  const stored = redactAuditEvent(raw);
  const text = siemExport([stored]);
  assert.ok(!text.includes(OPENAI_KEY));
  const parsed = JSON.parse(text.trim());
  assert.equal(parsed.event_id, stored.event_id);
});

console.log(`\n${passed} audit tests passed`);
