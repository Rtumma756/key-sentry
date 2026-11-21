// Standalone tests for the free-tier caps (FREE-TIER-CAPS.md) — the
// web side: daily counters (in-memory fallback + UTC-day rollover),
// anonymous IP hashing (no raw IP stored), the cap-hit 429 response
// shape, the audit-timeline free restriction, and the shareable-report
// free list (latest 2 per type, links stay live).
//
//   node tests/caps.test.mjs
//
// No test runner is configured for this project, so this file runs
// with plain node and uses node:assert (same pattern as
// tests/usage-limits.test.mjs). Only the pure helpers are covered
// here — the Postgres-backed counters in lib/usage.ts need a database
// (none is reachable from this sandbox), so they are verified by
// `npm run build` (type check) and by the route wiring, not by this
// file. The direct GET /api/vibe-scan/[id] route is untouched by this
// build (no diff), so its links keep working; the list slice is
// covered here through latestReportsForPlan.

import assert from "node:assert/strict";
import {
  capHitResponse,
  hashClientIp,
  memoryDailyCounters,
  resetsAtUtc,
  usageDay,
} from "../lib/usage-policy.ts";
import {
  checkDailyCap,
  dailyCapMessage,
  dailyCapUpgrade,
  formatCounter,
  getAllPlans,
  getPlan,
  latestReportsForPlan,
  limitCheck,
  restrictAuditTimeline,
} from "../lib/plans.ts";

let passed = 0;
function check(name, fn) {
  const result = fn();
  if (result instanceof Promise) return result.then(() => {
    passed++;
    console.log(`ok - ${name}`);
  });
  passed++;
  console.log(`ok - ${name}`);
}

const NOW = new Date("2026-11-21T12:00:00Z");

await check("daily counters roll over at midnight UTC", () => {
  memoryDailyCounters.reset();
  const key = "vibe-scans:ip:0123456789abcdef";
  assert.equal(memoryDailyCounters.get(key, "2026-11-21"), 0);
  assert.equal(memoryDailyCounters.increment(key, "2026-11-21"), 1);
  assert.equal(memoryDailyCounters.increment(key, "2026-11-21"), 2);
  assert.equal(memoryDailyCounters.get(key, "2026-11-21"), 2);
  // Same key, next UTC day: a new bucket, count zero.
  assert.equal(memoryDailyCounters.get(key, "2026-11-22"), 0);
  assert.equal(memoryDailyCounters.increment(key, "2026-11-22"), 1);
  assert.equal(memoryDailyCounters.get(key, "2026-11-21"), 2);
  // usageDay buckets by UTC, not local time.
  assert.equal(usageDay(new Date("2026-11-21T23:59:59Z")), "2026-11-21");
  assert.equal(usageDay(new Date("2026-11-22T00:00:01Z")), "2026-11-22");
  assert.equal(resetsAtUtc(NOW), "2026-11-22T00:00:00.000Z");
  memoryDailyCounters.reset();
});

await check("anonymous IP hashing never stores a raw IP", () => {
  const ip = "203.0.113.7";
  const hash = hashClientIp(ip);
  assert.match(hash, /^[0-9a-f]{16}$/);
  assert.equal(hashClientIp(ip), hash, "deterministic");
  assert.notEqual(hashClientIp("203.0.113.8"), hash, "different IP differs");
  assert.ok(!hash.includes("203.0.113.7"), "no raw IP in the hash");
  const counterKey = `vibe-scans:ip:${hash}`;
  assert.ok(!counterKey.includes(ip), "no raw IP in the counter key");
  assert.ok(!counterKey.includes("203"), "no IP fragment in the key");
});

await check("daily cap checks bite at the limit, not before", () => {
  assert.equal(checkDailyCap("free", "scans_per_day", 0).allowed, true);
  assert.equal(checkDailyCap("free", "scans_per_day", 1).allowed, true);
  const denied = checkDailyCap("free", "scans_per_day", 2);
  assert.equal(denied.allowed, false);
  assert.equal(denied.limit, 2);
  assert.equal(denied.used, 2);
  assert.match(denied.message, /Maker/);
  assert.match(denied.message, /\$19/);
  assert.match(denied.message, /unlimited vibe-code scans/);
  assert.match(denied.message, /come back tomorrow/i);
  assert.match(denied.message, /midnight UTC/);
  // Unlimited tiers never hit the cap.
  assert.equal(checkDailyCap("maker", "scans_per_day", 999).allowed, true);
  assert.equal(checkDailyCap("starter", "audits_per_day", 999).allowed, true);
});

await check("cap-hit response shape: 429 + upgrade prompt + tomorrow", async () => {
  const upgrade = dailyCapUpgrade("free", "scans_per_day");
  assert.deepEqual(upgrade, {
    message: "Upgrade to Maker ($19/mo) to unlock unlimited vibe-code scans.",
    tier: "Maker",
    price: "$19/mo",
    unlocks: "unlimited vibe-code scans",
  });
  const res = capHitResponse(
    dailyCapMessage("free", "scans_per_day", 2), 2, 2, upgrade, NOW);
  assert.equal(res.status, 429);
  assert.ok(Number(res.headers.get("Retry-After")) > 0);
  const body = await res.json();
  assert.match(body.error, /Maker/);
  assert.match(body.error, /come back tomorrow/i);
  assert.equal(body.used, 2);
  assert.equal(body.limit, 2);
  assert.equal(body.resetsAt, "2026-11-22T00:00:00.000Z");
  assert.equal(body.upgrade.tier, "Maker");
  assert.equal(body.upgrade.price, "$19/mo");
  assert.equal(body.upgrade.unlocks, "unlimited vibe-code scans");
});

await check("upgrade copy names the right tier per resource", () => {
  const cases = [
    ["scans_per_day", 2, "Maker", "unlimited vibe-code scans"],
    ["mcp_queries_per_day", 100, "Maker", "unlimited MCP server queries"],
    ["dashboard_saves_per_day", 2, "Maker", "unlimited dashboard saves"],
    ["audits_per_day", 2, "Starter", "unlimited agent identity audits"],
  ];
  for (const [resource, used, tier, unlocks] of cases) {
    const prompt = dailyCapUpgrade("free", resource);
    assert.equal(prompt.tier, tier, resource);
    assert.equal(prompt.unlocks, unlocks, resource);
    assert.match(
      dailyCapMessage("free", resource, used), /come back tomorrow/i, resource);
  }
  const reports = limitCheck("free", "shareable_reports", 3);
  assert.equal(reports.allowed, false);
  assert.match(reports.message, /Maker/);
  assert.match(reports.message, /unlimited shareable reports/);
  const seats = limitCheck("free", "seats", 2);
  assert.match(seats.message, /Team/);
  assert.match(seats.message, /5 team seats/);
  // Maker already has unlimited scans: no upgrade prompt.
  assert.equal(dailyCapUpgrade("maker", "scans_per_day"), null);
});

await check("audit GET free restriction: 2nd agent / older events", () => {
  const events = [
    { agent_id: "agent-a", timestamp: "2026-11-21T11:00:00Z" },
    { agent_id: "agent-a", timestamp: "2026-11-20T10:00:00Z" },
    { agent_id: "agent-a", timestamp: "2026-11-10T10:00:00Z" }, // 11d old
    { agent_id: "agent-b", timestamp: "2026-11-21T09:00:00Z" },
    { agent_id: "agent-b", timestamp: "2026-11-19T09:00:00Z" },
  ];
  const free = restrictAuditTimeline(events, "free", NOW);
  // Allowed agent is the newest event's agent (agent-a); agent-b's
  // events are excluded, as is agent-a's 11-day-old event.
  assert.deepEqual(
    free.events.map((e) => e.timestamp),
    ["2026-11-21T11:00:00Z", "2026-11-20T10:00:00Z"],
  );
  assert.equal(free.allowedAgent, "agent-a");
  assert.equal(free.windowDays, 7);
  assert.equal(free.excludedAgents, 2);
  assert.equal(free.excludedOlder, 1);
  // A 2nd agent needs the full timeline: Team.
  assert.equal(free.upgrade.tier, "Team");
  assert.equal(free.upgrade.price, "$149/mo");
  assert.match(free.upgrade.message, /full audit timeline/);
});

await check("audit restriction: older events only -> Maker", () => {
  const events = [
    { agent_id: "agent-a", timestamp: "2026-11-21T11:00:00Z" },
    { agent_id: "agent-a", timestamp: "2026-11-10T10:00:00Z" }, // 11d old
  ];
  const free = restrictAuditTimeline(events, "free", NOW);
  assert.equal(free.events.length, 1);
  assert.equal(free.excludedAgents, 0);
  assert.equal(free.excludedOlder, 1);
  // Older events need more history: Maker (30 days) on Free.
  assert.equal(free.upgrade.tier, "Maker");
  assert.equal(free.upgrade.price, "$19/mo");
  assert.match(free.upgrade.message, /30 days of audit history/);
  // Maker's 30-day window keeps a 20-day-old event, drops a 40-day one.
  const maker = restrictAuditTimeline([
    { agent_id: "agent-a", timestamp: "2026-11-01T10:00:00Z" },
    { agent_id: "agent-a", timestamp: "2026-10-12T10:00:00Z" },
  ], "maker", NOW);
  assert.equal(maker.events.length, 1);
  assert.equal(maker.excludedOlder, 1);
  assert.equal(maker.upgrade.tier, "Premium"); // 30d -> 60d is Premium
  assert.equal(maker.upgrade.price, "$99/mo");
  // Team sees everything within 90 days, no upgrade prompt.
  const team = restrictAuditTimeline([
    { agent_id: "agent-a", timestamp: "2026-11-21T11:00:00Z" },
    { agent_id: "agent-b", timestamp: "2026-11-10T10:00:00Z" },
    { agent_id: "agent-a", timestamp: "2026-09-01T10:00:00Z" },
  ], "team", NOW);
  assert.equal(team.events.length, 3);
  assert.equal(team.upgrade, null);
});

await check("report list: latest 2 per type on free, links stay live", () => {
  const reports = [
    { id: "r1", type: "vibe", createdAt: "2026-11-21T10:00:00Z" },
    { id: "r2", type: "vibe", createdAt: "2026-11-20T10:00:00Z" },
    { id: "r3", type: "vibe", createdAt: "2026-11-19T10:00:00Z" },
    { id: "a1", type: "audit", createdAt: "2026-11-21T09:00:00Z" },
    { id: "a2", type: "audit", createdAt: "2026-11-20T09:00:00Z" },
    { id: "a3", type: "audit", createdAt: "2026-11-19T09:00:00Z" },
  ];
  const free = latestReportsForPlan(reports, "free");
  assert.deepEqual(
    free.map((r) => r.id),
    ["r1", "a1", "r2", "a2"],
    "latest 2 per type, newest first overall",
  );
  // The slice never deletes anything: the input is untouched, so a
  // direct GET by id (a separate, unmodified route) still works and
  // the rolled-off report's link stays live.
  assert.equal(reports.length, 6, "input not mutated");
  assert.ok(reports.some((r) => r.id === "r3"), "oldest report still exists");
  const maker = latestReportsForPlan(reports, "maker");
  assert.equal(maker.length, 6, "paid tiers see the whole list");
  assert.equal(latestReportsForPlan([], "free").length, 0);
});

await check("Maker tier present in the web plan definitions", () => {
  const byId = Object.fromEntries(getAllPlans().map((t) => [t.id, t]));
  assert.deepEqual(
    getAllPlans().map((t) => t.id),
    [
      "free",
      "maker",
      "starter",
      "premium",
      "team",
      "premium_plus",
      "business",
      "enterprise",
    ],
  );
  assert.equal(byId.maker.price_monthly_usd, 19);
  assert.equal(byId.maker.price_label, "$19/mo");
  assert.equal(byId.maker.limits.repos, 5);
  assert.equal(byId.maker.limits.scans_per_day, null);
  assert.equal(byId.maker.limits.mcp_queries_per_day, null);
  assert.equal(byId.maker.limits.audit_timeline_days, 30);
  assert.equal(byId.maker.limits.audits_per_day, 2);
  assert.equal(byId.free.limits.scans_per_day, 2);
  assert.equal(byId.free.limits.audits_per_day, 2);
  assert.equal(byId.free.limits.mcp_queries_per_day, 100);
  assert.equal(byId.free.limits.dashboard_saves_per_day, 2);
  assert.equal(byId.free.limits.shareable_reports, 2);
  assert.equal(byId.free.limits.audit_timeline_days, 7);
  assert.equal(byId.free.limits.seats, 1);
  assert.equal(byId.team.limits.audit_timeline_days, 90);
  assert.equal(byId.team.limits.seats, 5);
  assert.equal(byId.business.limits.audit_timeline_days, 2555);
  // Unknown plan state still defaults to Free with free caps working.
  assert.equal(getPlan("bogus").id, "free");
  assert.equal(getPlan(null).limits.scans_per_day, 2);
  assert.equal(checkDailyCap("bogus", "scans_per_day", 2).allowed, false);
});

await check("counter display text matches the CLI wording", () => {
  assert.equal(formatCounter(1, 2, "scans"), "1 of 2 free scans used today");
  assert.equal(formatCounter(2, 2, "audits"), "2 of 2 free audits used today");
  assert.equal(
    formatCounter(3, null, "scans", "Maker"),
    "3 scans used today (unlimited on the Maker plan)",
  );
  assert.equal(
    formatCounter(1, 2, "audits", "Maker"),
    "1 of 2 audits used today (Maker plan)",
  );
});

console.log(`\ncaps: ${passed} checks passed`);
