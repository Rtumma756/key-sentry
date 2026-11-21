// Standalone tests for the plan definitions (lib/plans.ts) — the
// TypeScript mirror of tests/test_plans.py in ai-key-scanner. Same
// expectations on both sides: if these diverge, the CLI and the web
// app disagree about what a tier includes.
//
//   node tests/plans.test.mjs
//
// No test runner is configured for this project, so this file runs
// with plain node and uses node:assert (same pattern as
// tests/usage-limits.test.mjs). No database, no network, no Stripe.

import assert from "node:assert/strict";
import {
  DEFAULT_PLAN_ID,
  checkDailyCap,
  dailyCapMessage,
  dailyCapUpgrade,
  featureAllowed,
  formatCounter,
  getAllPlans,
  getPlan,
  getPlanId,
  limitCheck,
  nextTierForFeature,
  nextTierForLimit,
  upgradeMessage,
} from "../lib/plans.ts";

let passed = 0;
function check(name, fn) {
  fn();
  passed++;
  console.log(`ok - ${name}`);
}

check("eight tiers in order, free is the default", () => {
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
  assert.equal(DEFAULT_PLAN_ID, "free");
  assert.equal(getPlanId("bogus"), "free");
  assert.equal(getPlanId(null), "free");
  assert.equal(getPlanId(undefined), "free");
  assert.equal(getPlan("bogus").id, "free");
});

check("tier prices are 0 / 19 / 49 / 99 / 149 / 299 / 499 / custom", () => {
  const byId = Object.fromEntries(getAllPlans().map((t) => [t.id, t]));
  assert.equal(byId.free.price_monthly_usd, 0);
  assert.equal(byId.maker.price_monthly_usd, 19);
  assert.equal(byId.starter.price_monthly_usd, 49);
  assert.equal(byId.premium.price_monthly_usd, 99);
  assert.equal(byId.team.price_monthly_usd, 149);
  assert.equal(byId.premium_plus.price_monthly_usd, 299);
  assert.equal(byId.business.price_monthly_usd, 499);
  assert.equal(byId.enterprise.price_monthly_usd, null);
});

check("premium / premium plus gates and upgrade paths", () => {
  const byId = Object.fromEntries(getAllPlans().map((t) => [t.id, t]));
  assert.equal(featureAllowed("premium", "slack_alerts"), true);
  assert.equal(featureAllowed("premium", "remediation_workflow"), true);
  assert.equal(featureAllowed("premium", "owner_verification"), false);
  assert.equal(featureAllowed("premium", "api"), false);
  assert.equal(featureAllowed("premium_plus", "api"), true);
  assert.equal(featureAllowed("premium_plus", "priority_support"), true);
  assert.equal(featureAllowed("premium_plus", "audit_logs"), false);
  assert.equal(byId.premium.limits.repos, 15);
  assert.equal(byId.premium.limits.fingerprints, 75);
  assert.equal(byId.premium.limits.mcp_queries_per_day, 5000);
  assert.equal(byId.premium.limits.audit_timeline_days, 60);
  assert.equal(byId.premium.limits.seats, 5);
  assert.equal(byId.premium_plus.limits.audit_timeline_days, 180);
  assert.equal(byId.premium_plus.limits.seats, 25);
  // Upgrade paths follow the price-ordered ladder: a Premium cap hit
  // names Team, a Premium Plus cap hit names Business.
  assert.equal(
    nextTierForLimit("premium", "mcp_queries_per_day")?.id,
    "team",
  );
  assert.equal(
    nextTierForLimit("premium_plus", "audit_timeline_days")?.id,
    "business",
  );
  const up = dailyCapUpgrade("premium", "mcp_queries_per_day");
  assert.equal(up.tier, "Team");
  assert.match(up.message, /\$149/);
  assert.match(
    dailyCapMessage("premium", "mcp_queries_per_day", 5000),
    /come back tomorrow/i,
  );
});

check("free allows the free layer only", () => {
  for (const f of [
    "scan_one_repo",
    "mcp_read_only",
    "audit_timeline_one_agent",
    "vibe_report_one_repo",
  ]) {
    assert.equal(featureAllowed("free", f), true, f);
  }
  for (const f of [
    "fingerprint_monitoring",
    "email_alerts",
    "vibe_monitoring",
    "slack_alerts",
    "remediation_workflow",
    "owner_verification",
    "exports",
    "full_audit_timeline",
    "audit_logs",
    "compliance_export",
    "detections",
    "policy_controls",
    "api",
    "sla",
    "sso",
    "private_deployment",
  ]) {
    assert.equal(featureAllowed("free", f), false, f);
  }
});

check("starter / team / business / enterprise gates mirror Python", () => {
  assert.equal(featureAllowed("starter", "fingerprint_monitoring"), true);
  assert.equal(featureAllowed("starter", "email_alerts"), true);
  assert.equal(featureAllowed("starter", "vibe_monitoring"), true);
  assert.equal(featureAllowed("starter", "slack_alerts"), false);
  assert.equal(featureAllowed("starter", "detections"), false);
  assert.equal(featureAllowed("team", "slack_alerts"), true);
  assert.equal(featureAllowed("team", "remediation_workflow"), true);
  assert.equal(featureAllowed("team", "exports"), true);
  assert.equal(featureAllowed("team", "full_audit_timeline"), true);
  assert.equal(featureAllowed("team", "audit_logs"), false);
  assert.equal(featureAllowed("team", "api"), false);
  assert.equal(featureAllowed("business", "audit_logs"), true);
  assert.equal(featureAllowed("business", "compliance_export"), true);
  assert.equal(featureAllowed("business", "detections"), true);
  assert.equal(featureAllowed("business", "api"), true);
  assert.equal(featureAllowed("business", "sso"), false);
  assert.equal(featureAllowed("enterprise", "sso"), true);
  assert.equal(featureAllowed("enterprise", "private_deployment"), true);
  // Unknown plan id defaults to Free for gates too.
  assert.equal(featureAllowed("bogus", "scan_one_repo"), true);
  assert.equal(featureAllowed("bogus", "api"), false);
});

check("limit boundaries: 5 vs 6 free, 25 vs 26 starter", () => {
  assert.equal(limitCheck("free", "fingerprints", 5).allowed, true);
  const free6 = limitCheck("free", "fingerprints", 6);
  assert.equal(free6.allowed, false);
  assert.match(free6.message, /up to 5 fingerprints/);
  assert.match(free6.message, /you have 6/);
  assert.equal(limitCheck("starter", "fingerprints", 25).allowed, true);
  assert.equal(limitCheck("starter", "fingerprints", 26).allowed, false);
  for (const tier of ["team", "business", "enterprise"]) {
    assert.equal(limitCheck(tier, "fingerprints", 999).allowed, true);
    assert.equal(limitCheck(tier, "fingerprints", 999).limit, null);
  }
  assert.equal(limitCheck("free", "repos", 1).allowed, true);
  assert.equal(limitCheck("free", "repos", 2).allowed, false);
  // Caps build (FREE-TIER-CAPS.md): the web vibe-scan cap is 2/day
  // on Free (was 10/day in the layer model).
  assert.equal(limitCheck("free", "scans_per_day", 2).allowed, true);
  assert.equal(limitCheck("free", "scans_per_day", 3).allowed, false);
});

check("upgrade messages name the next tier, price, and unlock", () => {
  const fp = upgradeMessage("free", "fingerprint_monitoring");
  assert.match(fp, /Starter/);
  assert.match(fp, /\$49/);
  assert.match(fp, /fingerprint monitoring/);
  const det = upgradeMessage("free", "detections");
  assert.match(det, /Business/);
  assert.match(det, /\$499/);
  assert.match(det, /detections/);
  const comp = upgradeMessage("free", "compliance_export");
  assert.match(comp, /Business/);
  assert.match(comp, /\$499/);
  assert.match(comp, /compliance export/);
  const api = upgradeMessage("team", "api");
  assert.match(api, /Premium Plus/);
  assert.match(api, /\$299/);
  const rem = upgradeMessage("free", "remediation_workflow");
  assert.match(rem, /Premium/);
  assert.match(rem, /\$99/);
  // Included features say so instead of upselling.
  assert.match(
    upgradeMessage("free", "scan_one_repo"),
    /included in your Free plan/,
  );
  // Limit denials carry the upgrade too.
  const denied = limitCheck("free", "fingerprints", 6);
  assert.match(denied.message, /Starter/);
  assert.match(denied.message, /\$49/);
  assert.match(denied.message, /fingerprint monitoring/);
  const deniedStarter = limitCheck("starter", "fingerprints", 26);
  assert.match(deniedStarter.message, /Premium/);
  assert.match(deniedStarter.message, /\$99/);
  assert.match(deniedStarter.message, /up to 75 fingerprints/);
});

check("next tier lookup follows tier order", () => {
  assert.equal(nextTierForFeature("free", "api")?.id, "premium_plus");
  assert.equal(nextTierForFeature("team", "api")?.id, "premium_plus");
  assert.equal(nextTierForFeature("free", "sso")?.id, "enterprise");
  assert.equal(nextTierForFeature("enterprise", "sso"), null);
});

// --- Maker tier + daily caps (caps build) ------------------------------

check("maker tier: the vibe-coder tier from FREE-TIER-CAPS.md", () => {
  const byId = Object.fromEntries(getAllPlans().map((t) => [t.id, t]));
  const maker = byId.maker;
  assert.equal(maker.name, "Maker");
  assert.equal(maker.price_label, "$19/mo");
  // 5 apps, unlimited scans, monitoring, fix PRs, 30-day history.
  assert.equal(maker.limits.repos, 5);
  assert.equal(maker.limits.scans_per_day, null);
  assert.equal(maker.limits.mcp_queries_per_day, null);
  assert.equal(maker.limits.dashboard_saves_per_day, null);
  assert.equal(maker.limits.shareable_reports, null);
  assert.equal(maker.limits.audit_timeline_days, 30);
  for (const f of [
    "scan_one_repo",
    "mcp_read_only",
    "audit_timeline_one_agent",
    "vibe_report_one_repo",
    "vibe_monitoring",
    "fix_prs",
  ]) {
    assert.equal(featureAllowed("maker", f), true, f);
  }
  // Maker is not the dev-team tier: no fingerprint monitoring, no
  // email alerts, no unlimited audits.
  assert.equal(featureAllowed("maker", "fingerprint_monitoring"), false);
  assert.equal(featureAllowed("maker", "email_alerts"), false);
  assert.equal(maker.limits.fingerprints, 5);
  assert.equal(maker.limits.audits_per_day, 2);
  // Starter sits above Maker and keeps its team features.
  assert.equal(featureAllowed("starter", "fingerprint_monitoring"), true);
  assert.equal(featureAllowed("starter", "email_alerts"), true);
  assert.equal(byId.starter.limits.audits_per_day, null);
});

check("daily-cap limits per tier", () => {
  const byId = Object.fromEntries(getAllPlans().map((t) => [t.id, t]));
  const free = byId.free.limits;
  assert.equal(free.scans_per_day, 2);
  assert.equal(free.audits_per_day, 2);
  assert.equal(free.mcp_queries_per_day, 100);
  assert.equal(free.dashboard_saves_per_day, 2);
  assert.equal(free.shareable_reports, 2);
  assert.equal(free.audit_timeline_days, 7);
  assert.equal(free.seats, 1);
  assert.equal(free.fingerprint_checks_per_day, 1);
  assert.equal(byId.team.limits.audit_timeline_days, 90);
  assert.equal(byId.team.limits.seats, 5);
  assert.equal(byId.business.limits.audit_timeline_days, 2555);
  assert.equal(byId.enterprise.limits.audit_timeline_days, null);
});

check("daily-cap next tier per resource (not Starter for everything)", () => {
  const cases = [
    ["scans_per_day", 2, "Maker", "unlimited vibe-code scans"],
    ["mcp_queries_per_day", 100, "Maker", "unlimited MCP server queries"],
    ["dashboard_saves_per_day", 2, "Maker", "unlimited dashboard saves"],
    ["audits_per_day", 2, "Starter", "unlimited agent identity audits"],
    [
      "fingerprint_checks_per_day",
      1,
      "Starter",
      "automatic fingerprint monitoring",
    ],
  ];
  for (const [resource, used, tier, unlocks] of cases) {
    const denied = checkDailyCap("free", resource, used);
    assert.equal(denied.allowed, false, resource);
    assert.match(denied.message, new RegExp(tier), resource);
    assert.match(denied.message, new RegExp(unlocks), resource);
    assert.match(denied.message, /come back tomorrow/i, resource);
    const prompt = dailyCapUpgrade("free", resource);
    assert.equal(prompt.tier, tier, resource);
    assert.ok(prompt.unlocks.includes(unlocks), resource);
    assert.match(denied.message, new RegExp(unlocks), resource);
  }
  const reports = limitCheck("free", "shareable_reports", 3);
  assert.match(reports.message, /Maker/);
  assert.match(reports.message, /unlimited shareable reports/);
  const seats = limitCheck("free", "seats", 2);
  assert.match(seats.message, /Team/);
  assert.match(seats.message, /5 team seats/);
  // Audit history: Free -> Maker (30 days), Maker -> Premium (60 days).
  assert.match(
    limitCheck("free", "audit_timeline_days", 8).message,
    /Maker.*30 days of audit history/,
  );
  assert.match(
    limitCheck("maker", "audit_timeline_days", 31).message,
    /Premium.*60 days of audit history/,
  );
  // Under the cap: allowed, no message; unlimited tiers never hit it.
  assert.equal(checkDailyCap("free", "scans_per_day", 1).allowed, true);
  assert.equal(checkDailyCap("free", "scans_per_day", 1).message, "");
  assert.equal(checkDailyCap("maker", "scans_per_day", 999).allowed, true);
  assert.equal(dailyCapUpgrade("maker", "scans_per_day"), null);
  assert.match(dailyCapMessage("free", "scans_per_day", 2), /Maker/);
  assert.match(dailyCapMessage("free", "scans_per_day", 2), /\$19/);
});

check("counter display text matches the CLI wording", () => {
  assert.equal(formatCounter(1, 2, "scans"), "1 of 2 free scans used today");
  assert.equal(formatCounter(2, 2, "audits"), "2 of 2 free audits used today");
  assert.equal(
    formatCounter(3, null, "scans", "Maker"),
    "3 scans used today (unlimited on the Maker plan)",
  );
});

console.log(`\nplans: ${passed} checks passed`);
