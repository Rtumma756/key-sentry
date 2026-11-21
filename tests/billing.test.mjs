// Standalone tests for the Stripe billing stub (lib/billing.ts) and
// the workspace-plan default (lib/billing-db.ts).
//
//   node tests/billing.test.mjs
//
// No test runner is configured for this project, so this file runs
// with plain node and uses node:assert (same pattern as
// tests/usage-limits.test.mjs). No Stripe SDK, no network calls to
// Stripe, no live database: the webhook signature vector is computed
// locally with node:crypto, and the plan default is covered through
// the pure defaultWorkspacePlan helper in lib/plans.ts that GET
// /api/billing/plan uses when no row exists (or no DB is configured).

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  BILLING_SETUP_INSTRUCTIONS,
  billingNotConnectedResponse,
  BillingNotConfigured,
  buildCheckoutPayload,
  checkoutPayloadToFormBody,
  isBillingConfigured,
  isBillingLive,
  isWebhookConfigured,
  priceIdForTier,
  pricePlaceholder,
  requireBillingConfigured,
  tierForPriceId,
  verifyWebhookSignature,
} from "../lib/billing.ts";
import { defaultWorkspacePlan, getPlan } from "../lib/plans.ts";

let passed = 0;
function check(name, fn) {
  const result = fn();
  if (result instanceof Promise) {
    return result.then(() => {
      passed++;
      console.log(`ok - ${name}`);
    });
  }
  passed++;
  console.log(`ok - ${name}`);
}

// Save/restore the env vars these tests touch.
const ENV_KEYS = [
  "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET",
  "STRIPE_PRICE_STARTER",
  "STRIPE_PRICE_TEAM",
  "STRIPE_PRICE_BUSINESS",
  "KEYSENTRY_APP_URL",
  "KEYSENTRY_BILLING_LIVE",
];
const savedEnv = Object.fromEntries(
  ENV_KEYS.map((k) => [k, process.env[k]]),
);
function restoreEnv() {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
}
function clearBillingEnv() {
  for (const k of ENV_KEYS) delete process.env[k];
}

await check("checkout without env -> 503 billing_not_connected", async () => {
  clearBillingEnv();
  assert.equal(isBillingConfigured(), false);
  assert.equal(isWebhookConfigured(), false);
  assert.equal(isBillingLive(), false);
  const res = billingNotConnectedResponse();
  assert.equal(res.status, 503);
  const body = await res.json();
  assert.equal(body.error, "billing_not_connected");
  assert.match(body.message, /STRIPE_SECRET_KEY/);
  assert.match(body.message, /STRIPE_WEBHOOK_SECRET/);
  assert.equal(body.free_layer_unaffected, true);
  assert.match(BILLING_SETUP_INSTRUCTIONS, /redeploy/);
  assert.throws(() => requireBillingConfigured(), BillingNotConfigured);
  restoreEnv();
});

await check("checkout payload builder: correct Stripe fields per tier", () => {
  process.env.STRIPE_PRICE_STARTER = "price_test_starter";
  process.env.STRIPE_PRICE_TEAM = "price_test_team";
  process.env.STRIPE_PRICE_BUSINESS = "price_test_business";
  process.env.KEYSENTRY_APP_URL = "https://example.test";
  for (const [tier, priceId] of [
    ["starter", "price_test_starter"],
    ["team", "price_test_team"],
    ["business", "price_test_business"],
  ]) {
    const payload = buildCheckoutPayload(tier, { workspaceId: "ws-1" });
    assert.equal(payload.mode, "subscription");
    assert.equal(payload.line_items.length, 1);
    assert.equal(payload.line_items[0].price, priceId);
    assert.equal(payload.line_items[0].quantity, 1);
    assert.equal(payload.metadata.tier, tier);
    assert.equal(payload.metadata.workspace_id, "ws-1");
    assert.match(payload.success_url, /^https:\/\/example\.test\//);
    assert.match(payload.cancel_url, /^https:\/\/example\.test\//);
    // The wire encoding carries the same fields (bracket notation).
    const form = checkoutPayloadToFormBody(payload);
    assert.equal(form.get("mode"), "subscription");
    assert.equal(form.get("line_items[0][price]"), priceId);
    assert.equal(form.get("line_items[0][quantity]"), "1");
    assert.equal(form.get("metadata[tier]"), tier);
  }
  restoreEnv();
});

await check("checkout payload uses placeholders when prices unset", () => {
  clearBillingEnv();
  const payload = buildCheckoutPayload("starter");
  assert.equal(
    payload.line_items[0].price,
    pricePlaceholder("starter"),
  );
  assert.equal(priceIdForTier("starter"), "price_starter_placeholder");
  restoreEnv();
});

await check("new checkout tiers have price placeholders", () => {
  clearBillingEnv();
  for (const tier of ["maker", "premium", "premium_plus"]) {
    assert.equal(
      priceIdForTier(tier),
      `price_${tier}_placeholder`,
      tier,
    );
    assert.equal(
      buildCheckoutPayload(tier).line_items[0].price,
      `price_${tier}_placeholder`,
      tier,
    );
  }
  restoreEnv();
});

await check("checkout payload rejects free, enterprise, unknown tiers", () => {
  assert.throws(() => buildCheckoutPayload("free"), /nothing to buy/);
  assert.throws(() => buildCheckoutPayload("enterprise"), /custom pricing/);
  assert.throws(() => buildCheckoutPayload("bogus"), /Unknown tier/);
});

await check("tierForPriceId maps env prices back to tiers", () => {
  process.env.STRIPE_PRICE_STARTER = "price_test_starter";
  process.env.STRIPE_PRICE_TEAM = "price_test_team";
  assert.equal(tierForPriceId("price_test_starter"), "starter");
  assert.equal(tierForPriceId("price_test_team"), "team");
  assert.equal(tierForPriceId("price_nope"), null);
  assert.equal(tierForPriceId("price_starter_placeholder"), null);
  restoreEnv();
});

await check("webhook signature: known-good vector passes", () => {
  const secret = "whsec_test_secret";
  const rawBody = JSON.stringify({
    id: "evt_test",
    type: "checkout.session.completed",
  });
  const ts = Math.floor(Date.now() / 1000);
  const sig = createHmac("sha256", secret)
    .update(`${ts}.${rawBody}`)
    .digest("hex");
  const header = `t=${ts},v1=${sig}`;
  assert.equal(verifyWebhookSignature(rawBody, header, secret), true);
});

await check("webhook signature: tampered body, wrong secret, stale fail", () => {
  const secret = "whsec_test_secret";
  const rawBody = JSON.stringify({ id: "evt_test", type: "x" });
  const ts = Math.floor(Date.now() / 1000);
  const sig = createHmac("sha256", secret)
    .update(`${ts}.${rawBody}`)
    .digest("hex");
  const header = `t=${ts},v1=${sig}`;
  // Tampered body.
  assert.equal(
    verifyWebhookSignature(rawBody + " ", header, secret),
    false,
  );
  // Wrong secret.
  assert.equal(
    verifyWebhookSignature(rawBody, header, "whsec_wrong"),
    false,
  );
  // Stale timestamp (over the 5-minute tolerance).
  const oldTs = ts - 3600;
  const oldSig = createHmac("sha256", secret)
    .update(`${oldTs}.${rawBody}`)
    .digest("hex");
  assert.equal(
    verifyWebhookSignature(rawBody, `t=${oldTs},v1=${oldSig}`, secret),
    false,
  );
  // Malformed / missing header.
  assert.equal(verifyWebhookSignature(rawBody, "", secret), false);
  assert.equal(verifyWebhookSignature(rawBody, "t=abc,v1=zz", secret), false);
  assert.equal(verifyWebhookSignature("", header, secret), false);
});

await check("GET plan defaults to Free when no row exists", () => {
  // The route uses defaultWorkspacePlan when getWorkspacePlan returns
  // null (or the DB is unconfigured) — the Free default, never a crash.
  const row = defaultWorkspacePlan("default");
  assert.equal(row.plan, "free");
  assert.equal(row.workspaceId, "default");
  assert.equal(row.stripeCustomerId, null);
  assert.equal(getPlan(row.plan).id, "free");
  assert.equal(getPlan("bogus").id, "free");
  const other = defaultWorkspacePlan("acme");
  assert.equal(other.workspaceId, "acme");
  assert.equal(other.plan, "free");
});

restoreEnv();
console.log(`\nbilling: ${passed} checks passed`);
