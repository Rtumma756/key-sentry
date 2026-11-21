// Fingerprint-match alerting: Slack-compatible webhook (free,
// user-supplied) + email (free-only: Resend API or plain SMTP).
//
// When a NEW match is recorded, POST a short message to the URL in
// KEYSENTRY_ALERT_WEBHOOK (a Slack incoming webhook URL — free tier),
// then send an email via lib/email.ts when email is configured
// (KEYSENTRY_ALERT_EMAIL plus RESEND_API_KEY or SMTP_* — see
// docs/commercial/EMAIL-ALERTS.md in the CLI repo). Both payloads carry
// only the fingerprint (a one-way hash), the provider, and where it was
// seen — never a raw or masked key.
//
// Free-tier gate (FREE-TIER-CAPS.md): email/Slack alerts are NOT on
// Free — any alert is suppressed and recorded as a would-have-alerted
// note (function log) with the upgrade prompt, never sent. Match
// recording itself is unaffected.
//
// Alert delivery must never break match recording: sendMatchAlert swallows
// transport errors (logs them) and the caller proceeds regardless.
// It returns true when EITHER channel accepted (webhook 2xx or email
// accepted); previously it returned true for the webhook only.

import type { FingerprintMatchRow } from "./fingerprints-db";
import { sendMatchEmail } from "./email";
import { featureAllowed, upgradePrompt } from "./plans";
import { resolveWorkspacePlanId } from "./plan-enforcement";

export function alertWebhookUrl(): string | null {
  const url = process.env.KEYSENTRY_ALERT_WEBHOOK;
  return url && url.trim() ? url.trim() : null;
}

function alertText(match: FingerprintMatchRow): string {
  const where = [match.repo, match.file].filter(Boolean).join(" · ");
  const line = match.line > 0 ? `:${match.line}` : "";
  return (
    `:rotating_light: KeySentry: watched key \`${match.fingerprint}\` ` +
    `(${match.provider || "unknown provider"}) seen again` +
    (where ? ` in ${where}${line}` : "") +
    `. First seen ${match.firstSeen}; acknowledge or resolve it at ` +
    `the KeySentry matches list.`
  );
}

/**
 * Fire-and-forget alert for a newly recorded match. Webhook first, then
 * email. Returns true when either channel accepted (webhook 2xx, or the
 * email transport accepted), false when nothing is configured or every
 * configured channel failed. Never throws.
 *
 * `plan` is the workspace's plan id; when omitted it is resolved from
 * the workspace plan store (Free when unknown — the free-never-
 * locked-out default). On Free the alert is suppressed, not sent: a
 * would-have-alerted note is logged with the upgrade prompt, and the
 * function returns false (the caller reports alerted=false).
 */
export async function sendMatchAlert(
  match: FingerprintMatchRow,
  plan?: string,
): Promise<boolean> {
  const planId = plan ?? (await resolveWorkspacePlanId("default"));
  if (
    !featureAllowed(planId, "email_alerts") &&
    !featureAllowed(planId, "slack_alerts")
  ) {
    const prompt = upgradePrompt(planId, "email_alerts");
    console.info(
      `KeySentry match alert suppressed (would-have-alerted, ` +
        `${planId} plan): fingerprint ${match.fingerprint} ` +
        `(${match.provider || "unknown provider"}) seen again` +
        (match.repo || match.file
          ? ` in ${[match.repo, match.file].filter(Boolean).join(" · ")}`
          : "") +
        `. ${prompt?.message ?? ""}`,
    );
    return false;
  }
  const webhookOk = await sendWebhookAlert(match);
  // Email is best-effort too and never throws (see lib/email.ts).
  const emailOk = await sendMatchEmail(match);
  return webhookOk || emailOk;
}

async function sendWebhookAlert(
  match: FingerprintMatchRow,
): Promise<boolean> {
  const url = alertWebhookUrl();
  if (!url) return false;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: alertText(match) }),
        signal: controller.signal,
      });
      return res.ok;
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    // Alerting is best-effort; the match itself is already stored.
    console.error("KeySentry match alert failed:", err);
    return false;
  }
}
