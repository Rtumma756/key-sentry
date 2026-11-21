// Fingerprint-match email alerts (free-only transports).
//
// Pluggable sender, tried in this priority order:
//   (a) Resend HTTP API when RESEND_API_KEY is set — plain fetch to
//       https://api.resend.com/emails, no extra dependency. Free tier:
//       100 emails/day.
//   (b) Plain SMTP when SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS
//       are set, via nodemailer (MIT). SMTP_PORT defaults to 587
//       (STARTTLS); port 465 uses implicit TLS.
//
// Recipients: KEYSENTRY_ALERT_EMAIL, comma-separated.
// From: KEYSENTRY_ALERT_FROM, or "KeySentry <alerts@key-sentry-inky.vercel.app>".
// App link: KEYSENTRY_APP_URL, or https://key-sentry-inky.vercel.app.
//
// Env vars are read at call time (not module load), so tests can set
// them per case and Vercel picks up redeploys without a code change.
//
// Safety: the email carries only the fingerprint (a one-way SHA-256
// hash, first 16 hex), the provider, and where it was seen — never a
// raw or masked key. sendMatchEmail never throws: it logs transport
// errors and returns false, so alerting can never break match recording.

import nodemailer from "nodemailer";
import type { FingerprintMatchRow } from "./fingerprints-db";

export const DEFAULT_ALERT_FROM =
  "KeySentry <alerts@key-sentry-inky.vercel.app>";
export const DEFAULT_APP_URL = "https://key-sentry-inky.vercel.app";
const RESEND_API_URL = "https://api.resend.com/emails";

/** A match as the email needs it — same shape as FingerprintMatchRow. */
export type MatchEmailInput = Pick<
  FingerprintMatchRow,
  "fingerprint" | "provider" | "repo" | "file" | "line" | "firstSeen"
>;

export function alertEmailRecipients(): string[] {
  const raw = process.env.KEYSENTRY_ALERT_EMAIL ?? "";
  return raw
    .split(",")
    .map((addr) => addr.trim())
    .filter(Boolean);
}

export function alertEmailFrom(): string {
  const from = process.env.KEYSENTRY_ALERT_FROM;
  return from && from.trim() ? from.trim() : DEFAULT_ALERT_FROM;
}

function alertAppUrl(): string {
  const url = process.env.KEYSENTRY_APP_URL;
  return url && url.trim() ? url.trim().replace(/\/$/, "") : DEFAULT_APP_URL;
}

function resendApiKey(): string | null {
  const key = process.env.RESEND_API_KEY;
  return key && key.trim() ? key.trim() : null;
}

function smtpConfig(): {
  host: string;
  port: number;
  user: string;
  pass: string;
} | null {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host?.trim() || !user?.trim() || !pass?.trim()) return null;
  const port = Number(process.env.SMTP_PORT ?? 587);
  return {
    host: host.trim(),
    port: Number.isFinite(port) && port > 0 ? port : 587,
    user: user.trim(),
    pass,
  };
}

/**
 * True when an email can be sent: at least one recipient AND a
 * transport (Resend API key or SMTP credentials) is configured.
 */
export function emailConfigured(): boolean {
  if (alertEmailRecipients().length === 0) return false;
  return resendApiKey() !== null || smtpConfig() !== null;
}

export function matchEmailSubject(match: MatchEmailInput): string {
  const provider = match.provider || "unknown provider";
  return `[KeySentry] Watched key ${match.fingerprint} seen again (${provider})`;
}

export interface MatchEmailBody {
  text: string;
  html: string;
}

export function matchEmailBody(match: MatchEmailInput): MatchEmailBody {
  const provider = match.provider || "unknown provider";
  const where = [match.repo, match.file].filter(Boolean).join(" · ");
  const line = match.line > 0 ? `:${match.line}` : "";
  const location = where ? `${where}${line}` : "(location not recorded)";
  const appUrl = alertAppUrl();

  const text =
    `KeySentry: a watched key was seen again.\n` +
    `\n` +
    `Fingerprint: ${match.fingerprint}\n` +
    `Provider: ${provider}\n` +
    `Seen in: ${location}\n` +
    `First seen: ${match.firstSeen}\n` +
    `\n` +
    `Acknowledge or resolve it at ${appUrl} (matches list).\n` +
    `\n` +
    `The key itself is never included in alerts — only its SHA-256 ` +
    `fingerprint (a one-way hash) is sent, so this email cannot be used ` +
    `to recover the key. Rotate the key if it should no longer work.`;

  const esc = (s: string): string =>
    s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  const html =
    `<p>KeySentry: a watched key was seen again.</p>` +
    `<ul>` +
    `<li><strong>Fingerprint:</strong> <code>${esc(match.fingerprint)}</code></li>` +
    `<li><strong>Provider:</strong> ${esc(provider)}</li>` +
    `<li><strong>Seen in:</strong> ${esc(location)}</li>` +
    `<li><strong>First seen:</strong> ${esc(match.firstSeen)}</li>` +
    `</ul>` +
    `<p>Acknowledge or resolve it in the <a href="${esc(appUrl)}">KeySentry matches list</a>.</p>` +
    `<p><small>The key itself is never included in alerts — only its ` +
    `SHA-256 fingerprint (a one-way hash) is sent, so this email cannot ` +
    `be used to recover the key. Rotate the key if it should no longer work.</small></p>`;

  return { text, html };
}

/** Injectable transports, so tests can mock fetch / nodemailer. */
export interface EmailDeps {
  fetchImpl?: typeof fetch;
  createTransport?: typeof nodemailer.createTransport;
}

async function sendViaResend(
  match: MatchEmailInput,
  fetchImpl: typeof fetch,
): Promise<boolean> {
  const apiKey = resendApiKey();
  if (!apiKey) return false;
  const { text, html } = matchEmailBody(match);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetchImpl(RESEND_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: alertEmailFrom(),
        to: alertEmailRecipients(),
        subject: matchEmailSubject(match),
        text,
        html,
      }),
      signal: controller.signal,
    });
    return res.ok;
  } finally {
    clearTimeout(timer);
  }
}

async function sendViaSmtp(
  match: MatchEmailInput,
  createTransport: typeof nodemailer.createTransport,
): Promise<boolean> {
  const smtp = smtpConfig();
  if (!smtp) return false;
  const { text, html } = matchEmailBody(match);
  const transporter = createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.port === 465,
    auth: { user: smtp.user, pass: smtp.pass },
  });
  await transporter.sendMail({
    from: alertEmailFrom(),
    to: alertEmailRecipients().join(", "),
    subject: matchEmailSubject(match),
    text,
    html,
  });
  return true;
}

/**
 * Send a fingerprint-match email. Returns true when a transport
 * accepted it, false when email is unconfigured or delivery failed.
 * Never throws.
 */
export async function sendMatchEmail(
  match: MatchEmailInput,
  deps: EmailDeps = {},
): Promise<boolean> {
  if (!emailConfigured()) return false;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const createTransport = deps.createTransport ?? nodemailer.createTransport;
  try {
    // Resend first when its key is set; otherwise plain SMTP.
    if (resendApiKey() !== null) {
      return await sendViaResend(match, fetchImpl);
    }
    return await sendViaSmtp(match, createTransport);
  } catch (err) {
    console.error("KeySentry match email failed:", err);
    return false;
  }
}
