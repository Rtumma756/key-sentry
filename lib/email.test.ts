// Unit tests for lib/email.ts — mocked transports only, no real
// network or credentials. Run with:
//   npx tsc lib/email.test.ts lib/email.ts --module nodenext \
//     --target es2022 --moduleResolution nodenext --outDir /tmp/email-test
//   node --test /tmp/email-test/email.test.js
// (The web app has no test runner configured; the compile+run above is
// the verification path. `npm run build` type-checks this file too.)
//
// All fixture keys use the obviously-fake TESTFAKE marker and are never
// real-looking keys. The "raw key" asserted absent from every email is
// a dummy TESTFAKE string, never a stranger's key.

import { test } from "node:test";
import assert from "node:assert/strict";
import nodemailer from "nodemailer";
import {
  emailConfigured,
  matchEmailBody,
  matchEmailSubject,
  sendMatchEmail,
  type MatchEmailInput,
} from "./email";

// Dummy "raw key" — obviously fake, used ONLY to assert it never
// appears in any email subject or body.
const DUMMY_RAW_KEY = "sk-TESTFAKE-DO-NOT-USE-1234567890abcdef";
const MATCH: MatchEmailInput = {
  fingerprint: "06fabb99a6b4976b",
  provider: "Groq",
  repo: "acme/app",
  file: ".env",
  line: 7,
  firstSeen: "2026-11-21T00:00:00.000Z",
};

const EMAIL_ENV_KEYS = [
  "KEYSENTRY_ALERT_EMAIL",
  "KEYSENTRY_ALERT_FROM",
  "KEYSENTRY_APP_URL",
  "RESEND_API_KEY",
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_USER",
  "SMTP_PASS",
] as const;

function setEnv(vars: Record<string, string>): void {
  for (const key of EMAIL_ENV_KEYS) delete process.env[key];
  for (const [key, value] of Object.entries(vars)) {
    process.env[key] = value;
  }
}

function clearEnv(): void {
  for (const key of EMAIL_ENV_KEYS) delete process.env[key];
}

function okFetch(capture: { url?: string; init?: RequestInit }): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    capture.url = String(url);
    capture.init = init;
    return new Response(JSON.stringify({ id: "test-id" }), { status: 200 });
  }) as unknown as typeof fetch;
}

function failingFetch(): typeof fetch {
  return (async () => {
    throw new Error("network down");
  }) as unknown as typeof fetch;
}

function errorFetch(status: number): typeof fetch {
  return (async () =>
    new Response("error", { status })) as unknown as typeof fetch;
}

function fakeTransport(capture: {
  options?: object;
  mail?: Record<string, unknown>;
}): typeof nodemailer.createTransport {
  return ((options: object) => ({
    sendMail: async (mail: Record<string, unknown>) => {
      capture.options = options;
      capture.mail = mail;
      return { messageId: "test-message-id" };
    },
  })) as unknown as typeof nodemailer.createTransport;
}

function throwingTransport(): typeof nodemailer.createTransport {
  return (() => ({
    sendMail: async () => {
      throw new Error("SMTP refused");
    },
  })) as unknown as typeof nodemailer.createTransport;
}

test("unconfigured: no env at all -> false, no throw", async () => {
  clearEnv();
  try {
    assert.equal(emailConfigured(), false);
    assert.equal(await sendMatchEmail(MATCH), false);
  } finally {
    clearEnv();
  }
});

test("recipients set but no transport -> false, no throw", async () => {
  setEnv({ KEYSENTRY_ALERT_EMAIL: "owner@example.com" });
  try {
    assert.equal(emailConfigured(), false);
    assert.equal(await sendMatchEmail(MATCH), false);
  } finally {
    clearEnv();
  }
});

test("Resend configured + fetch ok -> true; payload has match, no raw key", async () => {
  const capture: { url?: string; init?: RequestInit } = {};
  setEnv({
    KEYSENTRY_ALERT_EMAIL: "owner@example.com, ops@example.com",
    RESEND_API_KEY: "re_TESTFAKE",
  });
  try {
    assert.equal(emailConfigured(), true);
    assert.equal(
      await sendMatchEmail(MATCH, { fetchImpl: okFetch(capture) }),
      true,
    );
    assert.equal(capture.url, "https://api.resend.com/emails");
    const headers = capture.init?.headers as Record<string, string>;
    assert.equal(headers.Authorization, "Bearer re_TESTFAKE");
    const body = JSON.parse(String(capture.init?.body));
    assert.deepEqual(body.to, ["owner@example.com", "ops@example.com"]);
    assert.ok(body.subject.includes(MATCH.fingerprint));
    assert.ok(body.text.includes(MATCH.fingerprint));
    assert.ok(body.text.includes("Groq"));
    assert.ok(body.text.includes("acme/app"));
    assert.ok(body.text.includes(".env"));
    assert.ok(!body.text.includes(DUMMY_RAW_KEY));
    assert.ok(!body.html.includes(DUMMY_RAW_KEY));
    assert.ok(body.text.includes("never included in alerts"));
  } finally {
    clearEnv();
  }
});

test("Resend configured + fetch rejects -> false, no throw", async () => {
  setEnv({
    KEYSENTRY_ALERT_EMAIL: "owner@example.com",
    RESEND_API_KEY: "re_TESTFAKE",
  });
  try {
    assert.equal(
      await sendMatchEmail(MATCH, { fetchImpl: failingFetch() }),
      false,
    );
  } finally {
    clearEnv();
  }
});

test("Resend configured + non-2xx -> false, no throw", async () => {
  setEnv({
    KEYSENTRY_ALERT_EMAIL: "owner@example.com",
    RESEND_API_KEY: "re_TESTFAKE",
  });
  try {
    assert.equal(
      await sendMatchEmail(MATCH, { fetchImpl: errorFetch(401) }),
      false,
    );
  } finally {
    clearEnv();
  }
});

test("SMTP configured + transport ok -> true; mail has match, no raw key", async () => {
  const capture: { options?: object; mail?: Record<string, unknown> } = {};
  setEnv({
    KEYSENTRY_ALERT_EMAIL: "owner@example.com",
    SMTP_HOST: "smtp.example.com",
    SMTP_PORT: "587",
    SMTP_USER: "user@example.com",
    SMTP_PASS: "TESTFAKE-pass",
  });
  try {
    assert.equal(emailConfigured(), true);
    assert.equal(
      await sendMatchEmail(MATCH, {
        createTransport: fakeTransport(capture),
      }),
      true,
    );
    assert.deepEqual(capture.options, {
      host: "smtp.example.com",
      port: 587,
      secure: false,
      auth: { user: "user@example.com", pass: "TESTFAKE-pass" },
    });
    const mail = capture.mail ?? {};
    assert.ok(String(mail.subject).includes(MATCH.fingerprint));
    assert.ok(String(mail.text).includes(MATCH.fingerprint));
    assert.ok(String(mail.text).includes("Groq"));
    assert.ok(String(mail.text).includes("acme/app"));
    assert.ok(!String(mail.text).includes(DUMMY_RAW_KEY));
    assert.ok(!String(mail.html).includes(DUMMY_RAW_KEY));
  } finally {
    clearEnv();
  }
});

test("SMTP configured + transport throws -> false, no throw", async () => {
  setEnv({
    KEYSENTRY_ALERT_EMAIL: "owner@example.com",
    SMTP_HOST: "smtp.example.com",
    SMTP_USER: "user@example.com",
    SMTP_PASS: "TESTFAKE-pass",
  });
  try {
    assert.equal(
      await sendMatchEmail(MATCH, {
        createTransport: throwingTransport(),
      }),
      false,
    );
  } finally {
    clearEnv();
  }
});

test("Resend wins over SMTP when both are configured", async () => {
  const capture: { url?: string; init?: RequestInit } = {};
  const smtpCapture: { mail?: Record<string, unknown> } = {};
  setEnv({
    KEYSENTRY_ALERT_EMAIL: "owner@example.com",
    RESEND_API_KEY: "re_TESTFAKE",
    SMTP_HOST: "smtp.example.com",
    SMTP_USER: "user@example.com",
    SMTP_PASS: "TESTFAKE-pass",
  });
  try {
    assert.equal(
      await sendMatchEmail(MATCH, {
        fetchImpl: okFetch(capture),
        createTransport: fakeTransport(smtpCapture),
      }),
      true,
    );
    assert.equal(capture.url, "https://api.resend.com/emails");
    assert.equal(smtpCapture.mail, undefined);
  } finally {
    clearEnv();
  }
});

test("subject and body contain fingerprint/provider/repo, never the raw key", () => {
  clearEnv();
  try {
    const subject = matchEmailSubject(MATCH);
    const { text, html } = matchEmailBody(MATCH);
    for (const part of [subject, text, html]) {
      assert.ok(part.includes(MATCH.fingerprint));
      assert.ok(!part.includes(DUMMY_RAW_KEY));
    }
    assert.ok(text.includes("Groq"));
    assert.ok(text.includes("acme/app"));
    assert.ok(text.includes(".env"));
    assert.ok(text.includes("https://key-sentry-inky.vercel.app"));
    assert.ok(text.includes("never included in alerts"));
    assert.ok(html.includes("never included in alerts"));
  } finally {
    clearEnv();
  }
});
