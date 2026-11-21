// Landing page (/) — the public face of KeySentry.
//
// The scanner dashboard lives at /app. This page has one job: in a few
// seconds, a developer should understand the problem (a leaked AI API
// key is someone else's bill on your account), how KeySentry protects
// and solves it, and the "no more worry" outcome — set it up once and
// stop watching GitHub yourself.
//
// Patterns taken from state-of-the-art dev/security pages (Linear,
// GitGuardian, TruffleHog, Snyk, Vercel, Doppler, Stripe, 1Password,
// GitHub, Cloudflare): one-sentence problem in the hero, show the
// product with a real before/after visual, a numbered flow, trust
// through mechanism (not claims), two CTAs with the free tier stated
// up front. No invented testimonials, stats, or customer logos: every
// claim here is a property of the product itself. The example key in
// the hero is fake and labelled as such.
//
// Copy sources: lib/plans.ts (single source of truth for tiers and
// prices), docs/commercial/GO-TO-MARKET.md (pillars), FREE-TIER-CAPS.md
// (free-tier limits), and the confirmed score policy (≥80 = confirmed
// leak, 50–79 = needs review, <50 = excluded).

import type { Metadata } from "next";
import { getAllPlans } from "@/lib/plans";

export const metadata: Metadata = {
  title: "KeySentry — Stop worrying about leaked AI API keys",
  description:
    "A leaked AI API key is someone else's bill on your account. KeySentry finds leaked AI API keys in public code and watches the keys you own — hashes only, so your keys never leave your machine. Free to start.",
};

const CLI_URL = "https://github.com/Rtumma756/ai-key-scanner";
const FEEDBACK_URL = "https://github.com/Rtumma756/key-sentry/issues";

/** Individual: solo use. Team: shared use. (Same split as /pricing.) */
const INDIVIDUAL_IDS = ["free", "maker"];

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} style={{ margin: "2.5rem 0 0 0" }}>
      <h2 style={{ margin: "0 0 0.75rem 0", fontSize: "1.4rem" }}>{title}</h2>
      {children}
    </section>
  );
}

export default function LandingPage() {
  const plans = getAllPlans();
  const individual = plans.filter((t) => INDIVIDUAL_IDS.includes(t.id));
  const team = plans.filter((t) => !INDIVIDUAL_IDS.includes(t.id));
  return (
    <div className="app">
      <header className="app-header">
        <div className="brand-row">
          <h1>KeySentry</h1>
          <span className="client-badge">100% client-side</span>
          <span style={{ marginLeft: "auto", display: "flex", gap: "1rem", alignItems: "center" }}>
            <a href="/pricing">Pricing</a>
            <a href="/app" className="btn-secondary" style={{ textDecoration: "none", padding: "6px 12px" }}>
              Open the scanner
            </a>
          </span>
        </div>
      </header>

      {/* Hero: the problem in one line, the fix in the next. */}
      <section style={{ margin: "1.5rem 0 0 0" }}>
        <h1 style={{ margin: "0 0 0.75rem 0", fontSize: "2.1rem", lineHeight: 1.15 }}>
          A leaked API key is someone else&apos;s bill on your account.
        </h1>
        <p style={{ margin: "0 0 1rem 0", fontSize: "1.1rem", color: "var(--muted)" }}>
          AI keys end up in public code every day — pasted by you, a
          teammate, or an AI agent. KeySentry finds them, and watches the
          keys you own, so the next leak reaches you first.
        </p>
        <div className="action-row" style={{ marginTop: 0 }}>
          <a href="/app" className="btn-primary" style={{ textDecoration: "none" }}>
            Open the scanner
          </a>
          <a href="/pricing" className="btn-secondary" style={{ textDecoration: "none" }}>
            See pricing
          </a>
        </div>
        <p style={{ margin: "0.75rem 0 0 0", fontSize: "0.9rem", color: "var(--muted)" }}>
          Free to start — no account, no card.
        </p>

        {/* Before / after: the leak, and what KeySentry shows you. */}
        <div
          style={{
            display: "flex",
            gap: "12px",
            flexWrap: "wrap",
            alignItems: "stretch",
            marginTop: "1.5rem",
          }}
        >
          <div style={{ flex: "1 1 280px", minWidth: 0 }}>
            <p style={{ margin: "0 0 6px 0", fontSize: "0.85rem", fontWeight: 700, color: "var(--danger-text)" }}>
              IN PUBLIC CODE — EXAMPLE, NOT A REAL KEY
            </p>
            <div className="context-line" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {`// config.js — pushed to a public repo
const client = new OpenAI({
  apiKey: "sk-ant-EXAMPLE0000000000000000",
});`}
            </div>
            <p style={{ margin: "6px 0 0 0", fontSize: "0.85rem", color: "var(--muted)" }}>
              Anyone can copy it. Every call they make is billed to you.
            </p>
          </div>
          <div
            style={{
              alignSelf: "center",
              fontSize: "1.5rem",
              fontWeight: 700,
              color: "var(--accent)",
            }}
            aria-hidden="true"
          >
            →
          </div>
          <div style={{ flex: "1 1 280px", minWidth: 0 }}>
            <p style={{ margin: "0 0 6px 0", fontSize: "0.85rem", fontWeight: 700, color: "var(--ok-text)" }}>
              WHAT KEYSENTRY SHOWS YOU
            </p>
            <div
              className="finding-card severity-high"
              style={{ margin: 0 }}
            >
              <div className="finding-head">
                <h3>Anthropic API key</h3>
                <span className="severity-badge high">Confirmed leak · Score 92</span>
              </div>
              <p className="finding-meta">
                Shown as <code>sk-a…</code> only — never the full key.
              </p>
              <p style={{ margin: "0 0 0 0", fontSize: "0.9rem" }}>
                1. Rotate the key. 2. Remove it from the repo. Done.
              </p>
            </div>
            <p style={{ margin: "6px 0 0 0", fontSize: "0.85rem", color: "var(--muted)" }}>
              You find out from KeySentry — not from next month&apos;s invoice.
            </p>
          </div>
        </div>
      </section>

      {/* What a leak costs. */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "12px",
          marginTop: "1rem",
        }}
      >
        <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 16px" }}>
          <strong>Their usage, your bill.</strong>
          <p style={{ margin: "4px 0 0 0", fontSize: "0.9rem", color: "var(--muted)" }}>
            API usage on a stolen key is billed to the key&apos;s owner — you.
          </p>
        </div>
        <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 16px" }}>
          <strong>It keeps working until you rotate it.</strong>
          <p style={{ margin: "4px 0 0 0", fontSize: "0.9rem", color: "var(--muted)" }}>
            A leaked key stays usable. Deleting the commit doesn&apos;t revoke it.
          </p>
        </div>
        <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 16px" }}>
          <strong>You hear about it last.</strong>
          <p style={{ margin: "4px 0 0 0", fontSize: "0.9rem", color: "var(--muted)" }}>
            Without monitoring, the first sign of a leak is often the invoice.
          </p>
        </div>
      </div>

      {/* The flow: leak → found → alerted → no more worry. */}
      <Section id="how-it-works" title="From leak to fixed — then no more worry">
        <ol style={{ margin: 0, paddingLeft: "1.25rem" }}>
          <li style={{ marginBottom: "0.75rem" }}>
            <strong>It leaks.</strong> A key slips into public code — a
            commit, a gist, or code your AI agent wrote.
          </li>
          <li style={{ marginBottom: "0.75rem" }}>
            <strong>KeySentry finds it.</strong> Scan any public repo or
            paste code. Or register the keys you own by fingerprint, and
            the nightly sweep watches for them.
          </li>
          <li style={{ marginBottom: "0.75rem" }}>
            <strong>You&apos;re alerted.</strong> An email alert and a
            dashboard match, masked to the first 4 characters, with
            plain-language steps to rotate the key.
          </li>
          <li>
            <strong>You stop worrying.</strong> Set it up once. Monitoring
            runs on its own — no more searching GitHub yourself for your
            own keys.
          </li>
        </ol>
        <p style={{ margin: "1rem 0 0 0" }}>
          <a href="/app" className="btn-primary" style={{ textDecoration: "none" }}>
            Open the scanner
          </a>
        </p>
      </Section>

      {/* How it protects: mechanism, not claims. */}
      <Section id="trust" title="How it protects you">
        <p style={{ margin: "0 0 0.75rem 0" }}>
          A scanner that handles secrets has to be trustworthy about secrets.
          These are properties of the product, not promises:
        </p>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "12px",
          }}
        >
          <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 16px" }}>
            <strong>Hashes only.</strong>
            <p style={{ margin: "4px 0 0 0", fontSize: "0.9rem", color: "var(--muted)" }}>
              You register a one-way hash of your key. The key itself never
              leaves your machine, and it can&apos;t be recovered from the
              fingerprint.
            </p>
          </div>
          <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 16px" }}>
            <strong>Masked reports.</strong>
            <p style={{ margin: "4px 0 0 0", fontSize: "0.9rem", color: "var(--muted)" }}>
              A found key is shown by its first 4 characters only — never
              the full key, anywhere in the product.
            </p>
          </div>
          <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 16px" }}>
            <strong>Never tested.</strong>
            <p style={{ margin: "4px 0 0 0", fontSize: "0.9rem", color: "var(--muted)" }}>
              KeySentry never calls a found key to see if it works, never
              unmasks it, never stores it.
            </p>
          </div>
          <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 16px" }}>
            <strong>Scored, not guessed.</strong>
            <p style={{ margin: "4px 0 0 0", fontSize: "0.9rem", color: "var(--muted)" }}>
              Every finding carries a 0–100 score: 80 and up is a confirmed
              leak, 50–79 needs review, under 50 is excluded from the
              headline count.
            </p>
          </div>
        </div>
      </Section>

      <Section id="pricing" title="Pricing">
        <p style={{ margin: "0 0 1rem 0", color: "var(--muted)" }}>
          Start free. Pay when you need monitoring, more repos, or team
          seats. Prices in Canadian dollars; tax is calculated automatically
          at checkout.
        </p>
        <h3 style={{ margin: "0 0 0.5rem 0", fontSize: "1rem" }}>Individual</h3>
        <ul style={{ margin: "0 0 1rem 0", paddingLeft: "1.25rem" }}>
          {individual.map((t) => (
            <li key={t.id} style={{ marginBottom: "0.5rem" }}>
              <strong>{t.name}</strong> — {t.price_label}. {t.summary}
            </li>
          ))}
        </ul>
        <h3 style={{ margin: "0 0 0.5rem 0", fontSize: "1rem" }}>Team</h3>
        <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
          {team.map((t) => (
            <li key={t.id} style={{ marginBottom: "0.5rem" }}>
              <strong>{t.name}</strong> — {t.price_label}. {t.summary}
            </li>
          ))}
        </ul>
        <p style={{ margin: "1rem 0 0 0" }}>
          <a href="/pricing">See full plans &amp; pricing →</a>
        </p>
      </Section>

      <Section id="faq" title="Questions">
        <h3 style={{ margin: "0 0 0.25rem 0" }}>What counts as a leak?</h3>
        <p style={{ margin: "0 0 1rem 0" }}>
          A key that scores 80 or higher is a confirmed leak. Scores of
          50–79 need a human review, and anything under 50 is excluded from
          the count entirely.
        </p>
        <h3 style={{ margin: "0 0 0.25rem 0" }}>
          What happens when one of my keys shows up publicly?
        </h3>
        <p style={{ margin: "0 0 1rem 0" }}>
          You get an email alert (on paid plans) and the match appears on
          your dashboard with steps to rotate the key. The report shows only
          the first 4 characters of the key.
        </p>
        <h3 style={{ margin: "0 0 0.25rem 0" }}>Do you store my API keys?</h3>
        <p style={{ margin: "0 0 1rem 0" }}>
          No. You register a one-way hash — a fingerprint — of the key. The
          key itself never leaves your machine, and it cannot be recovered
          from the fingerprint.
        </p>
        <h3 style={{ margin: "0 0 0.25rem 0" }}>
          How is this different from GitHub&apos;s secret scanning?
        </h3>
        <p style={{ margin: "0 0 1rem 0" }}>
          GitHub&apos;s scanner covers GitHub repos. KeySentry is built for
          AI API keys: it scans any public code you paste or point it at,
          watches your own keys by fingerprint, and scores every finding so
          you only chase real leaks.
        </p>
        <h3 style={{ margin: "0 0 0.25rem 0" }}>Is the free tier really free?</h3>
        <p style={{ margin: 0 }}>
          Yes. No account, no card. Free covers 2 repo scans and 2 identity
          audits a day, 5 fingerprints, and 7 days of audit history.
        </p>
      </Section>

      {/* Closing CTA: the no-more-worry outcome. */}
      <section
        style={{
          margin: "2.5rem 0 0 0",
          textAlign: "center",
          background: "var(--accent-bg)",
        }}
      >
        <h2 style={{ margin: "0 0 0.5rem 0", fontSize: "1.4rem" }}>
          Set it up once. Then stop worrying about leaked keys.
        </h2>
        <p style={{ margin: "0 0 1rem 0", color: "var(--muted)" }}>
          Register your keys, and KeySentry keeps watch. Free to start — no
          account, no card.
        </p>
        <div className="action-row" style={{ justifyContent: "center", marginTop: 0 }}>
          <a href="/app" className="btn-primary" style={{ textDecoration: "none" }}>
            Open the scanner
          </a>
          <a href="/pricing" className="btn-secondary" style={{ textDecoration: "none" }}>
            See pricing
          </a>
        </div>
      </section>

      <footer
        style={{
          margin: "2.5rem 0 0 0",
          paddingTop: "1rem",
          borderTop: "1px solid var(--border)",
          fontSize: "0.9rem",
          color: "var(--muted)",
          display: "flex",
          gap: "1rem",
          flexWrap: "wrap",
        }}
      >
        <a href="/app">Open the scanner</a>
        <a href="/pricing">Plans &amp; pricing</a>
        <a href={CLI_URL} target="_blank" rel="noreferrer">
          CLI on GitHub
        </a>
        <a href={FEEDBACK_URL} target="_blank" rel="noreferrer">
          Report an issue
        </a>
      </footer>
    </div>
  );
}
