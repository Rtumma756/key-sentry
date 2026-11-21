// Landing page (/) — the public face of KeySentry.
//
// The scanner dashboard lives at /app. This page explains the product,
// earns the trust a security tool needs, and points at the scanner and
// the pricing page. No invented testimonials, stats, or customer logos:
// every claim here is a property of the product itself.
//
// Copy sources: lib/plans.ts (single source of truth for tiers and
// prices), docs/commercial/GO-TO-MARKET.md (pillars), FREE-TIER-CAPS.md
// (free-tier limits), and the confirmed score policy (≥80 = confirmed
// leak, 50–79 = needs review, <50 = excluded).

import type { Metadata } from "next";
import { getAllPlans } from "@/lib/plans";

export const metadata: Metadata = {
  title: "KeySentry — Find leaked AI API keys before someone else does",
  description:
    "KeySentry finds leaked AI API keys in public code and watches the keys you own, so you get alerted if one shows up publicly. Hashes only — your keys never leave your machine. Free to start.",
};

const CLI_URL = "https://github.com/Rtumma756/ai-key-scanner";
const FEEDBACK_URL = "https://github.com/Rtumma756/key-sentry/issues";

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

      <section style={{ margin: "1.5rem 0 0 0" }}>
        <h1 style={{ margin: "0 0 0.75rem 0", fontSize: "2rem", lineHeight: 1.2 }}>
          Find leaked AI API keys before someone else does.
        </h1>
        <p style={{ margin: "0 0 1rem 0", fontSize: "1.1rem", color: "var(--muted)" }}>
          KeySentry finds leaked AI API keys — OpenAI, Anthropic, Gemini,
          Groq, and more — in public code, and watches the keys you own, so
          you get alerted if one shows up publicly.
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
      </section>

      <Section id="how-it-works" title="How it works">
        <ol style={{ margin: 0, paddingLeft: "1.25rem" }}>
          <li style={{ marginBottom: "0.75rem" }}>
            <strong>Scan.</strong> Paste code or point KeySentry at a public
            repo. It checks for leaked AI API keys across 13 providers —
            and scans the code your AI agents wrote, too.
          </li>
          <li style={{ marginBottom: "0.75rem" }}>
            <strong>Register fingerprints.</strong> For the keys you actually
            use, register a fingerprint. Only a one-way hash is stored —
            the key itself never leaves your machine.
          </li>
          <li>
            <strong>Get alerted.</strong> If a fingerprinted key ever shows
            up in public code, you get an email alert and the match appears
            on your dashboard, with plain-language steps to rotate it.
          </li>
        </ol>
      </Section>

      <Section id="trust" title="What KeySentry never does">
        <p style={{ margin: "0 0 0.75rem 0" }}>
          A scanner that handles secrets has to be trustworthy about secrets.
          These are properties of the product, not promises:
        </p>
        <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
          <li style={{ marginBottom: "0.5rem" }}>
            <strong>Your keys never leave your machine.</strong> Fingerprints
            are one-way hashes. Scanning runs in your browser; the CLI runs
            on your machine.
          </li>
          <li style={{ marginBottom: "0.5rem" }}>
            <strong>Reports are masked.</strong> A found key is shown by its
            first 4 characters only — never the full key.
          </li>
          <li style={{ marginBottom: "0.5rem" }}>
            <strong>Found keys are never tested, unmasked, or stored.</strong>{" "}
            KeySentry does not call anyone else&apos;s key to see if it works.
          </li>
          <li>
            <strong>Confidence is scored, not guessed.</strong> Every finding
            carries a 0–100 score: 80 and up is a confirmed leak, 50–79 needs
            review, under 50 is excluded from the headline count.
          </li>
        </ul>
      </Section>

      <Section id="pricing" title="Pricing">
        <p style={{ margin: "0 0 1rem 0", color: "var(--muted)" }}>
          Start free. Pay when you need monitoring, more repos, or team
          seats. Prices in Canadian dollars; tax is calculated automatically
          at checkout.
        </p>
        <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
          {plans.map((t) => (
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
        <h3 style={{ margin: "0 0 0.25rem 0" }}>Is the free tier really free?</h3>
        <p style={{ margin: 0 }}>
          Yes. No account, no card. Free covers 2 repo scans and 2 identity
          audits a day, 5 fingerprints, and 7 days of audit history.
        </p>
      </Section>

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
