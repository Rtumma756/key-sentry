// Pricing page (/pricing) — the real upgrade page.
//
// Two sections, Individual and Team, with one simple card per tier.
// Data comes from lib/plans.ts (the single source of truth, synced
// from docs/commercial/plans.json), so the prices and features here
// always match the CLI and the API docs.
//
// Upgrade buttons POST { tier } to /api/billing/checkout. On a live
// session the browser is sent to Stripe Checkout; on any failure the
// page shows a plain-language message — never raw JSON. Free shows as
// the current plan with no checkout button; Enterprise is custom
// pricing with a "Contact us" note and no checkout.

"use client";

import { useEffect, useState } from "react";
import { friendlyCheckoutError } from "@/lib/billing";
import {
  featureLabel,
  getAllPlans,
  getPlanId,
  type PlanDefinition,
} from "@/lib/plans";

/** Individual: solo use. Team: shared use. (Starter sits in Team —
 * it is the entry team tier even though its seat count is 1.) */
const INDIVIDUAL_IDS = ["free", "maker"];
const TEAM_IDS = [
  "starter",
  "premium",
  "team",
  "premium_plus",
  "business",
  "enterprise",
];

function historyLabel(days: number | null): string {
  if (days === null) return "Unlimited audit history";
  if (days >= 365) {
    const years = Math.round(days / 365);
    return `${years}-year audit history`;
  }
  return `${days}-day audit history`;
}

/** One short line of the tier's key limits, from plans.ts. */
function limitLine(tier: PlanDefinition): string {
  const l = tier.limits;
  const repos =
    l.repos === null
      ? "Unlimited repos"
      : `${l.repos} ${l.repos === 1 ? "repo" : "repos"}`;
  const fingerprints =
    l.fingerprints === null
      ? "Unlimited fingerprints"
      : `${l.fingerprints} fingerprints`;
  const seats =
    l.seats === null
      ? "Unlimited seats"
      : `${l.seats} ${l.seats === 1 ? "seat" : "seats"}`;
  return [repos, fingerprints, seats, historyLabel(l.audit_timeline_days)].join(
    " · ",
  );
}

function TierCard({
  tier,
  isCurrent,
  busy,
  onUpgrade,
}: {
  tier: PlanDefinition;
  isCurrent: boolean;
  busy: boolean;
  onUpgrade: (tierId: string) => void;
}) {
  const isFree = tier.id === "free";
  const isEnterprise = tier.id === "enterprise";
  return (
    <article
      aria-label={`${tier.name} plan`}
      style={{
        border: isCurrent
          ? "2px solid var(--accent)"
          : "1px solid var(--border)",
        borderRadius: "var(--radius)",
        background: "var(--surface)",
        padding: "1rem 1.25rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.5rem",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          justifyContent: "space-between",
          gap: "0.5rem",
        }}
      >
        <h3 style={{ margin: 0, fontSize: "1.1rem" }}>{tier.name}</h3>
        {isCurrent ? (
          <span
            style={{
              fontSize: "0.8rem",
              fontWeight: 600,
              color: "var(--ok-text)",
              background: "var(--ok-bg)",
              border: "1px solid var(--ok-border)",
              borderRadius: "999px",
              padding: "0.1rem 0.6rem",
              whiteSpace: "nowrap",
            }}
          >
            Current plan
          </span>
        ) : null}
      </div>
      <p style={{ margin: 0, fontSize: "1.25rem", fontWeight: 700 }}>
        {tier.price_label}
        {tier.price_monthly_usd !== null ? (
          <span
            style={{ fontSize: "0.85rem", fontWeight: 400, color: "var(--muted)" }}
          >
            {" "}
            / month
          </span>
        ) : null}
      </p>
      <p style={{ margin: 0, color: "var(--muted)" }}>{tier.summary}</p>
      <p style={{ margin: 0, fontSize: "0.9rem" }}>{limitLine(tier)}</p>
      <ul style={{ margin: "0.25rem 0 0 0", paddingLeft: "1.25rem" }}>
        {tier.features.map((f) => (
          <li key={f}>{featureLabel(f)}</li>
        ))}
      </ul>
      <div style={{ marginTop: "auto", paddingTop: "0.75rem" }}>
        {isCurrent ? (
          <p style={{ margin: 0, color: "var(--muted)" }}>
            {isFree
              ? "You're on the Free plan — no card needed."
              : "You're on this plan."}
          </p>
        ) : isEnterprise ? (
          <p style={{ margin: 0, color: "var(--muted)" }}>
            Custom pricing — contact us to set it up.
          </p>
        ) : (
          <button
            type="button"
            disabled={busy}
            onClick={() => onUpgrade(tier.id)}
            style={{
              background: "var(--accent)",
              color: "#fff",
              border: "none",
              borderRadius: "8px",
              padding: "0.6rem 1.25rem",
              fontWeight: 600,
            }}
          >
            {busy ? "Starting checkout…" : `Upgrade to ${tier.name}`}
          </button>
        )}
      </div>
    </article>
  );
}

function Section({
  title,
  subtitle,
  tiers,
  currentPlan,
  busyTier,
  onUpgrade,
}: {
  title: string;
  subtitle: string;
  tiers: PlanDefinition[];
  currentPlan: string;
  busyTier: string | null;
  onUpgrade: (tierId: string) => void;
}) {
  return (
    <section aria-label={title} style={{ marginTop: "2rem" }}>
      <h2 style={{ margin: "0 0 0.25rem 0" }}>{title}</h2>
      <p style={{ margin: "0 0 1rem 0", color: "var(--muted)" }}>{subtitle}</p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))",
          gap: "1rem",
        }}
      >
        {tiers.map((tier) => (
          <TierCard
            key={tier.id}
            tier={tier}
            isCurrent={tier.id === currentPlan}
            busy={busyTier === tier.id}
            onUpgrade={onUpgrade}
          />
        ))}
      </div>
    </section>
  );
}

export default function PricingPage() {
  const [currentPlan, setCurrentPlan] = useState<string>("free");
  const [busyTier, setBusyTier] = useState<string | null>(null);
  const [error, setError] = useState("");

  // The current workspace plan (Free when unknown) highlights the
  // matching card. Failure to load it leaves the Free default.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/usage/counters");
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled && typeof data.plan === "string") {
          setCurrentPlan(getPlanId(data.plan));
        }
      } catch {
        // Counters unavailable: Free stays highlighted.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function upgrade(tierId: string) {
    setError("");
    setBusyTier(tierId);
    try {
      const res = await fetch("/api/billing/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tier: tierId }),
      });
      const data: unknown = await res.json().catch(() => null);
      const url = (data as { session?: { url?: unknown } } | null)?.session
        ?.url;
      if (res.ok && typeof url === "string" && url.startsWith("https://")) {
        window.location.href = url;
        return;
      }
      if ((data as { mode?: unknown } | null)?.mode === "dry-run") {
        setError(
          "Checkout is in dry-run mode, so no payment page was created. " +
            "Live checkout needs to be enabled first — no charge was made.",
        );
      } else {
        setError(friendlyCheckoutError(res.status, data));
      }
    } catch {
      setError(friendlyCheckoutError(0, null));
    } finally {
      setBusyTier(null);
    }
  }

  const all = getAllPlans();
  const individual = INDIVIDUAL_IDS.map((id) =>
    all.find((t) => t.id === id),
  ).filter((t): t is PlanDefinition => Boolean(t));
  const team = TEAM_IDS.map((id) => all.find((t) => t.id === id)).filter(
    (t): t is PlanDefinition => Boolean(t),
  );

  return (
    <div className="app">
      <p style={{ margin: "0 0 1rem 0" }}>
        <a href="/">← Back to dashboard</a>
      </p>
      <h1 style={{ margin: "0 0 0.5rem 0" }}>Plans &amp; pricing</h1>
      <p style={{ margin: "0 0 0.5rem 0", color: "var(--muted)" }}>
        Start free — no account, no card. Upgrade when you need more repos,
        fingerprints, or team seats.
      </p>
      <p style={{ margin: 0, color: "var(--muted)", fontSize: "0.9rem" }}>
        Prices are in Canadian dollars; applicable tax is calculated
        automatically at checkout.
      </p>
      {error ? (
        <p
          role="alert"
          style={{
            margin: "1rem 0 0 0",
            padding: "0.75rem 1rem",
            border: "1px solid var(--danger-border)",
            background: "var(--danger-bg)",
            color: "var(--danger-text)",
            borderRadius: "8px",
          }}
        >
          {error}
        </p>
      ) : null}
      <Section
        title="Individual"
        subtitle="For solo use — one seat."
        tiers={individual}
        currentPlan={currentPlan}
        busyTier={busyTier}
        onUpgrade={upgrade}
      />
      <Section
        title="Team"
        subtitle="For teams working together."
        tiers={team}
        currentPlan={currentPlan}
        busyTier={busyTier}
        onUpgrade={upgrade}
      />
    </div>
  );
}
