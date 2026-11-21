// Upgrade banner (dashboard): shown when the workspace is on the
// Free plan. Names the feature, what the next tier unlocks, and its
// price. The CTA links to the pricing page (/pricing), where each
// paid tier has a working checkout button. Copy comes from
// lib/plans.ts, the same source as the CLI, so the wording matches
// everywhere.
"use client";

import { getPlan, nextTierForFeature, upgradeMessage } from "@/lib/plans";

export default function UpgradeBanner({
  plan = "free",
  feature = "fingerprint_monitoring",
}: {
  plan?: string;
  feature?: string;
}) {
  const current = getPlan(plan);
  const next = nextTierForFeature(plan, feature);
  if (!next) return null;
  const message = upgradeMessage(plan, feature);
  return (
    <div
      role="note"
      aria-label="Upgrade prompt"
      style={{
        border: "1px solid var(--hatch-widget-border)",
        background: "var(--hatch-widget-surface-muted)",
        color: "var(--hatch-widget-text)",
        borderRadius: "8px",
        padding: "0.75rem 1rem",
        margin: "0 0 1rem 0",
        display: "flex",
        flexWrap: "wrap",
        gap: "0.5rem 1rem",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      <p style={{ margin: 0 }}>
        <strong>
          You&apos;re on the {current.name} plan ({current.price_label}).
        </strong>{" "}
        {message}
      </p>
      <a
        href="/pricing"
        style={{ color: "var(--hatch-widget-accent)", whiteSpace: "nowrap" }}
      >
        See upgrade options — {next.name} {next.price_label}
      </a>
    </div>
  );
}
