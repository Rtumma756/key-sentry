// Free-tier usage counter badge: "1 of 2 free scans used today".
// Shared by the vibe, agents, and audit pages and the home-page
// banner. `used` is today's count (null when the count is not known —
// e.g. MCP queries, which the MCP server counts locally); `limit` is
// the plan's cap (null = unlimited). `variant` "allowance" renders a
// non-daily allowance instead ("1 of 1 agents on the timeline").
// Copy comes from lib/plans.ts formatCounter/formatAllowance, the
// same wording as the CLI (`plans.py counters`).

"use client";

import { formatAllowance, formatCounter } from "@/lib/plans";

export default function CounterBadge({
  used,
  limit,
  label,
  planName = "Free",
  variant = "daily",
  suffix,
}: {
  used: number | null;
  limit: number | null;
  label: string;
  planName?: string;
  variant?: "daily" | "allowance";
  suffix?: string;
}) {
  let text: string;
  if (variant === "allowance") {
    text =
      used === null
        ? `${label}: ${limit === null ? "unlimited" : `up to ${limit}`} on the ${planName} plan`
        : formatAllowance(used, limit, label);
  } else if (used === null) {
    text = `${label}: ${limit === null ? "unlimited" : `up to ${limit}`} on the ${planName} plan`;
  } else {
    text = formatCounter(used, limit, label, planName);
  }
  return (
    <p
      role="status"
      aria-label="Free usage counter"
      style={{
        margin: 0,
        padding: "0.4rem 0.75rem",
        border: "1px solid var(--border)",
        borderRadius: "8px",
        background: "var(--surface)",
        color: "var(--text)",
        fontSize: "0.9rem",
        display: "inline-block",
      }}
    >
      {text}
      {suffix ? (
        <span style={{ color: "var(--muted)" }}> · {suffix}</span>
      ) : null}
    </p>
  );
}
