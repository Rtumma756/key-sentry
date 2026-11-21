// Plan definitions (web side) — mirrors ai-key-scanner/plans.py.
//
// Single source of truth: docs/commercial/plans.json, synced to
// lib/plans.json by scripts/sync_plans.py (verbatim copy — never edit
// this JSON by hand). The message templates live in that JSON, so the
// upgrade copy here is identical to the CLI's by construction.
//
// Free-never-locked-out rule: an unknown plan id (or missing plan
// state) resolves to Free and ALL free-layer capabilities keep
// working; commercial features return an upgrade prompt, never a
// crash or a silent block.

import plansData from "./plans.json" with { type: "json" };

export type PlanId =
  | "free"
  | "maker"
  | "starter"
  | "premium"
  | "team"
  | "premium_plus"
  | "business"
  | "enterprise";

export interface PlanLimits {
  repos: number | null;
  fingerprints: number | null;
  scans_per_day: number | null;
  audit_timeline_agents: number | null;
  vibe_reports: number | null;
  audits_per_day: number | null;
  mcp_queries_per_day: number | null;
  dashboard_saves_per_day: number | null;
  shareable_reports: number | null;
  audit_timeline_days: number | null;
  seats: number | null;
  fingerprint_checks_per_day: number | null;
}

export interface PlanDefinition {
  id: PlanId;
  name: string;
  price_monthly_usd: number | null;
  price_label: string;
  summary: string;
  limits: PlanLimits;
  features: string[];
}

export type ResourceKey = keyof PlanLimits;

interface PlansFile {
  version: number;
  tier_order: string[];
  upgrade_template: string;
  upgrade_template_custom: string;
  limit_message_template: string;
  daily_limit_message_template?: string;
  daily_cap_suffix?: string;
  resources: Record<
    string,
    {
      label: string;
      upgrade_feature?: string;
      /** Daily cap (resets at midnight UTC) — see FREE-TIER-CAPS.md. */
      daily?: boolean;
      reset?: string;
      /** Tier to name on a cap hit (caps build); see limitUpgradeDetails. */
      next_tier?: string;
      /** Copy for what that tier unlocks for this resource. */
      upgrade_unlocks?: string;
    }
  >;
  features: Record<string, { label: string; unlocks: string }>;
  tiers: Record<string, PlanDefinition>;
}

const PLANS = plansData as unknown as PlansFile;

export const DEFAULT_PLAN_ID: PlanId = "free";

export const TIER_ORDER: PlanId[] = PLANS.tier_order.filter(
  (t): t is PlanId => t in PLANS.tiers,
);

/** The Free default returned when no workspace-plan row exists (or
 * no DB is configured) — the free layer keeps working. Pure helper,
 * so tests can cover the default without a live database. */
export interface WorkspacePlanSummary {
  workspaceId: string;
  plan: string;
  stripeCustomerId: string | null;
  status: string;
  updatedAt: string;
}

export function defaultWorkspacePlan(
  workspaceId = "default",
): WorkspacePlanSummary {
  return {
    workspaceId,
    plan: "free",
    stripeCustomerId: null,
    status: "free",
    updatedAt: new Date().toISOString(),
  };
}

/** All plan definitions, in tier order. */
export function getAllPlans(): PlanDefinition[] {
  return TIER_ORDER.map((id) => PLANS.tiers[id]);
}

/** Tier definition for a plan id. Unknown ids, null, and anything
 * unparseable resolve to Free — the free layer never breaks on
 * unknown plan state. */
export function getPlan(plan: string | null | undefined): PlanDefinition {
  if (typeof plan === "string" && plan in PLANS.tiers) {
    return PLANS.tiers[plan];
  }
  return PLANS.tiers[DEFAULT_PLAN_ID];
}

/** Normalized plan id; unknown -> 'free'. */
export function getPlanId(plan: string | null | undefined): PlanId {
  return getPlan(plan).id;
}

export function featureAllowed(
  plan: string | null | undefined,
  feature: string,
): boolean {
  return (getPlan(plan).features ?? []).includes(feature);
}

/** Human-readable label for a feature id (from plans.json). Unknown
 * ids fall back to the id itself — never a blank label. */
export function featureLabel(feature: string): string {
  return PLANS.features[feature]?.label ?? feature;
}

/** First tier above `plan` (in tier order) that allows `feature`. */
export function nextTierForFeature(
  plan: string | null | undefined,
  feature: string,
): PlanDefinition | null {
  const current = getPlanId(plan);
  const start = TIER_ORDER.indexOf(current) + 1;
  for (const tierId of TIER_ORDER.slice(start)) {
    const tier = PLANS.tiers[tierId];
    if ((tier.features ?? []).includes(feature)) return tier;
  }
  return null;
}

function formatUpgrade(tier: PlanDefinition, unlocks: string): string {
  if (tier.price_monthly_usd === null) {
    return PLANS.upgrade_template_custom
      .replace("{tier}", tier.name)
      .replace("{unlocks}", unlocks);
  }
  return PLANS.upgrade_template
    .replace("{tier}", tier.name)
    .replace("{price}", String(tier.price_monthly_usd))
    .replace("{unlocks}", unlocks);
}

/** Upgrade prompt for a feature `plan` does not include. Names the
 * next tier, its price, and exactly what it unlocks. When the feature
 * is already included, says so instead of upselling. */
export function upgradeMessage(
  plan: string | null | undefined,
  feature: string,
): string {
  const tier = getPlan(plan);
  const def = PLANS.features[feature];
  const label = def?.label ?? feature;
  if (featureAllowed(plan, feature)) {
    return `${label} is included in your ${tier.name} plan.`;
  }
  const next = nextTierForFeature(plan, feature);
  if (next === null) {
    return `${label} is not available on any paid plan yet.`;
  }
  return formatUpgrade(next, def?.unlocks ?? label);
}

/** First tier above `plan` with a higher (or unlimited) limit for
 * `resource`. */
export function nextTierForLimit(
  plan: string | null | undefined,
  resource: ResourceKey,
): PlanDefinition | null {
  const current = getPlan(plan);
  const currentLimit = current.limits[resource];
  const start = TIER_ORDER.indexOf(current.id) + 1;
  for (const tierId of TIER_ORDER.slice(start)) {
    const tier = PLANS.tiers[tierId];
    const limit = tier.limits[resource];
    if (limit === null || (currentLimit !== null && limit > currentLimit)) {
      return tier;
    }
  }
  return null;
}

function formatLimit(limit: number | null): string {
  return limit === null ? "unlimited" : `up to ${limit}`;
}

export interface UpgradeDetails {
  tier: PlanDefinition;
  unlocks: string;
  message: string;
}

/** Structured upgrade prompt for a cap hit (the JSON cap-hit
 * responses carry this object): the next tier's name, price label,
 * what it unlocks for this resource, and the full sentence. */
export interface UpgradePrompt {
  message: string;
  tier: string;
  price: string;
  unlocks: string;
}

function toUpgradePrompt(details: UpgradeDetails): UpgradePrompt {
  return {
    message: details.message,
    tier: details.tier.name,
    price: details.tier.price_label,
    unlocks: details.unlocks,
  };
}

/** Structured upgrade for a denied limit check, or null.
 *
 * Preference order (the caps build, FREE-TIER-CAPS.md):
 *   1. The resource's explicit `next_tier` (plans.json) when it sits
 *      above the current plan and raises the limit — this is what
 *      makes scans/MCP/saves name Maker while audits/fingerprints
 *      name Starter, instead of the layer model's "Starter for
 *      everything". Copy comes from `upgrade_unlocks`.
 *   2. The resource's `upgrade_feature` route (existing behavior).
 *   3. The next tier that raises the limit.
 * Same logic as plans.py _limit_upgrade_details.
 */
export function limitUpgradeDetails(
  plan: string | null | undefined,
  resource: ResourceKey,
): UpgradeDetails | null {
  const def = PLANS.resources[resource];
  const label = def?.label ?? resource;
  const tier = getPlan(plan);
  const currentLimit = tier.limits[resource];
  const raises = (next: PlanDefinition): boolean => {
    const nextLimit = next.limits[resource];
    return (
      nextLimit === null ||
      (currentLimit !== null && nextLimit > currentLimit)
    );
  };
  // 1. Explicit per-resource next tier (caps build).
  const nextTierId = def?.next_tier;
  if (
    typeof nextTierId === "string" &&
    nextTierId in PLANS.tiers &&
    TIER_ORDER.includes(tier.id) &&
    TIER_ORDER.includes(nextTierId as PlanId) &&
    TIER_ORDER.indexOf(nextTierId as PlanId) > TIER_ORDER.indexOf(tier.id)
  ) {
    const next = PLANS.tiers[nextTierId];
    if (raises(next)) {
      const unlocks =
        def.upgrade_unlocks ??
        `${formatLimit(next.limits[resource])} ${label}`;
      return { tier: next, unlocks, message: formatUpgrade(next, unlocks) };
    }
  }
  // 2. Feature route (layer-model behavior, unchanged).
  const feature = def?.upgrade_feature;
  if (feature && !featureAllowed(plan, feature)) {
    const next = nextTierForFeature(plan, feature);
    if (next !== null && raises(next)) {
      return {
        tier: next,
        unlocks: PLANS.features[feature]?.unlocks ?? feature,
        message: upgradeMessage(plan, feature),
      };
    }
  }
  // 3. Next tier that raises the limit.
  const next = nextTierForLimit(plan, resource);
  if (next === null) return null;
  const unlocks = `${formatLimit(next.limits[resource])} ${label}`;
  return { tier: next, unlocks, message: formatUpgrade(next, unlocks) };
}

function limitUpgradeMessage(
  plan: string | null | undefined,
  resource: ResourceKey,
): string {
  return limitUpgradeDetails(plan, resource)?.message ?? "";
}

/** Structured upgrade prompt for a feature `plan` does not include
 * (used by the sweep skip-free gate and the alerts gate). Null when
 * the feature is already included or no higher tier offers it. */
export function upgradePrompt(
  plan: string | null | undefined,
  feature: string,
): UpgradePrompt | null {
  const next = nextTierForFeature(plan, feature);
  if (next === null) return null;
  if (featureAllowed(plan, feature)) return null;
  const unlocks = PLANS.features[feature]?.unlocks ?? feature;
  return toUpgradePrompt({
    tier: next,
    unlocks,
    message: formatUpgrade(next, unlocks),
  });
}

/** Structured upgrade prompt for a limit hit on `resource`, or null.
 * The generic form of dailyCapUpgrade (which is this, for daily
 * resources). */
export function limitUpgradePrompt(
  plan: string | null | undefined,
  resource: ResourceKey,
): UpgradePrompt | null {
  const details = limitUpgradeDetails(plan, resource);
  return details === null ? null : toUpgradePrompt(details);
}

/** Structured upgrade prompt for a daily-cap hit, or null. Null when
 * the plan's limit for the resource is already unlimited (no cap to
 * hit) or no higher tier lifts it. */
export function dailyCapUpgrade(
  plan: string | null | undefined,
  resource: ResourceKey,
): UpgradePrompt | null {
  if (getPlan(plan).limits[resource] === null) return null;
  return limitUpgradePrompt(plan, resource);
}

/** Full denial message for a daily-cap hit: limit sentence + upgrade
 * (next tier, price, unlocks) + the come-back-tomorrow suffix. Never
 * a bare error, never a dead end. */
export function dailyCapMessage(
  plan: string | null | undefined,
  resource: ResourceKey,
  used: number,
): string {
  const tier = getPlan(plan);
  const limit = tier.limits[resource];
  if (limit === null) return "";
  const label = PLANS.resources[resource]?.label ?? resource;
  const template =
    PLANS.daily_limit_message_template ??
    "{plan} plan allows up to {limit} {label} (you have used {used} today).";
  let message = template
    .replace("{plan}", tier.name)
    .replace("{limit}", String(limit))
    .replace("{label}", label)
    .replace("{used}", String(used));
  const upgrade = limitUpgradeMessage(plan, resource);
  if (upgrade) message += ` ${upgrade}`;
  message += ` ${
    PLANS.daily_cap_suffix ??
    "Come back tomorrow, it works again (free caps reset at midnight UTC)."
  }`;
  return message;
}

export interface DailyCapCheck {
  allowed: boolean;
  /** Full daily-cap message when denied; empty when allowed. */
  message: string;
  limit: number | null;
  used: number;
}

/** Is one more use of daily-capped `resource` allowed? Allowed when
 * usedToday < limit; a null limit is unlimited. Same semantics as
 * plans.py check_daily_cap. */
export function checkDailyCap(
  plan: string | null | undefined,
  resource: ResourceKey,
  usedToday: number,
): DailyCapCheck {
  const tier = getPlan(plan);
  const limit = tier.limits[resource];
  if (limit === null) {
    return { allowed: true, message: "", limit, used: usedToday };
  }
  if (usedToday < limit) {
    return { allowed: true, message: "", limit, used: usedToday };
  }
  return {
    allowed: false,
    message: dailyCapMessage(plan, resource, usedToday),
    limit,
    used: usedToday,
  };
}

/** Counter display: "1 of 2 free scans used today". `label` is the
 * short resource name ("scans", "audits", "dashboard saves",
 * "MCP queries"). Same wording as plans.py format_counter. */
export function formatCounter(
  used: number,
  limit: number | null,
  label: string,
  planName = "Free",
): string {
  if (limit === null) {
    return `${used} ${label} used today (unlimited on the ${planName} plan)`;
  }
  if (planName === "Free") {
    return `${used} of ${limit} free ${label} used today`;
  }
  return `${used} of ${limit} ${label} used today (${planName} plan)`;
}

/** Non-daily allowance display: "1 of 1 agents on the timeline".
 * Used by the audit timeline (1 agent, last 7 days) — not a daily
 * counter, so no "used today" phrasing. */
export function formatAllowance(
  used: number,
  limit: number | null,
  label: string,
): string {
  if (limit === null) return `${used} ${label} (unlimited)`;
  return `${used} of ${limit} ${label}`;
}

/** Free audit-timeline restriction (FREE-TIER-CAPS.md): Free sees one
 * agent and the last 7 days of events; paid tiers see their own
 * agent/day limits (Maker/Starter: 1 agent, 30 days; Team: all
 * agents, 90 days; Business: all agents, 7 years). Events outside
 * the allowance are excluded — never an error, never a dead end —
 * and the response names the upgrade that lifts the wall.
 *
 * `events` are the raw event JSON objects (agent_id, timestamp).
 * The allowed agent is the agent of the newest event (by timestamp);
 * an explicit agent filter upstream narrows the list first, so the
 * newest event is that agent's. `now` is injectable for tests.
 */
export interface AuditTimelineEventLike {
  agent_id?: string;
  timestamp?: string;
  [key: string]: unknown;
}

export interface AuditTimelineRestriction {
  events: AuditTimelineEventLike[];
  allowedAgent: string | null;
  windowDays: number | null;
  excludedAgents: number;
  excludedOlder: number;
  upgrade: UpgradePrompt | null;
}

export function restrictAuditTimeline(
  events: AuditTimelineEventLike[],
  plan: string | null | undefined,
  now: Date = new Date(),
): AuditTimelineRestriction {
  const tier = getPlan(plan);
  const agentLimit = tier.limits.audit_timeline_agents;
  const days = tier.limits.audit_timeline_days;
  const cutoff =
    days === null ? null : now.getTime() - days * 24 * 60 * 60 * 1000;
  // Newest event's agent is the allowed one (events arrive newest
  // first from listAuditEvents; max-timestamp wins regardless).
  let allowedAgent: string | null = null;
  let newest = -Infinity;
  for (const e of events) {
    const t = Date.parse(e.timestamp ?? "");
    if (Number.isFinite(t) && t > newest) {
      newest = t;
      allowedAgent = e.agent_id ?? null;
    }
  }
  if (allowedAgent === null && events.length > 0) {
    allowedAgent = events[0].agent_id ?? null;
  }
  let excludedAgents = 0;
  let excludedOlder = 0;
  const kept: AuditTimelineEventLike[] = [];
  for (const e of events) {
    if (agentLimit !== null && e.agent_id !== allowedAgent) {
      excludedAgents++;
      continue;
    }
    if (cutoff !== null) {
      const t = Date.parse(e.timestamp ?? "");
      if (!Number.isFinite(t) || t < cutoff) {
        excludedOlder++;
        continue;
      }
    }
    kept.push(e);
  }
  let upgrade: UpgradePrompt | null = null;
  if (excludedAgents > 0) {
    // A second agent needs the full timeline (Team).
    upgrade = upgradePrompt(plan, "full_audit_timeline");
  } else if (excludedOlder > 0) {
    // Older events need more history: the next tier that raises the
    // day limit (Free -> Maker, 30 days; Maker -> Team, 90 days).
    upgrade = limitUpgradePrompt(plan, "audit_timeline_days");
  }
  return {
    events: kept,
    allowedAgent,
    windowDays: days,
    excludedAgents,
    excludedOlder,
    upgrade,
  };
}

/** Shareable-report free list (FREE-TIER-CAPS.md): Free shows the
 * latest 2 reports per type; a 3rd report replaces the oldest in
 * the list. Paid tiers see the whole list. The stored reports are
 * never deleted — a direct GET by id still works, so links stay live.
 *
 * `reports` carry a `type` (default "vibe") and createdAt/created_at.
 */
export interface ReportListLike {
  type?: string;
  createdAt?: string;
  created_at?: string;
  [key: string]: unknown;
}

export function latestReportsForPlan<T extends ReportListLike>(
  reports: T[],
  plan: string | null | undefined,
): T[] {
  const tier = getPlan(plan);
  const limit = tier.limits.shareable_reports;
  if (limit === null) return reports;
  const createdOf = (r: T): number => {
    const t = Date.parse(r.createdAt ?? r.created_at ?? "");
    return Number.isFinite(t) ? t : 0;
  };
  const byType = new Map<string, T[]>();
  for (const r of reports) {
    const type = r.type ?? "vibe";
    const group = byType.get(type) ?? [];
    group.push(r);
    byType.set(type, group);
  }
  const out: T[] = [];
  for (const group of byType.values()) {
    out.push(
      ...[...group]
        .sort((a, b) => createdOf(b) - createdOf(a))
        .slice(0, limit),
    );
  }
  return out.sort((a, b) => createdOf(b) - createdOf(a));
}

export interface LimitCheckResult {
  allowed: boolean;
  /** Empty when allowed; the limit + upgrade message when denied. */
  message: string;
  limit: number | null;
  used: number;
}

/** Is `used` of `resource` within `plan`'s limit? `used` is the total
 * count held (e.g. fingerprints watched). Allowed when used <= limit;
 * a null limit is unlimited (within abuse caps). Same semantics as
 * plans.py check_limit. */
export function limitCheck(
  plan: string | null | undefined,
  resource: ResourceKey,
  used: number,
): LimitCheckResult {
  const tier = getPlan(plan);
  const limit = tier.limits[resource];
  if (limit === null) {
    return { allowed: true, message: "", limit, used };
  }
  const label = PLANS.resources[resource]?.label ?? resource;
  if (used <= limit) {
    return { allowed: true, message: "", limit, used };
  }
  let message = PLANS.limit_message_template
    .replace("{plan}", tier.name)
    .replace("{limit}", String(limit))
    .replace("{label}", label)
    .replace("{used}", String(used));
  const upgrade = limitUpgradeMessage(plan, resource);
  if (upgrade) message += ` ${upgrade}`;
  return { allowed: false, message, limit, used };
}
