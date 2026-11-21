// Server-side plan enforcement — wraps lib/usage.ts (DO NOT edit
// usage.ts). Routes call enforcePlanLimit before a guarded operation;
// the plan check runs first, then the existing daily abuse-cap counter
// from usage.ts when the resource has one.
//
// When the plan state is missing/unknown the plan resolves to Free
// (see lib/plans.ts) and all free-layer capabilities keep working;
// commercial features return an upgrade prompt, never a crash.

import {
  checkLimit as checkDailyLimit,
  getMaxFingerprintsPerDay,
  USAGE_KEY_FINGERPRINTS_ADDED,
} from "./usage";
import {
  getPlan,
  getPlanId,
  limitCheck,
  dailyCapMessage,
  dailyCapUpgrade,
  type LimitCheckResult,
  type PlanId,
  type ResourceKey,
  type UpgradePrompt,
} from "./plans";
import { getDailyCount, resetsAtUtc } from "./usage";
import { getWorkspacePlan } from "./billing-db";
import { usageDay } from "./usage-policy";

export interface PlanEnforcementResult {
  allowed: boolean;
  /** Upgrade prompt when a plan limit (or daily cap) blocks the call. */
  upgrade?: string;
  /** The plan limit for the resource (null = unlimited). */
  limit: number | null;
  used: number;
}

/** Daily abuse-cap counters (lib/usage.ts) keyed by plan resource.
 * Only fingerprints have a daily counter today; other resources rely
 * on the plan limit alone. */
const DAILY_COUNTERS: Partial<
  Record<ResourceKey, { key: string; maxPerDay: () => number; what: string }>
> = {
  fingerprints: {
    key: USAGE_KEY_FINGERPRINTS_ADDED,
    maxPerDay: getMaxFingerprintsPerDay,
    what: "fingerprints added",
  },
};

/** Enforce `plan`'s limit for `resource` at `used` total held.
 *
 * `workspaceId` is reserved for per-workspace counters (the usage
 * counters are workspace-global today, matching lib/usage.ts). When
 * the database is not configured the daily-cap check is skipped —
 * the plan check has already run, and the free layer must never break
 * because billing/DB is unconfigured.
 */
export async function enforcePlanLimit(
  workspaceId: string,
  plan: PlanId | string | null | undefined,
  resource: ResourceKey,
  used: number,
): Promise<PlanEnforcementResult> {
  void workspaceId; // reserved: counters are workspace-global today
  const planCheck: LimitCheckResult = limitCheck(plan, resource, used);
  if (!planCheck.allowed) {
    return {
      allowed: false,
      upgrade: planCheck.message,
      limit: planCheck.limit,
      used,
    };
  }
  const counter = DAILY_COUNTERS[resource];
  if (!counter) {
    return { allowed: true, limit: planCheck.limit, used };
  }
  try {
    const daily = await checkDailyLimit(counter.key, counter.maxPerDay());
    if (!daily.allowed) {
      return {
        allowed: false,
        upgrade:
          `Daily limit reached: at most ${daily.limit} ${counter.what} ` +
          `per day (already ${daily.count} today). Try again tomorrow.`,
        limit: planCheck.limit,
        used,
      };
    }
  } catch {
    // No database configured (or DB unreachable): skip the daily cap.
    // The plan limit above already applied; never fail open or closed
    // on infrastructure the free layer does not need.
  }
  return { allowed: true, limit: planCheck.limit, used };
}

/** Convenience: the current plan's display name (defaults to Free). */
export function planDisplayName(
  plan: PlanId | string | null | undefined,
): string {
  return getPlan(plan).name;
}

// ---------------------------------------------------------------------------
// Free-tier daily caps (FREE-TIER-CAPS.md).
// ---------------------------------------------------------------------------

/** Resolve the plan id for a workspace. Any failure (no row, no
 * database, DB unreachable) resolves to Free — the free-never-
 * locked-out rule: the free layer keeps working with its caps, and
 * commercial features return an upgrade prompt, never a crash. */
export async function resolveWorkspacePlanId(
  workspaceId = "default",
): Promise<string> {
  try {
    const row = await getWorkspacePlan(workspaceId);
    return getPlanId(row?.plan ?? null);
  } catch {
    return "free";
  }
}

export interface DailyCapResult {
  allowed: boolean;
  /** The plan's daily limit for the resource (null = unlimited). */
  limit: number | null;
  /** Uses so far today. */
  used: number;
  /** ISO timestamp of next midnight UTC (when the cap resets). */
  resetsAt: string;
  /** Full denial message when blocked (limit + upgrade + come back
   * tomorrow); empty when allowed. */
  message: string;
  /** Structured upgrade prompt when blocked; null when allowed (or
   * when no higher tier lifts the cap). */
  upgrade: UpgradePrompt | null;
}

/** Enforce `plan`'s daily cap for `resource` at `counterKey`
 * (a `<resource>:<scope>` key from lib/usage.ts — the count is read,
 * never recorded here; the route records after the guarded operation
 * succeeds). A null plan limit is unlimited. Never throws: a counter
 * read failure counts as 0 uses rather than breaking the free layer.
 */
export async function enforceDailyCap(
  workspaceId: string,
  plan: PlanId | string | null | undefined,
  resource: ResourceKey,
  counterKey: string,
  day: string = usageDay(),
): Promise<DailyCapResult> {
  void workspaceId; // reserved: counters are keyed by scope, not workspace
  void day; // the counter store buckets by the current UTC day itself
  const tier = getPlan(plan);
  const limit = tier.limits[resource];
  let used = 0;
  try {
    used = await getDailyCount(counterKey);
  } catch {
    used = 0;
  }
  const resetsAt = resetsAtUtc();
  if (limit === null || used < limit) {
    return { allowed: true, limit, used, resetsAt, message: "", upgrade: null };
  }
  return {
    allowed: false,
    limit,
    used,
    resetsAt,
    message: dailyCapMessage(plan, resource, used),
    upgrade: dailyCapUpgrade(plan, resource),
  };
}
