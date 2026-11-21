// Five first detections over audit events (pure functions, no DB).
// TypeScript mirror of ai-key-scanner/audit/detections.py — same five
// detectors, same names, same thresholds. Change both together.
//
// 1. tool_set_drift — an agent calls a tool outside its established set.
// 2. cost_spike — event count per (agent, model) per hour vs the
//    trailing baseline, above threshold (event count = token/cost proxy).
// 3. confidence_floor_breach — events carrying a confidence score below
//    the floor.
// 4. cross_tenant_access — one agent touching resources of two
//    different tenants (resource tenant prefix differs).
// 5. sub_agent_fanout — a parent agent spawning children above
//    threshold in a window.
//
// Each detector returns alerts:
//   { detector, severity, evidence_event_ids, summary }

export const TOOL_DRIFT_BASELINE_EVENTS = 5;
export const COST_SPIKE_THRESHOLD = 3.0;
export const COST_SPIKE_MIN_EVENTS = 10;
export const CONFIDENCE_FLOOR = 0.7;
export const FANOUT_MAX_CHILDREN = 5;
export const FANOUT_WINDOW_SECONDS = 3600;

export type AuditEventLike = Record<string, unknown>;

export interface AuditAlert {
  detector: string;
  severity: "low" | "medium" | "high";
  evidence_event_ids: string[];
  summary: string;
}

function eventId(e: AuditEventLike): string {
  return String(e["event_id"] ?? "");
}

function sortedEvents(events: AuditEventLike[]): AuditEventLike[] {
  return [...events].sort((a, b) =>
    String(a["timestamp"] ?? "").localeCompare(String(b["timestamp"] ?? "")),
  );
}

/** Tenant prefix of a resource. `tenant:acme/db/users` -> `acme`;
 * `acme/db/users` (no tenant prefix) -> null. */
export function tenantOf(resource: string): string | null {
  if (!resource) return null;
  let rest = resource;
  if (rest.startsWith("tenant:")) {
    rest = rest.slice("tenant:".length);
  } else if (rest.split("/")[0].includes(":")) {
    rest = rest.split(":", 2)[1];
  } else {
    return null;
  }
  const tenant = rest.split("/")[0].trim();
  return tenant || null;
}

export function detectToolSetDrift(
  events: AuditEventLike[],
  baselineEvents: number = TOOL_DRIFT_BASELINE_EVENTS,
): AuditAlert[] {
  const alerts: AuditAlert[] = [];
  const byAgent = new Map<string, AuditEventLike[]>();
  for (const event of sortedEvents(events)) {
    const agent = String(event["agent_id"] ?? "");
    if (!agent) continue;
    const list = byAgent.get(agent) ?? [];
    list.push(event);
    byAgent.set(agent, list);
  }
  for (const [agent, agentEvents] of byAgent) {
    if (agentEvents.length <= baselineEvents) continue;
    const baseline = new Set(
      agentEvents.slice(0, baselineEvents).map((e) => String(e["tool"] ?? "")),
    );
    const newTools = new Map<string, string[]>();
    for (const event of agentEvents.slice(baselineEvents)) {
      const tool = String(event["tool"] ?? "");
      if (tool && !baseline.has(tool)) {
        const ids = newTools.get(tool) ?? [];
        ids.push(eventId(event));
        newTools.set(tool, ids);
      }
    }
    for (const [tool, ids] of [...newTools.entries()].sort()) {
      alerts.push({
        detector: "tool_set_drift",
        severity: "medium",
        evidence_event_ids: ids,
        summary:
          `Agent ${agent} called tool '${tool}' outside its established ` +
          `tool set (${[...baseline].sort()}).`,
      });
    }
  }
  return alerts;
}

export function detectCostSpike(
  events: AuditEventLike[],
  threshold: number = COST_SPIKE_THRESHOLD,
  minEvents: number = COST_SPIKE_MIN_EVENTS,
): AuditAlert[] {
  const alerts: AuditAlert[] = [];
  const buckets = new Map<string, AuditEventLike[]>();
  for (const event of events) {
    const tsText = String(event["timestamp"] ?? "");
    // Hour bucket from the timestamp as written (same as Python's
    // strftime on the parsed value); invalid timestamps are skipped.
    if (Number.isNaN(Date.parse(tsText)) || tsText.length < 13) continue;
    const hour = tsText.slice(0, 13) + ":00:00";
    const key = JSON.stringify([
      String(event["agent_id"] ?? ""),
      String(event["model"] ?? ""),
      hour,
    ]);
    const list = buckets.get(key) ?? [];
    list.push(event);
    buckets.set(key, list);
  }
  const hoursByAgentModel = new Map<string, Map<string, number>>();
  const idsByKey = new Map<string, string[]>();
  for (const [key, hourEvents] of buckets) {
    const [agent, model, hour] = JSON.parse(key) as string[];
    const groupKey = JSON.stringify([agent, model]);
    const hours = hoursByAgentModel.get(groupKey) ?? new Map();
    hours.set(hour, hourEvents.length);
    hoursByAgentModel.set(groupKey, hours);
    idsByKey.set(key, hourEvents.map(eventId));
  }
  for (const [groupKey, hours] of hoursByAgentModel) {
    const [agent, model] = JSON.parse(groupKey) as string[];
    const ordered = [...hours.keys()].sort();
    for (let i = 1; i < ordered.length; i++) {
      const prior = ordered.slice(0, i).map((h) => hours.get(h) ?? 0);
      const baseline = prior.reduce((a, b) => a + b, 0) / prior.length;
      const count = hours.get(ordered[i]) ?? 0;
      if (baseline > 0 && count >= minEvents && count >= threshold * baseline) {
        const key = JSON.stringify([agent, model, ordered[i]]);
        alerts.push({
          detector: "cost_spike",
          severity: "high",
          evidence_event_ids: idsByKey.get(key) ?? [],
          summary:
            `Agent ${agent} (${model}) logged ${count} events in hour ` +
            `${ordered[i]}, ${(count / baseline).toFixed(1)}x its trailing ` +
            `baseline of ${baseline.toFixed(1)}/hour (threshold ` +
            `${threshold}x, min ${minEvents}).`,
        });
      }
    }
  }
  return alerts;
}

export function detectConfidenceFloor(
  events: AuditEventLike[],
  floor: number = CONFIDENCE_FLOOR,
): AuditAlert[] {
  const alerts: AuditAlert[] = [];
  const byAgent = new Map<string, AuditEventLike[]>();
  for (const event of events) {
    const confidence = event["confidence"];
    if (typeof confidence === "number" && confidence < floor) {
      const agent = String(event["agent_id"] ?? "");
      const list = byAgent.get(agent) ?? [];
      list.push(event);
      byAgent.set(agent, list);
    }
  }
  for (const [agent, agentEvents] of [...byAgent.entries()].sort()) {
    const lowest = Math.min(
      ...agentEvents.map((e) => e["confidence"] as number),
    );
    alerts.push({
      detector: "confidence_floor_breach",
      severity: lowest < 0.5 ? "high" : "medium",
      evidence_event_ids: agentEvents.map(eventId),
      summary:
        `Agent ${agent || "(unknown)"} had ${agentEvents.length} event(s) ` +
        `below the confidence floor ${floor} (lowest ${lowest.toFixed(2)}).`,
    });
  }
  return alerts;
}

export function detectCrossTenantAccess(
  events: AuditEventLike[],
): AuditAlert[] {
  const alerts: AuditAlert[] = [];
  const byAgent = new Map<string, Map<string, string[]>>();
  for (const event of events) {
    const tenant = tenantOf(String(event["resource"] ?? ""));
    if (tenant === null) continue;
    const agent = String(event["agent_id"] ?? "");
    const tenants = byAgent.get(agent) ?? new Map();
    const ids = tenants.get(tenant) ?? [];
    ids.push(eventId(event));
    tenants.set(tenant, ids);
    byAgent.set(agent, tenants);
  }
  for (const [agent, tenants] of [...byAgent.entries()].sort()) {
    if (tenants.size < 2) continue;
    const ids = [...tenants.values()].flat();
    alerts.push({
      detector: "cross_tenant_access",
      severity: "high",
      evidence_event_ids: ids,
      summary:
        `Agent ${agent || "(unknown)"} touched ${tenants.size} tenants ` +
        `in one trail: ${[...tenants.keys()].sort()}.`,
    });
  }
  return alerts;
}

export function detectSubagentFanout(
  events: AuditEventLike[],
  maxChildren: number = FANOUT_MAX_CHILDREN,
  windowSeconds: number = FANOUT_WINDOW_SECONDS,
): AuditAlert[] {
  const alerts: AuditAlert[] = [];
  const byParent = new Map<string, AuditEventLike[]>();
  for (const event of events) {
    const parent = String(event["parent_agent_id"] ?? "");
    const child = String(event["agent_id"] ?? "");
    if (parent && child && child !== parent) {
      const list = byParent.get(parent) ?? [];
      list.push(event);
      byParent.set(parent, list);
    }
  }
  for (const [parent, parentEvents] of [...byParent.entries()].sort()) {
    const parsed = sortedEvents(parentEvents)
      .map((e) => ({ event: e, ts: new Date(String(e["timestamp"] ?? "")) }))
      .filter(({ ts }) => !Number.isNaN(ts.getTime()));
    for (let i = 0; i < parsed.length; i++) {
      const window = parsed
        .slice(i)
        .filter(
          ({ ts }) =>
            (ts.getTime() - parsed[i].ts.getTime()) / 1000 <= windowSeconds,
        );
      const children = new Set(window.map(({ event }) => String(event["agent_id"] ?? "")));
      if (children.size > maxChildren) {
        alerts.push({
          detector: "sub_agent_fanout",
          severity: "high",
          evidence_event_ids: window.map(({ event }) => eventId(event)),
          summary:
            `Parent agent ${parent} spawned ${children.size} distinct ` +
            `child agents within ${windowSeconds}s (max ${maxChildren}): ` +
            `${[...children].sort()}.`,
        });
        break; // one alert per parent, at the first breach
      }
    }
  }
  return alerts;
}

export const DETECTORS = [
  detectToolSetDrift,
  detectCostSpike,
  detectConfidenceFloor,
  detectCrossTenantAccess,
  detectSubagentFanout,
];

export function runAllDetections(events: AuditEventLike[]): AuditAlert[] {
  return DETECTORS.flatMap((detector) => detector(events));
}
