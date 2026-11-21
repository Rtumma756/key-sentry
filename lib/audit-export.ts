// Compliance export for audit events — TypeScript mirror of
// ai-key-scanner/audit/export.py. Keep the control lists in sync and
// note any intentional divergence in the coordinator report.
//
// IMPORTANT — these are MAPPING TEMPLATES, not certification claims.
// KeySentry is not SOC 2 certified, not ISO 27001 certified, and this
// export does not certify compliance with the EU AI Act. The mappings
// show which logged events an auditor would look at for each control;
// a real audit still needs the organisation's own policies, access
// reviews and auditor judgement. Every report carries this disclaimer.

// This file is deliberately self-contained (no imports from other
// lib/ files): plain-node tests import it directly (tests/audit.test.mjs),
// and Node's type stripping cannot resolve extensionless relative
// imports. The two helpers below mirror lib/audit-redact.ts —
// `canonicalJsonValue` mirrors `canonicalJson`, `utcnowIso` mirrors
// `utcnowIso` — keep them in sync.

/** Canonical JSON: sorted keys, no whitespace (mirrors audit-redact). */
function canonicalJsonValue(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const s = JSON.stringify(value);
    return s === undefined ? "null" : s;
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalJsonValue(v)).join(",") + "]";
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalJsonValue(record[k]))
      .join(",") +
    "}"
  );
}

function utcnowIso(): string {
  return new Date().toISOString();
}

export const DISCLAIMER =
  "Mapping template only — NOT a certification claim. KeySentry is not " +
  "SOC 2 or ISO 27001 certified, and this export does not certify " +
  "compliance with the EU AI Act. It maps logged audit events to the " +
  "controls / articles an auditor would examine; a real audit requires " +
  "the organisation's own policies and an auditor's judgement.";

export interface ControlMapping {
  control: string;
  name: string;
  eventTypes: string[];
}

// SOC 2 Trust Services Criteria mapping: control -> event types that
// evidence it. "any" matches every event type.
export const SOC2_CONTROLS: ControlMapping[] = [
  {
    control: "CC6.1",
    name: "Logical access — access restricted to authorised users",
    eventTypes: ["mcp.tool_call", "agent.action"],
  },
  {
    control: "CC6.6",
    name: "Logical access — encryption / protection of credentials",
    eventTypes: ["vibe.finding"],
  },
  {
    control: "CC7.2",
    name: "Monitoring — system components monitored for anomalies",
    eventTypes: ["any"],
  },
  {
    control: "CC7.3",
    name: "Monitoring — anomalies evaluated and acted on",
    eventTypes: ["agent.action", "vibe.finding"],
  },
  {
    control: "CC8.1",
    name: "Change management — changes authorised and tested",
    eventTypes: ["agent.action"],
  },
];

// ISO/IEC 27001:2022 Annex A mapping.
export const ISO27001_CONTROLS: ControlMapping[] = [
  { control: "A.12.4.1", name: "Event logging", eventTypes: ["any"] },
  {
    control: "A.12.4.2",
    name: "Protection of log information",
    eventTypes: ["any"],
  },
  {
    control: "A.12.4.3",
    name: "Administrator and operator logs",
    eventTypes: ["mcp.tool_call", "agent.action"],
  },
  {
    control: "A.9.2.1",
    name: "User registration and de-registration",
    eventTypes: ["agent.action"],
  },
  {
    control: "A.9.4.2",
    name: "Secure log-on procedures",
    eventTypes: ["mcp.tool_call"],
  },
  { control: "A.8.15", name: "Logging", eventTypes: ["any"] },
];

export const EU_AI_ACT_ARTICLE = "12";

export type AuditEventLike = Record<string, unknown>;

export interface ControlReport {
  framework: string;
  disclaimer: string;
  generatedAt: string;
  eventCount: number;
  eventTypesSeen: string[];
  controls: {
    control: string;
    name: string;
    eventsMatched: number;
    eventIds: string[];
  }[];
}

export interface EuAiActReport {
  framework: string;
  article: string;
  articleTitle: string;
  disclaimer: string;
  generatedAt: string;
  eventCount: number;
  records: {
    eventId: unknown;
    timestamp: unknown;
    actor: {
      principalId: unknown;
      agentId: unknown;
      agentVersion: unknown;
      model: unknown;
      modelRunId: unknown;
    };
    operation: {
      eventType: unknown;
      tool: unknown;
      resource: unknown;
      argKeys: unknown;
    };
    decision: { allow: unknown; policy: unknown; reason: unknown };
    outcome: unknown;
    correlationId: unknown;
    sessionId: unknown;
  }[];
}

function matchedEvents(
  events: AuditEventLike[],
  eventTypes: string[],
): AuditEventLike[] {
  if (eventTypes.includes("any")) return [...events];
  return events.filter((e) => eventTypes.includes(String(e["event_type"] ?? "")));
}

function controlReport(
  events: AuditEventLike[],
  controls: ControlMapping[],
  framework: string,
): ControlReport {
  const typesSeen = [...new Set(events.map((e) => String(e["event_type"] ?? "")).filter(Boolean))].sort();
  return {
    framework,
    disclaimer: DISCLAIMER,
    generatedAt: utcnowIso(),
    eventCount: events.length,
    eventTypesSeen: typesSeen,
    controls: controls.map((control) => {
      const matched = matchedEvents(events, control.eventTypes);
      return {
        control: control.control,
        name: control.name,
        eventsMatched: matched.length,
        eventIds: matched.map((e) => String(e["event_id"] ?? "")),
      };
    }),
  };
}

/** SOC 2 control mapping report (template, not a certification). */
export function soc2Report(events: AuditEventLike[]): ControlReport {
  return controlReport(events, SOC2_CONTROLS, "SOC 2");
}

/** ISO/IEC 27001 Annex A control mapping report (template). */
export function iso27001Report(events: AuditEventLike[]): ControlReport {
  return controlReport(events, ISO27001_CONTROLS, "ISO 27001");
}

/** EU AI Act Article 12 record-keeping report. Art. 12 requires
 * logging that lets an operation be traced: what happened, when, by
 * whom (actor), and what was decided. */
export function euAiActReport(events: AuditEventLike[]): EuAiActReport {
  return {
    framework: "EU AI Act",
    article: EU_AI_ACT_ARTICLE,
    articleTitle: "Record-keeping",
    disclaimer: DISCLAIMER,
    generatedAt: utcnowIso(),
    eventCount: events.length,
    records: events.map((event) => {
      const decision = (event["decision"] ?? {}) as Record<string, unknown>;
      return {
        eventId: event["event_id"],
        timestamp: event["timestamp"],
        actor: {
          principalId: event["principal_id"],
          agentId: event["agent_id"],
          agentVersion: event["agent_version"],
          model: event["model"],
          modelRunId: event["model_run_id"],
        },
        operation: {
          eventType: event["event_type"],
          tool: event["tool"],
          resource: event["resource"],
          argKeys: event["arg_keys"],
        },
        decision: {
          allow: decision["allow"],
          policy: decision["policy"],
          reason: decision["reason"],
        },
        outcome: event["outcome"],
        correlationId: event["correlation_id"],
        sessionId: event["session_id"],
      };
    }),
  };
}

/** SIEM-friendly export: one JSON object per line, canonical form. */
export function siemExport(events: AuditEventLike[]): string {
  return events.map((e) => canonicalJsonValue(e)).join("\n") + (events.length ? "\n" : "");
}

/** Human-readable Markdown rendering of a SOC 2 / ISO 27001 / EU AI
 * Act report. */
export function renderMarkdown(
  report: ControlReport | EuAiActReport,
): string {
  const lines: string[] = [`# ${report.framework} — audit-trail export`, ""];
  if ("article" in report) {
    lines.push(`Article ${report.article}: ${report.articleTitle}`, "");
  }
  lines.push(`> ${report.disclaimer}`, "");
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push(`Events: ${report.eventCount}`, "");
  if ("controls" in report) {
    lines.push("## Control mapping", "");
    lines.push("| Control | Name | Events matched |");
    lines.push("| --- | --- | ---: |");
    for (const row of report.controls) {
      lines.push(`| ${row.control} | ${row.name} | ${row.eventsMatched} |`);
    }
    lines.push("");
  }
  if ("records" in report) {
    lines.push("## Records (Article 12 trace)", "");
    for (const record of report.records) {
      lines.push(
        `- \`${record.timestamp}\` ${record.eventId} — ` +
          `${record.operation.eventType} / ${record.operation.tool} on ` +
          `${record.operation.resource} by agent ${record.actor.agentId} ` +
          `(principal ${record.actor.principalId}), decision allow=` +
          `${record.decision.allow} (${record.decision.policy}), ` +
          `outcome ${record.outcome}.`,
      );
    }
    lines.push("");
  }
  return lines.join("\n");
}

/** Retention policy: hot 30d / warm 90d / cold 7y (pilot: 90 days
 * total — see docs/commercial/AUDIT-RETENTION.md). */
export function retentionWindows(): {
  hotDays: number;
  warmDays: number;
  coldYears: number;
  pilotTotalDays: number;
} {
  return { hotDays: 30, warmDays: 90, coldYears: 7, pilotTotalDays: 90 };
}
