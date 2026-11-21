// Agent audit trail — timeline view (Pillar 3).
//
// Passphrase-gated for the pilot (same VAULT_ADMIN_PASS as the vault):
// the passphrase is kept in component state only, sent as the
// x-admin-pass header, and never stored. Timeline shows what each
// agent did, in order, with the decision attached; the verify button
// recomputes the hash chain server-side and shows per-event pass/fail.

"use client";

import { useCallback, useEffect, useState } from "react";
import CounterBadge from "../components/CounterBadge";

interface AuditEvent {
  event_id?: string;
  event_type?: string;
  timestamp?: string;
  agent_id?: string;
  session_id?: string;
  correlation_id?: string;
  tool?: string;
  resource?: string;
  arg_keys?: string[];
  decision?: { allow?: boolean; policy?: string; reason?: string };
  outcome?: string;
  model?: string;
  confidence?: number | null;
  event_hash?: string;
}

interface VerifyItem {
  index: number;
  eventId: string;
  ok: boolean;
  error: string | null;
  continued: boolean;
}

interface Alert {
  detector: string;
  severity: string;
  evidence_event_ids: string[];
  summary: string;
}

export default function AuditPage() {
  const [adminPass, setAdminPass] = useState("");
  const [unlocked, setUnlocked] = useState(false);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [agentFilter, setAgentFilter] = useState("");
  const [sessionFilter, setSessionFilter] = useState("");
  const [runFilter, setRunFilter] = useState("");
  const [verifyResult, setVerifyResult] = useState<{
    ok: boolean;
    count: number;
    firstBadIndex: number | null;
    continuedFromArchive: boolean;
    events: VerifyItem[];
  } | null>(null);
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [alertCount, setAlertCount] = useState(0);
  // Free-tier timeline allowance (1 agent, last 7 days on Free) and
  // the upgrade prompt when events were excluded. The limits come
  // from the counters endpoint; the badge's "used" is the distinct
  // agents in the loaded timeline.
  const [timeline, setTimeline] = useState<{
    agentsLimit: number | null;
    daysLimit: number | null;
  } | null>(null);
  const [planName, setPlanName] = useState("Free");
  const [upgradeNote, setUpgradeNote] = useState("");

  useEffect(() => {
    fetch("/api/usage/counters")
      .then(async (res) => {
        if (!res.ok) return;
        const data = await res.json();
        const t = data.counters?.audit_timeline;
        if (t) {
          setTimeline({
            agentsLimit: t.agentsLimit ?? null,
            daysLimit: t.daysLimit ?? null,
          });
        }
        if (typeof data.planName === "string") setPlanName(data.planName);
      })
      .catch(() => {});
  }, []);

  const headers = useCallback(
    () => ({ "x-admin-pass": adminPass }),
    [adminPass],
  );

  async function loadTimeline() {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      if (agentFilter) params.set("agent", agentFilter);
      if (sessionFilter) params.set("session", sessionFilter);
      if (runFilter) params.set("run", runFilter);
      const res = await fetch(`/api/audit?${params}`, {
        headers: headers(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Could not load timeline.");
      setEvents(data.events ?? []);
      setUpgradeNote(data.upgrade?.message ?? "");
      setUnlocked(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load timeline.");
    } finally {
      setLoading(false);
    }
  }

  async function runVerify() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/audit/verify", { headers: headers() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Verification failed.");
      setVerifyResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
    } finally {
      setLoading(false);
    }
  }

  async function runDetect() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/audit/detect", { headers: headers() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Detection run failed.");
      setAlerts(data.alerts ?? []);
      setAlertCount(data.eventCount ?? 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Detection run failed.");
    } finally {
      setLoading(false);
    }
  }

  async function downloadExport(format: string) {
    setError("");
    try {
      const res = await fetch(`/api/audit/export?format=${format}`, {
        headers: headers(),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error ?? "Export failed.");
      }
      const text = await res.text();
      const ext = format === "siem" ? "jsonl" : "json";
      const blob = new Blob([text], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `keysentry-audit-${format}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed.");
    }
  }

  return (
    <main className="app">
      <header className="app-header">
        <h1>Agent audit trail</h1>
        <p className="muted">
          What each agent did, in order, with the decision attached. Events
          are hash-chained and tamper-evident; argument values are never
          stored, only key names.
        </p>
      </header>

      {!unlocked && (
        <section aria-label="Admin unlock">
          <p className="muted">
            The timeline is passphrase-gated for the pilot (same admin
            passphrase as the vault).
          </p>
          <div className="vault-admin-row">
            <input
              type="password"
              value={adminPass}
              onChange={(e) => setAdminPass(e.target.value)}
              placeholder="Admin passphrase"
              aria-label="Admin passphrase"
            />
            <button
              className="btn-primary"
              onClick={loadTimeline}
              disabled={loading || !adminPass}
            >
              {loading ? "Loading…" : "Unlock timeline"}
            </button>
          </div>
        </section>
      )}

      {error && <p className="error-banner">{error}</p>}

      {unlocked && (
        <>
          {timeline ? (
            <div style={{ marginBottom: "1rem" }}>
              <CounterBadge
                used={
                  new Set(events.map((e) => e.agent_id ?? "")).size
                }
                limit={timeline.agentsLimit}
                label="agents on the audit timeline"
                planName={planName}
                variant="allowance"
                suffix={
                  timeline.daysLimit === null
                    ? "Full history"
                    : `Last ${timeline.daysLimit} days of events`
                }
              />
            </div>
          ) : null}
          {upgradeNote ? (
            <p className="muted" role="note">
              {upgradeNote}
            </p>
          ) : null}
          <section aria-label="Timeline filters">
            <div className="vault-admin-row">
              <input
                value={agentFilter}
                onChange={(e) => setAgentFilter(e.target.value)}
                placeholder="Filter: agent id"
                aria-label="Filter by agent"
              />
              <input
                value={sessionFilter}
                onChange={(e) => setSessionFilter(e.target.value)}
                placeholder="Filter: session id"
                aria-label="Filter by session"
              />
              <input
                value={runFilter}
                onChange={(e) => setRunFilter(e.target.value)}
                placeholder="Filter: run / task id"
                aria-label="Filter by run"
              />
              <button
                className="btn-secondary"
                onClick={loadTimeline}
                disabled={loading}
              >
                Apply filters
              </button>
            </div>
            <div className="vault-admin-row">
              <button
                className="btn-secondary"
                onClick={runVerify}
                disabled={loading}
              >
                Verify chain
              </button>
              <button
                className="btn-secondary"
                onClick={runDetect}
                disabled={loading}
              >
                Run detections
              </button>
              <button
                className="btn-secondary"
                onClick={() => downloadExport("soc2")}
              >
                Export SOC 2
              </button>
              <button
                className="btn-secondary"
                onClick={() => downloadExport("iso27001")}
              >
                Export ISO 27001
              </button>
              <button
                className="btn-secondary"
                onClick={() => downloadExport("eu-ai-act")}
              >
                Export EU AI Act Art. 12
              </button>
              <button
                className="btn-secondary"
                onClick={() => downloadExport("siem")}
              >
                Export SIEM (JSONL)
              </button>
            </div>
          </section>

          {verifyResult && (
            <section aria-label="Chain verification">
              <h2>Chain verification</h2>
              <p>
                {verifyResult.ok
                  ? `Chain intact — ${verifyResult.count} events verified.`
                  : `CHAIN BROKEN — first bad index ${verifyResult.firstBadIndex}.`}
                {verifyResult.continuedFromArchive &&
                  " (Chain continues from an archived segment.)"}
              </p>
              <ul>
                {verifyResult.events.map((item) => (
                  <li key={item.index}>
                    [{item.index}] {item.ok ? "PASS" : "FAIL"}{" "}
                    {item.eventId}
                    {item.continued ? " (continues from archive)" : ""}
                    {item.error ? ` — ${item.error}` : ""}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {alerts !== null && (
            <section aria-label="Detections">
              <h2>Detections ({alerts.length} alerts over {alertCount} events)</h2>
              {alerts.length === 0 ? (
                <p className="muted">No alerts — nothing breached a threshold.</p>
              ) : (
                <ul>
                  {alerts.map((alert, i) => (
                    <li key={i}>
                      <strong>{alert.detector}</strong> [{alert.severity}] —{" "}
                      {alert.summary}
                    </li>
                  ))}
                </ul>
              )}
            </section>
          )}

          <section aria-label="Timeline">
            <h2>Timeline ({events.length} events)</h2>
            {events.length === 0 ? (
              <p className="muted">
                No events yet. Ingest events via POST /api/audit or the CLI
                (`audit.py log`).
              </p>
            ) : (
              <ol>
                {events.map((event) => (
                  <li key={event.event_id} style={{ marginBottom: 12 }}>
                    <div>
                      <code>{event.timestamp}</code> —{" "}
                      <strong>{event.event_type}</strong> · agent{" "}
                      {event.agent_id} · tool {event.tool}
                    </div>
                    <div className="muted">
                      resource {event.resource ?? "—"} · arg keys:{" "}
                      {(event.arg_keys ?? []).join(", ") || "—"} · run{" "}
                      {event.correlation_id ?? "—"}
                    </div>
                    <div>
                      Decision:{" "}
                      {event.decision?.allow ? "ALLOW" : "DENY"}
                      {event.decision?.policy
                        ? ` (${event.decision.policy})`
                        : ""}
                      {event.decision?.reason
                        ? ` — ${event.decision.reason}`
                        : ""}{" "}
                      · outcome {event.outcome}
                      {typeof event.confidence === "number"
                        ? ` · confidence ${event.confidence.toFixed(2)}`
                        : ""}
                    </div>
                    <div className="muted">
                      hash {(event.event_hash ?? "").slice(0, 12)}…
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </section>
        </>
      )}
    </main>
  );
}
