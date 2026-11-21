"use client";

// Agent identity dashboard (Pillar 1): which agent holds which
// credential, and how many of each agent's credentials are exposed.
// Everything shown is fingerprints + prefix4-masked values only —
// no raw key material ever reaches this page.

import { useEffect, useState } from "react";
import CounterBadge from "../components/CounterBadge";

interface AgentCredential {
  provider: string;
  credentialType: string;
  fingerprint: string;
  masked: string;
  source: string;
  envVar: string;
}

interface Agent {
  id: number;
  name: string;
  type: string;
  configPath: string;
  repo: string;
  owner: string;
  credentials: AgentCredential[];
  exposedCount: number;
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [audits, setAudits] = useState<{
    used: number;
    limit: number | null;
  } | null>(null);
  const [planName, setPlanName] = useState("Free");

  useEffect(() => {
    fetch("/api/agents")
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Could not load agents.");
        setAgents(data.agents ?? []);
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
    // Free-tier daily audit counter (2/day on Free) — best-effort;
    // the list still loads when the counters endpoint is down.
    fetch("/api/usage/counters")
      .then(async (res) => {
        if (!res.ok) return;
        const data = await res.json();
        setAudits(data.counters?.audits ?? null);
        if (typeof data.planName === "string") setPlanName(data.planName);
      })
      .catch(() => {});
  }, []);

  const totalCredentials = agents.reduce(
    (sum, a) => sum + a.credentials.length,
    0,
  );
  const totalExposed = agents.reduce((sum, a) => sum + a.exposedCount, 0);

  return (
    <main>
      <h1>Agent Identity</h1>
      <p className="muted">
        Which agent holds which credential — registered from the CLI with{" "}
        <code>aiscan agents inventory --json</code> and{" "}
        <code>aiscan agents map --json</code>. Fingerprints and masked
        values only; no raw keys are stored or shown.
      </p>
      {audits ? (
        <div style={{ marginBottom: "1rem" }}>
          <CounterBadge
            used={audits.used}
            limit={audits.limit}
            label="audits"
            planName={planName}
            suffix="Resets at midnight UTC"
          />
        </div>
      ) : null}
      {loading && <p className="progress-note">Loading agents…</p>}
      {error && <p className="error-banner">{error}</p>}
      {!loading && !error && (
        <>
          <p className="breakdown">
            <strong>
              {agents.length} agent(s) · {totalCredentials} credential(s) ·{" "}
              {totalExposed} exposed
            </strong>
          </p>
          {agents.length === 0 ? (
            <p className="muted">
              No agents registered yet. Run{" "}
              <code>aiscan agents inventory &lt;path&gt; --json</code> and
              POST the output to <code>/api/agents</code>.
            </p>
          ) : (
            <table className="savings-table">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Type</th>
                  <th>Credentials</th>
                  <th>Exposed</th>
                  <th>Owner</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => (
                  <tr key={agent.id}>
                    <td>
                      {agent.name}
                      <br />
                      <span className="muted">{agent.configPath}</span>
                      {agent.repo && (
                        <>
                          <br />
                          <span className="muted">{agent.repo}</span>
                        </>
                      )}
                    </td>
                    <td>{agent.type || "—"}</td>
                    <td>
                      {agent.credentials.length === 0
                        ? "—"
                        : agent.credentials.map((cred, i) => (
                            <span key={i}>
                              {cred.provider}
                              {cred.fingerprint
                                ? ` ${cred.masked} (fp ${cred.fingerprint})`
                                : cred.envVar
                                  ? ` $${cred.envVar}`
                                  : ""}
                              <br />
                            </span>
                          ))}
                    </td>
                    <td>{agent.exposedCount}</td>
                    <td>{agent.owner || "unknown"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </main>
  );
}
