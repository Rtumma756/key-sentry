"use client";

import { Fragment, useEffect, useMemo, useState } from "react";
import UpgradeBanner from "../components/UpgradeBanner";
import CounterBadge from "../components/CounterBadge";
import { DEMO_CODE, DEMO_EXPECTED_FINDINGS } from "@/lib/demo";
import { fetchRepoFiles, parseRepoUrl } from "@/lib/github";
import { buildMarkdownReport, remediationSteps } from "@/lib/remediation";
import { scanSources, type Finding, type ScanResult } from "@/lib/scan";
import type { MaskMode } from "@/lib/detectors";
import {
  estimateSavings,
  formatUsd,
  INCIDENT_RESPONSE_PER_KEY_USD,
  ownerVerifiedLiveNote,
  SAVINGS_METHODOLOGY_NOTE,
  vaultEntriesToVerifiedFindings,
  VERIFIED_NOT_AVAILABLE_NOTE,
} from "@/lib/savings";

const FEEDBACK_URL = "https://github.com/Rtumma756/key-sentry/issues";

const DETECTOR_SUMMARY = [
  "OpenAI (project, service account, legacy)",
  "Anthropic",
  "Google Gemini",
  "Groq",
  "OpenRouter",
  "DeepSeek",
  "xAI",
  "Perplexity",
  "Hugging Face",
  "Replicate",
  "Together AI",
  "Mistral",
  "Cohere",
];

function ProviderBreakdown({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;
  return (
    <p className="breakdown">
      <strong>By provider: </strong>
      {entries.map(([k, v]) => `${k} (${v})`).join(" · ")}
    </p>
  );
}

function SavingsPanel({
  findings,
  vaultSignal,
}: {
  findings: Finding[];
  vaultSignal: number;
}) {
  // Owner-verified side, wired to the live vault: fetch its masked
  // entries and count active, non-demo ones as verified. Only the
  // provider is used by the model — no key material ever enters this
  // path. Refreshes on page load and whenever a store/rotate/delete
  // changes the vault (vaultSignal). If the vault is unreachable the
  // verified side stays $0 with the not-available note.
  const [verifiedFindings, setVerifiedFindings] = useState<Finding[]>([]);
  const [vaultAvailable, setVaultAvailable] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/vault");
        if (cancelled) return;
        if (!res.ok) {
          setVaultAvailable(false);
          setVerifiedFindings([]);
          return;
        }
        const data = await res.json();
        setVaultAvailable(true);
        setVerifiedFindings(
          vaultEntriesToVerifiedFindings(data.entries ?? []),
        );
      } catch {
        if (cancelled) return;
        setVaultAvailable(false);
        setVerifiedFindings([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [vaultSignal]);

  const savings = useMemo(
    () => estimateSavings(findings, verifiedFindings),
    [findings, verifiedFindings],
  );
  const h = savings.headlineRangeUsd;
  const vh = savings.ownerVerified.headlineRangeUsd;
  const expected = savings.scenarios.expected;
  const byProvider = Object.entries(expected.byProviderUsd).sort(
    (a, b) => b[1] - a[1],
  );
  return (
    <section className="savings-panel" aria-label="Potential savings">
      <h2>Potential savings</h2>
      <p className="savings-sub">
        <strong>Potential (candidate) savings.</strong> These keys look
        real (documented format, real code/config context) but were never
        tested against a provider, so liveness and paid billing are
        unconfirmed — treat these figures as an upper bound.
      </p>
      <p className="savings-range">
        <strong>
          {formatUsd(h.conservative)} conservative –{" "}
          {formatUsd(h.expected)} expected – {formatUsd(h.worstCase)}{" "}
          worst-case
        </strong>
      </p>
      <p className="savings-sub">
        Estimated usage-bill savings from finding these{" "}
        {savings.totalKeys} key(s) before they could be abused. Expected
        case: 25% of keys abused at 25M tokens/day for 30 days undetected
        ({formatUsd(expected.perKeyUsd)} per key), plus{" "}
        {formatUsd(expected.incidentResponseSavingsUsd)} of incident-response
        cost at an assumed ${INCIDENT_RESPONSE_PER_KEY_USD.toLocaleString()}{" "}
        per abused key.
      </p>
      <table className="savings-table">
        <thead>
          <tr>
            <th>Scenario</th>
            <th>Keys abused</th>
            <th>Throughput</th>
            <th>Window</th>
            <th>Usage-bill savings</th>
          </tr>
        </thead>
        <tbody>
          {(
            [
              ["Conservative", savings.scenarios.conservative],
              ["Expected", savings.scenarios.expected],
              ["Worst-case", savings.scenarios.worstCase],
            ] as const
          ).map(([label, s]) => (
            <tr key={label}>
              <td>{label}</td>
              <td>{Math.round(s.pAbuse * 100)}%</td>
              <td>{s.throughputTokensPerDay / 1_000_000}M tok/day</td>
              <td>{s.windowDays} days</td>
              <td>{formatUsd(s.usageBillSavingsUsd)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="breakdown">
        <strong>Expected case, by provider: </strong>
        {byProvider
          .map(([p, v]) => `${p} (${formatUsd(v)})`)
          .join(" · ")}
      </p>
      <p className="savings-sub">
        <strong>Owner-verified savings.</strong>{" "}
        <strong>
          {formatUsd(vh.conservative)} conservative –{" "}
          {formatUsd(vh.expected)} expected – {formatUsd(vh.worstCase)}{" "}
          worst-case
        </strong>{" "}
        ({savings.verifiedKeys} key(s) verified)
      </p>
      {vaultAvailable !== null && (
        <p className="muted">
          {vaultAvailable
            ? ownerVerifiedLiveNote(savings.verifiedKeys)
            : VERIFIED_NOT_AVAILABLE_NOTE}
        </p>
      )}
      <p className="muted">{SAVINGS_METHODOLOGY_NOTE}</p>
      <p className="muted">
        Assumes paid billing on the keys; free-tier keys would cost far less.
        Blended rates from public list prices (Nov 2026); providers without
        a researched price use a generic rate. Full model and sources: the
        CLI scanner&apos;s results/DISCOVERY_INTELLIGENCE.md.
      </p>
    </section>
  );
}

interface VaultEntry {
  id: string;
  provider: string;
  masked: string;
  fingerprint: string;
  source: string;
  file: string;
  line: number;
  severity: string;
  status: "active" | "rotated" | "expired";
  storedAt: string;
  rotatedAt: string | null;
}

interface VaultAuditEntry {
  id: number;
  entryId: string | null;
  action: string;
  actor: string;
  detail: string;
  createdAt: string;
}

interface VaultSetup {
  configured: boolean;
  db: boolean;
  encryptionKey: boolean;
  adminPass: boolean;
  reason: string | null;
}

function VaultSection({
  refreshSignal,
  onVaultChange,
}: {
  refreshSignal: number;
  onVaultChange?: () => void;
}) {
  const [entries, setEntries] = useState<VaultEntry[] | null>(null);
  const [audit, setAudit] = useState<VaultAuditEntry[]>([]);
  const [setup, setSetup] = useState<VaultSetup | null>(null);
  const [loading, setLoading] = useState(true);
  const [adminPass, setAdminPass] = useState("");
  const [revealed, setRevealed] = useState<{ id: string; value: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadVault() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/vault");
      const data = await res.json();
      if (!res.ok) {
        setSetup(data.setup ?? null);
        setEntries(null);
        setError(data.error ?? "Vault unavailable.");
      } else {
        setSetup(null);
        setEntries(data.entries ?? []);
      }
      const auditRes = await fetch("/api/vault/audit");
      if (auditRes.ok) {
        const auditData = await auditRes.json();
        setAudit(auditData.entries ?? []);
      }
    } catch {
      setError("Could not reach the vault API.");
      setEntries(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadVault();
  }, [refreshSignal]);

  async function handleReveal(entry: VaultEntry) {
    if (!adminPass) {
      setError("Enter the admin passphrase to reveal a key.");
      return;
    }
    setBusy(`reveal:${entry.id}`);
    setError(null);
    try {
      const res = await fetch("/api/vault/reveal", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: entry.id, adminPass }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Reveal failed.");
        setRevealed(null);
      } else {
        setRevealed({ id: entry.id, value: data.value });
        loadVault();
      }
    } catch {
      setError("Could not reach the vault API.");
    } finally {
      setBusy(null);
    }
  }

  async function handleRotate(entry: VaultEntry) {
    if (!adminPass) {
      setError("Enter the admin passphrase to mark a key rotated.");
      return;
    }
    setBusy(`rotate:${entry.id}`);
    setError(null);
    try {
      const res = await fetch("/api/vault/rotate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: entry.id, adminPass, status: "rotated" }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Rotate failed.");
      } else {
        setRevealed(null);
        loadVault();
        onVaultChange?.();
      }
    } catch {
      setError("Could not reach the vault API.");
    } finally {
      setBusy(null);
    }
  }

  async function handleDelete(entry: VaultEntry) {
    if (!adminPass) {
      setError("Enter the admin passphrase to remove a key.");
      return;
    }
    if (
      !window.confirm(
        `Permanently remove the ${entry.provider} key ${entry.masked} from the vault? ` +
          "This deletes the encrypted key and cannot be undone.",
      )
    ) {
      return;
    }
    setBusy(`delete:${entry.id}`);
    setError(null);
    try {
      const res = await fetch("/api/vault/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: entry.id, adminPass }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Remove failed.");
      } else {
        if (revealed?.id === entry.id) setRevealed(null);
        loadVault();
        onVaultChange?.();
      }
    } catch {
      setError("Could not reach the vault API.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="vault-panel" aria-label="Encrypted vault">
      <h2>Encrypted vault (admin-only)</h2>
      <p className="section-sub">
        The vault holds a finding&apos;s <strong>unmasked</strong> key,
        encrypted at rest (AES-256-GCM, Vercel Postgres). Everything else —
        this page, reports, the audit log — shows masked keys only. Only an
        admin holding the passphrase can reveal a key, and every reveal is
        audit-logged.
      </p>
      <p className="muted">
        Scope: vault only keys from scans you ran yourself (pasted code, or
        your own repo) — so you can rotate them. Never vault keys found in
        other people&apos;s public code. Demo TESTFAKE keys are fine to
        vault for a trial run; they never count toward owner-verified
        savings, and can be removed with the Remove button (admin only).
      </p>

      {loading ? (
        <p className="progress-note">Loading vault…</p>
      ) : setup ? (
        <div className="vault-setup">
          <p>
            <strong>Vault is not configured yet.</strong>
          </p>
          <p>{setup.reason}</p>
          <ul>
            <li>
              Postgres database: {setup.db ? "connected ✓" : "missing"}
            </li>
            <li>
              VAULT_ENCRYPTION_KEY:{" "}
              {setup.encryptionKey ? "set ✓" : "missing"}
            </li>
            <li>
              VAULT_ADMIN_PASS: {setup.adminPass ? "set ✓" : "missing"}
            </li>
          </ul>
          <p className="muted">
            Setup: in Vercel, Storage → Create → Postgres (free tier), then
            set VAULT_ENCRYPTION_KEY (`openssl rand -base64 32`) and
            VAULT_ADMIN_PASS in Settings → Environment Variables, and
            redeploy. Tables are created automatically on first use.
          </p>
        </div>
      ) : (
        <>
          <div className="vault-admin-row">
            <input
              type="password"
              value={adminPass}
              onChange={(e) => setAdminPass(e.target.value)}
              placeholder="Admin passphrase (to reveal, rotate, or remove)"
              aria-label="Admin passphrase"
              spellCheck={false}
              autoComplete="off"
            />
            <button
              type="button"
              className="btn-secondary"
              onClick={loadVault}
            >
              Refresh
            </button>
          </div>
          {error && <p className="error-banner">{error}</p>}
          {revealed && (
            <div className="revealed-key">
              <p>
                <strong>Revealed key (shown once — copy it, then hide it):</strong>
              </p>
              <code>{revealed.value}</code>
              <div className="action-row">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setRevealed(null)}
                >
                  Hide
                </button>
                <span className="char-count">
                  Reveal audit-logged. Rotate this key now if it was ever
                  exposed.
                </span>
              </div>
            </div>
          )}
          {entries && entries.length === 0 ? (
            <p className="muted">
              Vault is empty. Use “Store in vault” on a finding above — that
              click is the explicit consent to send that one key to the
              server vault.
            </p>
          ) : (
            <table className="savings-table vault-table">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Masked key</th>
                  <th>Source</th>
                  <th>Stored</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {(entries ?? []).map((e) => (
                  <tr key={e.id}>
                    <td>{e.provider}</td>
                    <td>
                      <code>{e.masked}</code>
                    </td>
                    <td>
                      {e.source}
                      {e.file ? ` · ${e.file}` : ""}
                      {e.line ? `:${e.line}` : ""}
                    </td>
                    <td>{e.storedAt.slice(0, 19).replace("T", " ")}</td>
                    <td>{e.status}</td>
                    <td>
                      <button
                        type="button"
                        className="btn-small"
                        disabled={busy !== null}
                        onClick={() => handleReveal(e)}
                      >
                        {busy === `reveal:${e.id}` ? "…" : "Reveal"}
                      </button>{" "}
                      {e.status === "active" && (
                        <button
                          type="button"
                          className="btn-small"
                          disabled={busy !== null}
                          onClick={() => handleRotate(e)}
                        >
                          {busy === `rotate:${e.id}` ? "…" : "Mark rotated"}
                        </button>
                      )}{" "}
                      <button
                        type="button"
                        className="btn-small"
                        disabled={busy !== null}
                        onClick={() => handleDelete(e)}
                        title="Permanently remove this entry from the vault (admin only, audit-logged)."
                      >
                        {busy === `delete:${e.id}` ? "…" : "Remove"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <details className="remediation">
            <summary>
              Audit trail ({audit.length} entr{audit.length === 1 ? "y" : "ies"}
              )
            </summary>
            {audit.length === 0 ? (
              <p className="muted">No audit entries yet.</p>
            ) : (
              <ol>
                {audit.map((a) => (
                  <li key={a.id}>
                    {a.createdAt.slice(0, 19).replace("T", " ")} —{" "}
                    <strong>{a.action}</strong> · {a.entryId ?? "—"} ·{" "}
                    {a.actor} · {a.detail}
                  </li>
                ))}
              </ol>
            )}
            <p className="muted">
              The audit log records who did what and when. Full keys are
              never written to it.
            </p>
          </details>
        </>
      )}
    </section>
  );
}

function FindingCard({
  finding,
  onStore,
  stored,
  storeBusy,
}: {
  finding: Finding;
  onStore?: (f: Finding) => void;
  stored?: boolean;
  storeBusy?: boolean;
}) {
  const steps = remediationSteps(finding);
  return (
    <article className={`finding-card severity-${finding.severity}`}>
      <div className="finding-head">
        <h3>
          {finding.provider} — {finding.credType}
        </h3>
        <span className={`severity-badge ${finding.severity}`}>
          {finding.severity}
        </span>
      </div>
      <p className="finding-meta">
        Key: <code>{finding.maskedKey}</code> · {finding.source}, line{" "}
        {finding.lineNumber} · detected via {finding.via}
      </p>
      <div className="context-line">{finding.contextLine}</div>
      <div className="finding-actions">
        {finding.consoleUrl && (
          <a
            className="btn-small"
            href={finding.consoleUrl}
            target="_blank"
            rel="noreferrer"
          >
            Revoke at {finding.provider}
          </a>
        )}
        {onStore && (
          <button
            type="button"
            className="btn-small"
            disabled={stored || storeBusy}
            onClick={() => onStore(finding)}
            title="Sends this one key to the server-side encrypted vault (admin-only reveal). Explicit click only — nothing is stored automatically."
          >
            {stored ? "Stored in vault ✓" : storeBusy ? "Storing…" : "Store in vault"}
          </button>
        )}
      </div>
      <details className="remediation">
        <summary>Remediation checklist ({steps.length} steps)</summary>
        <ol>
          {steps.map((s) => (
            <li key={s.title}>
              <strong>{s.title}</strong>
              <p>{s.detail}</p>
              {s.link && (
                <a href={s.link} target="_blank" rel="noreferrer">
                  {s.linkLabel ?? s.link}
                </a>
              )}
            </li>
          ))}
        </ol>
      </details>
    </article>
  );
}

interface Fingerprint {
  id: number;
  fingerprint: string;
  provider: string;
  label: string;
  status: "active" | "removed";
  createdAt: string;
}

interface MatchHistoryEntry {
  id: number;
  matchId: number;
  oldStatus: string;
  newStatus: string;
  changedBy: string;
  note: string;
  changedAt: string;
}

interface FingerprintMatch {
  id: number;
  fingerprint: string;
  provider: string;
  repo: string;
  file: string;
  line: number;
  firstSeen: string;
  lastSeen: string;
  status: "new" | "acknowledged" | "resolved";
  // Assignee + history arrived with the team-basics schema update; an
  // older API response may omit them, so both stay optional here.
  assignee?: string;
  history?: MatchHistoryEntry[];
}

function FingerprintSection() {
  const [fingerprints, setFingerprints] = useState<Fingerprint[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [adminPass, setAdminPass] = useState("");
  const [newFingerprint, setNewFingerprint] = useState("");
  const [newProvider, setNewProvider] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function loadFingerprints() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/fingerprints");
      const data = await res.json();
      if (!res.ok) {
        setFingerprints(null);
        setError(data.error ?? "Fingerprint monitoring unavailable.");
      } else {
        setFingerprints(data.fingerprints ?? []);
      }
    } catch {
      setError("Could not reach the fingerprints API.");
      setFingerprints(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFingerprints();
  }, []);

  async function handleAdd() {
    const fp = newFingerprint.trim().toLowerCase();
    if (!/^[0-9a-f]{16}$/.test(fp)) {
      setError(
        "Fingerprint must be 16 lowercase hex chars (SHA-256 of the key, first 16). " +
          "Compute one with the CLI: echo -n '<key>' | python3 fingerprint_watch.py hash — never paste a raw key here.",
      );
      return;
    }
    if (!newProvider.trim()) {
      setError("Enter a provider for the fingerprint.");
      return;
    }
    if (!adminPass) {
      setError("Enter the admin passphrase to add a fingerprint.");
      return;
    }
    setBusy("add");
    setError(null);
    try {
      const res = await fetch("/api/fingerprints", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          fingerprint: fp,
          provider: newProvider.trim(),
          label: newLabel.trim(),
          adminPass,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Add failed.");
      } else {
        setNewFingerprint("");
        setNewProvider("");
        setNewLabel("");
        loadFingerprints();
      }
    } catch {
      setError("Could not reach the fingerprints API.");
    } finally {
      setBusy(null);
    }
  }

  async function handleRemove(fp: Fingerprint) {
    if (!adminPass) {
      setError("Enter the admin passphrase to remove a fingerprint.");
      return;
    }
    if (
      !window.confirm(
        `Stop watching fingerprint ${fp.fingerprint} (${fp.provider})? ` +
          "Past matches stay on record; new sightings will no longer be watched.",
      )
    ) {
      return;
    }
    setBusy(`remove:${fp.id}`);
    setError(null);
    try {
      const res = await fetch("/api/fingerprints", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fingerprint: fp.fingerprint, adminPass }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Remove failed.");
      } else {
        loadFingerprints();
      }
    } catch {
      setError("Could not reach the fingerprints API.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="vault-panel" aria-label="Fingerprint monitoring">
      <h2>Fingerprint monitoring</h2>
      <p className="section-sub">
        Watch SHA-256 fingerprints (first 16 hex chars) of keys you own —
        e.g. keys you rotated after a leak. When a scan finds one again in
        public code, it lands in the matches list below and (if configured)
        fires a webhook alert. Only hashes are stored here, never a raw key.
      </p>
      {loading ? (
        <p className="progress-note">Loading fingerprints…</p>
      ) : (
        <>
          <div className="vault-admin-row">
            <input
              type="text"
              value={newFingerprint}
              onChange={(e) => setNewFingerprint(e.target.value)}
              placeholder="Fingerprint — 16 hex chars, e.g. c826852ab88147ba"
              aria-label="Fingerprint (16 hex chars)"
              spellCheck={false}
              autoComplete="off"
            />
            <input
              type="text"
              value={newProvider}
              onChange={(e) => setNewProvider(e.target.value)}
              placeholder="Provider, e.g. Groq"
              aria-label="Provider"
              spellCheck={false}
              autoComplete="off"
            />
            <input
              type="text"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="Label (optional), e.g. prod key rotated Nov 2026"
              aria-label="Label (optional)"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <div className="vault-admin-row">
            <input
              type="password"
              value={adminPass}
              onChange={(e) => setAdminPass(e.target.value)}
              placeholder="Admin passphrase (to add or remove)"
              aria-label="Admin passphrase"
              spellCheck={false}
              autoComplete="off"
            />
            <button
              type="button"
              className="btn-primary"
              onClick={handleAdd}
              disabled={busy !== null}
            >
              {busy === "add" ? "…" : "Watch fingerprint"}
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={loadFingerprints}
            >
              Refresh
            </button>
          </div>
          {error && <p className="error-banner">{error}</p>}
          {fingerprints && fingerprints.length === 0 ? (
            <p className="muted">
              No fingerprints watched yet. Compute one with the CLI (
              <code>fingerprint_watch.py hash</code>) and add it above.
            </p>
          ) : (
            <table className="savings-table vault-table">
              <thead>
                <tr>
                  <th>Fingerprint</th>
                  <th>Provider</th>
                  <th>Label</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {(fingerprints ?? []).map((f) => (
                  <tr key={f.id}>
                    <td>
                      <code>{f.fingerprint}</code>
                    </td>
                    <td>{f.provider}</td>
                    <td>{f.label}</td>
                    <td>{f.createdAt.slice(0, 19).replace("T", " ")}</td>
                    <td>
                      <button
                        type="button"
                        className="btn-small"
                        disabled={busy !== null}
                        onClick={() => handleRemove(f)}
                      >
                        {busy === `remove:${f.id}` ? "…" : "Remove"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="muted">
            Alerts: a new match posts to the Slack-compatible webhook in
            KEYSENTRY_ALERT_WEBHOOK when set in Vercel. Email alerts are not
            available yet (they need SMTP credentials).
          </p>
        </>
      )}
    </section>
  );
}

function FindingsSection() {
  const [matches, setMatches] = useState<FingerprintMatch[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [adminPass, setAdminPass] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [providerFilter, setProviderFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [assigneeDrafts, setAssigneeDrafts] = useState<
    Record<number, string>
  >({});
  const [histories, setHistories] = useState<
    Record<number, MatchHistoryEntry[]>
  >({});
  const [historyOpen, setHistoryOpen] = useState<Record<number, boolean>>(
    {},
  );
  const [historyBusy, setHistoryBusy] = useState<number | null>(null);

  async function loadMatches() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/matches");
      const data = await res.json();
      if (!res.ok) {
        setMatches(null);
        setError(data.error ?? "Matches unavailable.");
      } else {
        setMatches(data.matches ?? []);
      }
    } catch {
      setError("Could not reach the matches API.");
      setMatches(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadMatches();
  }, []);

  const providers = useMemo(() => {
    const set = new Set<string>();
    for (const m of matches ?? []) {
      if (m.provider) set.add(m.provider);
    }
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [matches]);

  const summary = useMemo(() => {
    const all = matches ?? [];
    const open = all.filter(
      (m) => m.status === "new" || m.status === "acknowledged",
    ).length;
    const resolved = all.filter((m) => m.status === "resolved").length;
    return {
      open,
      newCount: all.filter((m) => m.status === "new").length,
      resolved,
      total: all.length,
    };
  }, [matches]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (matches ?? []).filter((m) => {
      if (statusFilter !== "all" && m.status !== statusFilter) return false;
      if (providerFilter !== "all" && m.provider !== providerFilter)
        return false;
      if (
        q &&
        !m.repo.toLowerCase().includes(q) &&
        !m.file.toLowerCase().includes(q) &&
        !m.fingerprint.toLowerCase().includes(q)
      )
        return false;
      return true;
    });
  }, [matches, statusFilter, providerFilter, query]);

  async function handleStatus(
    match: FingerprintMatch,
    status: "acknowledged" | "resolved",
  ) {
    if (!adminPass) {
      setError("Enter the admin passphrase to change a match status.");
      return;
    }
    setBusy(`${status}:${match.id}`);
    setError(null);
    try {
      const res = await fetch("/api/matches", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: match.id, status, adminPass }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Status change failed.");
      } else {
        loadMatches();
      }
    } catch {
      setError("Could not reach the matches API.");
    } finally {
      setBusy(null);
    }
  }

  async function handleAssign(match: FingerprintMatch) {
    const assignee = (
      assigneeDrafts[match.id] ?? match.assignee ?? ""
    ).trim();
    if (!adminPass) {
      setError("Enter the admin passphrase to assign a match.");
      return;
    }
    setBusy(`assign:${match.id}`);
    setError(null);
    try {
      const res = await fetch("/api/matches/assign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: match.id, assignee, adminPass }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Assign failed.");
      } else {
        // The assign response carries the updated status history — keep
        // it so the history row below shows the assignment right away.
        if (Array.isArray(data.history)) {
          setHistories((prev) => ({ ...prev, [match.id]: data.history }));
          setHistoryOpen((prev) => ({ ...prev, [match.id]: true }));
        }
        setAssigneeDrafts((prev) => {
          const next = { ...prev };
          delete next[match.id];
          return next;
        });
        loadMatches();
      }
    } catch {
      setError("Could not reach the matches API.");
    } finally {
      setBusy(null);
    }
  }

  async function toggleHistory(match: FingerprintMatch) {
    if (historyOpen[match.id]) {
      setHistoryOpen((prev) => ({ ...prev, [match.id]: false }));
      return;
    }
    setHistoryOpen((prev) => ({ ...prev, [match.id]: true }));
    // History may already ride along on the match object (assign
    // responses include it); fetch it only when we do not have it yet.
    if (histories[match.id] || match.history) return;
    setHistoryBusy(match.id);
    try {
      const res = await fetch(`/api/matches/history?id=${match.id}`);
      const data = await res.json();
      if (res.ok) {
        setHistories((prev) => ({
          ...prev,
          [match.id]: data.history ?? [],
        }));
      }
    } catch {
      // History is a nice-to-have: a failed fetch just leaves the row
      // empty instead of breaking the findings list.
    } finally {
      setHistoryBusy(null);
    }
  }

  return (
    <section className="vault-panel" aria-label="Findings">
      <h2>Findings — watched keys seen again</h2>
      <p className="section-sub">
        Every time a scan finds a watched fingerprint in public code, a
        finding is recorded here. Acknowledge it once you have started the
        rotation; resolve it once the key is revoked and scrubbed. Assign
        it to a team member so someone owns the cleanup.
      </p>
      <div className="summary-bar" aria-label="Findings summary">
        <div className="summary-stat">
          <span className="stat-number">{summary.open}</span>
          <span className="stat-label">open</span>
        </div>
        <div className="summary-stat">
          <span className="stat-number">{summary.newCount}</span>
          <span className="stat-label">new</span>
        </div>
        <div className="summary-stat">
          <span className="stat-number">{summary.resolved}</span>
          <span className="stat-label">resolved</span>
        </div>
        <div className="summary-stat">
          <span className="stat-number">{summary.total}</span>
          <span className="stat-label">total findings</span>
        </div>
      </div>
      <div className="vault-admin-row">
        <label className="mask-toggle">
          Status:
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Match status filter"
          >
            <option value="all">All</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </label>
        <label className="mask-toggle">
          Provider:
          <select
            value={providerFilter}
            onChange={(e) => setProviderFilter(e.target.value)}
            aria-label="Provider filter"
          >
            <option value="all">All providers</option>
            {providers.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search repo, file, or fingerprint…"
          aria-label="Search findings by repo, file, or fingerprint"
          spellCheck={false}
          autoComplete="off"
        />
        <input
          type="password"
          value={adminPass}
          onChange={(e) => setAdminPass(e.target.value)}
          placeholder="Admin passphrase (to acknowledge / resolve / assign)"
          aria-label="Admin passphrase"
          spellCheck={false}
          autoComplete="off"
        />
        <button
          type="button"
          className="btn-secondary"
          onClick={loadMatches}
        >
          Refresh
        </button>
      </div>
      {error && <p className="error-banner">{error}</p>}
      {loading ? (
        <p className="progress-note">Loading findings…</p>
      ) : matches && matches.length === 0 ? (
        <p className="muted">
          No findings yet. Run the CLI watcher (
          <code>fingerprint_watch.py check</code>) after a scan to record
          sightings, or wait for the daily sweep to re-check open matches.
        </p>
      ) : visible.length === 0 ? (
        <p className="muted">
          No findings match these filters. Clear the search or pick another
          status / provider.
        </p>
      ) : (
        <table className="savings-table vault-table">
          <thead>
            <tr>
              <th>Fingerprint</th>
              <th>Provider</th>
              <th>Seen in</th>
              <th>First seen</th>
              <th>Last seen</th>
              <th>Status</th>
              <th>Assignee</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((m) => {
              const history = histories[m.id] ?? m.history ?? [];
              return (
                <Fragment key={m.id}>
                  <tr>
                    <td>
                      <code>{m.fingerprint}</code>
                    </td>
                    <td>{m.provider}</td>
                    <td>
                      {m.repo}
                      {m.file ? ` · ${m.file}` : ""}
                      {m.line ? `:${m.line}` : ""}
                    </td>
                    <td>{m.firstSeen.slice(0, 19).replace("T", " ")}</td>
                    <td>{m.lastSeen.slice(0, 19).replace("T", " ")}</td>
                    <td>{m.status}</td>
                    <td>{m.assignee || "—"}</td>
                    <td>
                      {m.status === "new" && (
                        <button
                          type="button"
                          className="btn-small"
                          disabled={busy !== null}
                          onClick={() => handleStatus(m, "acknowledged")}
                        >
                          {busy === `acknowledged:${m.id}`
                            ? "…"
                            : "Acknowledge"}
                        </button>
                      )}{" "}
                      {m.status !== "resolved" && (
                        <button
                          type="button"
                          className="btn-small"
                          disabled={busy !== null}
                          onClick={() => handleStatus(m, "resolved")}
                        >
                          {busy === `resolved:${m.id}` ? "…" : "Resolve"}
                        </button>
                      )}{" "}
                      <input
                        type="text"
                        value={assigneeDrafts[m.id] ?? m.assignee ?? ""}
                        onChange={(e) =>
                          setAssigneeDrafts((prev) => ({
                            ...prev,
                            [m.id]: e.target.value,
                          }))
                        }
                        placeholder="Assign to…"
                        aria-label={`Assignee for match ${m.id}`}
                        spellCheck={false}
                        autoComplete="off"
                        style={{ width: "7rem" }}
                      />{" "}
                      <button
                        type="button"
                        className="btn-small"
                        disabled={busy !== null}
                        onClick={() => handleAssign(m)}
                      >
                        {busy === `assign:${m.id}` ? "…" : "Assign"}
                      </button>{" "}
                      <button
                        type="button"
                        className="btn-small"
                        disabled={historyBusy === m.id}
                        onClick={() => toggleHistory(m)}
                      >
                        {historyBusy === m.id
                          ? "…"
                          : historyOpen[m.id]
                            ? "Hide history"
                            : "History"}
                      </button>
                    </td>
                  </tr>
                  {historyOpen[m.id] && (
                    <tr>
                      <td colSpan={8}>
                        {history.length === 0 ? (
                          <p className="muted">
                            No history recorded for this finding yet.
                          </p>
                        ) : (
                          <ol>
                            {history.map((h) => (
                              <li key={h.id}>
                                {h.changedAt
                                  .slice(0, 19)
                                  .replace("T", " ")}{" "}
                                —{" "}
                                {h.oldStatus === h.newStatus ? (
                                  <strong>{h.note || "updated"}</strong>
                                ) : (
                                  <>
                                    <strong>
                                      {h.oldStatus || "—"} → {h.newStatus}
                                    </strong>
                                    {h.note ? ` — ${h.note}` : ""}
                                  </>
                                )}{" "}
                                · {h.changedBy}
                              </li>
                            ))}
                          </ol>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
      <p className="muted">
        The daily sweep re-checks open findings against the live file and
        refreshes “last seen” while the key is still there; a finding is
        never auto-resolved — resolve it here once the key is revoked.
      </p>
    </section>
  );
}

export default function Home() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [sourceLabel, setSourceLabel] = useState("pasted code");
  const [copied, setCopied] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [repoBusy, setRepoBusy] = useState(false);
  const [repoError, setRepoError] = useState<string | null>(null);
  const [repoProgress, setRepoProgress] = useState<string | null>(null);
  const [storedIds, setStoredIds] = useState<string[]>([]);
  const [storeBusyId, setStoreBusyId] = useState<string | null>(null);
  const [storeNote, setStoreNote] = useState<string | null>(null);
  const [vaultSignal, setVaultSignal] = useState(0);
  // Masking mode for displayed keys. Default "prefix4" shows the first 4
  // chars and hides the rest. "ends" hides the first 5 and last 3 and shows
  // the middle — that exposes most of a key, so use it only when scanning
  // your own code, never for keys that belong to someone else.
  const [maskMode, setMaskMode] = useState<MaskMode>("prefix4");
  // Workspace plan for the upgrade banner (Free -> show it). Fetched
  // client-side; if the fetch fails (billing unconfigured, offline),
  // the banner stays hidden — the dashboard must never break because
  // billing is unconfigured.
  const [workspacePlan, setWorkspacePlan] = useState<string | null>(null);
  // Today's free-tier daily counters for the banner row (vibe scans,
  // audits, dashboard saves). Same best-effort fetch as the plan:
  // when it fails the badges stay hidden, never an error.
  const [dayCounters, setDayCounters] = useState<{
    planName: string;
    vibe_scans: { used: number; limit: number | null };
    audits: { used: number; limit: number | null };
    dashboard_saves: { used: number; limit: number | null };
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/billing/plan");
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled && typeof data.plan === "string") {
          setWorkspacePlan(data.plan);
        }
      } catch {
        // Billing unconfigured or unreachable: no banner, no error.
      }
      try {
        const res = await fetch("/api/usage/counters");
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled && data.counters) {
          setDayCounters({
            planName:
              typeof data.planName === "string" ? data.planName : "Free",
            vibe_scans: data.counters.vibe_scans,
            audits: data.counters.audits,
            dashboard_saves: data.counters.dashboard_saves,
          });
        }
      } catch {
        // Counters unavailable: no badges, no error.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const findings = result?.findings ?? [];

  const bySeverity = useMemo(() => {
    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;
    return { high, medium };
  }, [findings]);

  function runScan(text: string, label: string) {
    if (!text.trim()) return;
    const r = scanSources([{ name: label, text }], maskMode);
    setResult(r);
    setSourceLabel(label);
    setCopied(false);
  }

  function handleScan() {
    runScan(input, "pasted code");
  }

  function handleDemo() {
    setInput(DEMO_CODE);
    runScan(DEMO_CODE, "demo sample");
  }

  function handleClear() {
    setInput("");
    setResult(null);
    setCopied(false);
  }

  async function handleStoreFinding(finding: Finding) {
    // Explicit click only: this is the one place a full key leaves the
    // browser — to the server-side encrypted vault, never automatically.
    setStoreBusyId(finding.id);
    setStoreNote(null);
    try {
      const res = await fetch("/api/vault", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: finding.provider,
          value: finding.value,
          source: sourceLabel,
          file: finding.source,
          line: finding.lineNumber,
          severity: finding.severity,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStoreNote(
          data.error ??
            "Could not store in vault. See the vault section below.",
        );
      } else {
        setStoredIds((prev) => [...prev, finding.id]);
        setStoreNote(
          `Stored ${finding.provider} key ${finding.maskedKey} in the vault.`,
        );
        setVaultSignal((n) => n + 1);
      }
    } catch {
      setStoreNote("Could not reach the vault API.");
    } finally {
      setStoreBusyId(null);
    }
  }

  async function handleCopyReport() {
    if (!result) return;
    const md = buildMarkdownReport(
      result.findings,
      result.metrics,
      sourceLabel,
    );
    try {
      await navigator.clipboard.writeText(md);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Clipboard unavailable — fall back to selecting nothing.
      setCopied(false);
    }
  }

  async function handleRepoScan() {
    const parsed = parseRepoUrl(repoUrl);
    if (!parsed) {
      setRepoError(
        "Enter a public repository URL like https://github.com/owner/repo",
      );
      return;
    }
    setRepoError(null);
    setRepoBusy(true);
    setRepoProgress("Looking up repository…");
    try {
      const files = await fetchRepoFiles(parsed.owner, parsed.repo, (p) => {
        setRepoProgress(
          `${p.stage} (${p.filesFetched}/${p.filesTotal} files)`,
        );
      });
      if (files.length === 0) {
        setRepoError(
          "No scannable text files found in this repo (capped at 25 files, 200 KB each).",
        );
        setRepoBusy(false);
        setRepoProgress(null);
        return;
      }
      const r = scanSources(
        files.map((f) => ({ name: f.name, text: f.text })),
        maskMode,
      );
      setResult(r);
      setSourceLabel(`${parsed.owner}/${parsed.repo}`);
      setCopied(false);
      setRepoProgress(null);
    } catch (err) {
      setRepoError(
        err instanceof Error ? err.message : "Could not scan the repository.",
      );
      setRepoProgress(null);
    } finally {
      setRepoBusy(false);
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand-row">
          <h1>KeySentry</h1>
          <span className="client-badge">100% client-side</span>
          <a href="/pricing" style={{ marginLeft: "auto" }}>
            Pricing
          </a>
        </div>
        <p className="tagline">
          Paste code, find leaked AI API keys, fix them.
        </p>
        <p className="privacy-note">
          <strong>Privacy:</strong> scanning runs entirely in your browser.
          Pasted code and scanned files never leave your machine — the only
          network calls this app makes are the optional public GitHub repo
          scan below, a finding you explicitly choose to store in the
          encrypted vault (see below), and the fingerprint watch list /
          matches panels, which send only one-way hashes, never keys.
        </p>
      </header>

      {workspacePlan === "free" && (
        <UpgradeBanner plan="free" feature="fingerprint_monitoring" />
      )}

      {dayCounters && (
        <div
          style={{
            display: "flex",
            gap: "0.5rem",
            flexWrap: "wrap",
            margin: "0 0 1rem 0",
          }}
          aria-label="Today's free usage"
        >
          <CounterBadge
            used={dayCounters.vibe_scans.used}
            limit={dayCounters.vibe_scans.limit}
            label="scans"
            planName={dayCounters.planName}
            suffix="Resets at midnight UTC"
          />
          <CounterBadge
            used={dayCounters.audits.used}
            limit={dayCounters.audits.limit}
            label="audits"
            planName={dayCounters.planName}
            suffix="Resets at midnight UTC"
          />
          <CounterBadge
            used={dayCounters.dashboard_saves.used}
            limit={dayCounters.dashboard_saves.limit}
            label="dashboard saves"
            planName={dayCounters.planName}
            suffix="Resets at midnight UTC"
          />
        </div>
      )}

      <section aria-label="Paste code to scan">
        <h2>Scan pasted code</h2>
        <p className="section-sub">
          Paste source code, a .env file, a config file, or anything else.
          Detectors cover {DETECTOR_SUMMARY.length} AI providers.
        </p>
        <textarea
          className="paste-area"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={"# Paste code here — e.g. a .env file or a Python file with API keys…"}
          rows={12}
          aria-label="Code to scan"
          spellCheck={false}
        />
        <div className="action-row">
          <button
            type="button"
            className="btn-primary"
            onClick={handleScan}
            disabled={!input.trim()}
          >
            Scan for leaked keys
          </button>
          <button type="button" className="btn-secondary" onClick={handleDemo}>
            Try the demo
          </button>
          <label className="mask-toggle">
            Masking:
            <select
              value={maskMode}
              onChange={(e) => setMaskMode(e.target.value as MaskMode)}
              aria-label="Masking mode"
            >
              <option value="prefix4">First 4 shown</option>
              <option value="ends">Hide first 5 + last 3</option>
            </select>
          </label>
          <button
            type="button"
            className="btn-secondary"
            onClick={handleClear}
            disabled={!input && !result}
          >
            Clear
          </button>
          <span className="char-count">
            {input.length.toLocaleString()} characters
          </span>
        </div>
      </section>

      {result && (
        <>
          <div className="summary-bar" aria-label="Scan summary">
            <div
              className={`summary-stat ${findings.length > 0 ? "danger" : "ok"}`}
            >
              <span className="stat-number">{findings.length}</span>
              <span className="stat-label">findings</span>
            </div>
            <div className="summary-stat">
              <span className="stat-number">{bySeverity.high}</span>
              <span className="stat-label">high severity</span>
            </div>
            <div className="summary-stat">
              <span className="stat-number">{bySeverity.medium}</span>
              <span className="stat-label">medium severity</span>
            </div>
            <div className="summary-stat">
              <span className="stat-number">
                {Object.keys(result.metrics.byProvider).length}
              </span>
              <span className="stat-label">providers affected</span>
            </div>
            <div className="summary-stat">
              <span className="stat-number">
                {result.metrics.scanTimeMs} ms
              </span>
              <span className="stat-label">scan time</span>
            </div>
          </div>

          {findings.length === 0 ? (
            <div className="clean-banner">
              No leaked AI API keys found in {sourceLabel}. Note: this scan
              only checks the text you provided — it cannot prove a codebase
              is clean.
            </div>
          ) : (
            <>
              <SavingsPanel findings={findings} vaultSignal={vaultSignal} />
              <div className="action-row" style={{ marginBottom: 12 }}>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={handleCopyReport}
                >
                  {copied ? "Copied ✓" : "Copy remediation report (Markdown)"}
                </button>
                <span className="char-count">
                  Source: {sourceLabel} · keys are masked — full values are
                  never shown
                </span>
              </div>
              {storeNote && <p className="progress-note">{storeNote}</p>}
              {findings.map((f) => (
                <FindingCard
                  key={f.id}
                  finding={f}
                  onStore={handleStoreFinding}
                  stored={storedIds.includes(f.id)}
                  storeBusy={storeBusyId === f.id}
                />
              ))}
            </>
          )}

          <section aria-label="Metrics">
            <h2>Metrics</h2>
            <div className="metrics-grid">
              <div className="metric-cell">
                <span className="metric-value">
                  {result.metrics.linesScanned.toLocaleString()}
                </span>
                <span className="metric-label">lines scanned</span>
              </div>
              <div className="metric-cell">
                <span className="metric-value">
                  {result.metrics.candidatesFound}
                </span>
                <span className="metric-label">candidates found</span>
              </div>
              <div className="metric-cell">
                <span className="metric-value">
                  {result.metrics.findingsAfterDedup}
                </span>
                <span className="metric-label">findings after dedup</span>
              </div>
              <div className="metric-cell">
                <span className="metric-value">
                  {result.metrics.duplicatesRemoved}
                </span>
                <span className="metric-label">duplicates removed</span>
              </div>
              <div className="metric-cell">
                <span className="metric-value">
                  {(result.metrics.bytesScanned / 1024).toFixed(1)} KB
                </span>
                <span className="metric-label">bytes scanned</span>
              </div>
              <div className="metric-cell">
                <span className="metric-value">
                  {result.metrics.sourcesScanned}
                </span>
                <span className="metric-label">
                  {result.metrics.sourcesScanned === 1 ? "source" : "sources"}{" "}
                  scanned
                </span>
              </div>
            </div>
            <ProviderBreakdown data={result.metrics.byProvider} />
            <p className="breakdown">
              <strong>By credential type: </strong>
              {Object.entries(result.metrics.byType)
                .map(([k, v]) => `${k} (${v})`)
                .join(" · ")}
            </p>
            <div className="accuracy-box">
              <strong>How accurate is this?</strong>
              <p>
                On the CLI prototype&apos;s fixture suite, the same detectors
                found 16 of 16 planted keys with 0 false positives on the
                decoy set (UUIDs, hashes, placeholders). The demo above
                mirrors that suite — it should report{" "}
                {DEMO_EXPECTED_FINDINGS} findings and ignore every decoy
                line.
              </p>
              <p className="muted">
                Fixture scores measure the detector, not live data. Real
                codebases vary — treat any finding as “revoke first, ask
                questions later.”
              </p>
            </div>
          </section>
        </>
      )}

      <section aria-label="Scan a public GitHub repository">
        <h2>Scan a public GitHub repo</h2>
        <p className="section-sub">
          Fetches the repo&apos;s file tree from the public GitHub API and
          scans up to 25 small text files (max 200 KB each) in your browser.
          Unauthenticated GitHub API use is limited to 60 requests per hour.
        </p>
        <div className="repo-row">
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            aria-label="Public GitHub repository URL"
            spellCheck={false}
          />
          <button
            type="button"
            className="btn-primary"
            onClick={handleRepoScan}
            disabled={repoBusy || !repoUrl.trim()}
          >
            {repoBusy ? "Scanning…" : "Scan repo"}
          </button>
        </div>
        {repoProgress && <p className="progress-note">{repoProgress}</p>}
        {repoError && <p className="error-banner">{repoError}</p>}
      </section>

      <VaultSection
        refreshSignal={vaultSignal}
        onVaultChange={() => setVaultSignal((n) => n + 1)}
      />

      <FingerprintSection />
      <FindingsSection />

      <div className="info-grid">
        <section aria-label="How it works">
          <h2>How it works</h2>
          <ol>
            <li>
              <strong>Regex patterns</strong> match known key formats — every
              provider gives its keys a fixed shape, like{" "}
              <code>sk-proj-</code> (OpenAI) or <code>gsk_</code> (Groq).
            </li>
            <li>
              <strong>Entropy check</strong> catches keys with no fixed
              format by measuring how random a string looks, but only on
              lines that name a secret (api_key, token, secret…).
            </li>
            <li>
              <strong>Classification</strong> maps each match to a provider
              and credential type, and <strong>dedup</strong> collapses the
              same key found in several places into one finding.
            </li>
            <li>
              <strong>Remediation</strong> tells you exactly what to do:
              revoke, rotate, scrub git history, and stop it happening
              again.
            </li>
          </ol>
          <p className="muted">
            Detectors cover: {DETECTOR_SUMMARY.join(", ")}.
          </p>
        </section>

        <section aria-label="Give feedback">
          <h2>Give feedback</h2>
          <p className="section-sub">
            This is an early prototype — your feedback shapes what gets built
            next.
          </p>
          <ul>
            <li>
              <strong>Missed a key?</strong> Tell us the provider and the key
              format (mask the middle — never paste a real key).
            </li>
            <li>
              <strong>False positive?</strong> Share the file type and the
              surrounding line, with the value redacted.
            </li>
            <li>
              <strong>Providers to add?</strong> Which AI service&apos;s keys
              should be detected next?
            </li>
          </ul>
          <p>
            <a href={FEEDBACK_URL} target="_blank" rel="noreferrer">
              Open an issue on GitHub
            </a>
          </p>
        </section>
      </div>

      <footer className="app-footer">
        KeySentry prototype — detectors ported from the CLI scanner
        (15 detectors, 13 providers). Scanning is client-side; data leaves
        your browser only for the optional public GitHub repo fetch, or a
        finding you explicitly store in the encrypted vault.
      </footer>
    </div>
  );
}
