"use client";

import { useMemo, useState } from "react";
import { DEMO_CODE, DEMO_EXPECTED_FINDINGS } from "@/lib/demo";
import { fetchRepoFiles, parseRepoUrl } from "@/lib/github";
import { buildMarkdownReport, remediationSteps } from "@/lib/remediation";
import { scanSources, type Finding, type ScanResult } from "@/lib/scan";
import {
  estimateSavings,
  formatUsd,
  INCIDENT_RESPONSE_PER_KEY_USD,
  SAVINGS_METHODOLOGY_NOTE,
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

function SavingsPanel({ findings }: { findings: Finding[] }) {
  const savings = useMemo(() => estimateSavings(findings), [findings]);
  const h = savings.headlineRangeUsd;
  const expected = savings.scenarios.expected;
  const byProvider = Object.entries(expected.byProviderUsd).sort(
    (a, b) => b[1] - a[1],
  );
  return (
    <section className="savings-panel" aria-label="Potential savings">
      <h2>Potential savings</h2>
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

function FindingCard({ finding }: { finding: Finding }) {
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

export default function Home() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [sourceLabel, setSourceLabel] = useState("pasted code");
  const [copied, setCopied] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [repoBusy, setRepoBusy] = useState(false);
  const [repoError, setRepoError] = useState<string | null>(null);
  const [repoProgress, setRepoProgress] = useState<string | null>(null);

  const findings = result?.findings ?? [];

  const bySeverity = useMemo(() => {
    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;
    return { high, medium };
  }, [findings]);

  function runScan(text: string, label: string) {
    if (!text.trim()) return;
    const r = scanSources([{ name: label, text }]);
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
        </div>
        <p className="tagline">
          Paste code, find leaked AI API keys, fix them.
        </p>
        <p className="privacy-note">
          <strong>Privacy:</strong> scanning runs entirely in your browser.
          Pasted code and scanned files never leave your machine — the only
          network call this app makes is the optional public GitHub repo scan
          below.
        </p>
      </header>

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
              <SavingsPanel findings={findings} />
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
              {findings.map((f) => (
                <FindingCard key={f.id} finding={f} />
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
        (15 detectors, 13 providers). No accounts, no server, no data leaves
        your browser except the optional public GitHub repo fetch.
      </footer>
    </div>
  );
}
