"use client";

// Pillar 2 — public vibe-scan report view: severity summary, findings
// table with masked values + fingerprints, plain-language fixes, and a
// "share this report" copy button. Masked-only, always.

import { use, useEffect, useState } from "react";

interface VibeFinding {
  id: string;
  title: string;
  severity: string;
  file: string;
  line: number;
  evidence: string;
  fix: string;
  masked: string | null;
  fingerprint: string | null;
  provider: string | null;
  confidence: number | null;
}

interface VibeReport {
  id: string;
  repoUrl: string;
  summary: { total: number; bySeverity: Record<string, number> };
  findings: VibeFinding[];
  filesScanned: number;
  createdAt: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--danger-text)",
  high: "var(--danger-text)",
  medium: "var(--warn-text)",
  low: "var(--muted)",
};

export default function VibeReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [report, setReport] = useState<VibeReport | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/vibe-scan/${id}`);
        const data = (await res.json()) as VibeReport & { error?: string };
        if (cancelled) return;
        if (!res.ok) {
          setError(data.error ?? "Report not found.");
          return;
        }
        setReport(data);
      } catch {
        if (!cancelled) setError("Could not load the report.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  async function copyShareLink() {
    const url = window.location.href;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
    } catch {
      setCopied(false);
      window.prompt("Copy this report link:", url);
    }
  }

  if (error) {
    return (
      <main style={{ maxWidth: 720, margin: "0 auto", padding: "2rem 1rem" }}>
        <h1>Report not found</h1>
        <p role="alert">{error}</p>
        <a href="/vibe">Run a new scan →</a>
      </main>
    );
  }
  if (!report) {
    return (
      <main style={{ maxWidth: 720, margin: "0 auto", padding: "2rem 1rem" }}>
        <p>Loading report…</p>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 860, margin: "0 auto", padding: "2rem 1rem" }}>
      <h1>Vibe-code security report</h1>
      <p>
        <strong>{report.repoUrl}</strong>
        <br />
        Scanned {new Date(report.createdAt).toLocaleString()} ·{" "}
        {report.filesScanned} files · {report.summary.total} finding(s)
      </p>
      <p>
        {Object.entries(report.summary.bySeverity)
          .map(([sev, n]) => `${sev}: ${n}`)
          .join(" · ") || "No issues found. 🎉"}
      </p>
      <button
        onClick={copyShareLink}
        style={{
          padding: "0.5rem 0.9rem",
          borderRadius: "8px",
          border: "1px solid var(--border)",
          background: "var(--surface)",
          color: "var(--text)",
          cursor: "pointer",
          marginBottom: "1rem",
        }}
      >
        {copied ? "Link copied ✓" : "Share this report"}
      </button>
      {report.findings.length === 0 ? (
        <p>No issues found in the scanned files.</p>
      ) : (
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            background: "var(--surface)",
          }}
        >
          <thead>
            <tr>
              <th style={{ textAlign: "left", padding: "0.5rem" }}>Severity</th>
              <th style={{ textAlign: "left", padding: "0.5rem" }}>Issue</th>
              <th style={{ textAlign: "left", padding: "0.5rem" }}>Where</th>
              <th style={{ textAlign: "left", padding: "0.5rem" }}>What to do</th>
            </tr>
          </thead>
          <tbody>
            {report.findings.map((f, i) => (
              <tr key={`${f.id}-${f.file}-${f.line}-${i}`}>
                <td
                  style={{
                    padding: "0.5rem",
                    verticalAlign: "top",
                    color: SEVERITY_COLORS[f.severity] ?? "var(--text)",
                    fontWeight: 600,
                  }}
                >
                  {f.severity}
                </td>
                <td style={{ padding: "0.5rem", verticalAlign: "top" }}>
                  {f.title}
                  {f.masked ? (
                    <div>
                      <code>{f.masked}</code>
                      {f.fingerprint ? (
                        <span style={{ color: "var(--muted)" }}>
                          {" "}
                          · fingerprint {f.fingerprint}
                        </span>
                      ) : null}
                    </div>
                  ) : null}
                  {f.evidence ? (
                    <div style={{ color: "var(--muted)" }}>
                      <code>{f.evidence}</code>
                    </div>
                  ) : null}
                </td>
                <td style={{ padding: "0.5rem", verticalAlign: "top" }}>
                  <code>
                    {f.file}
                    {f.line ? `:${f.line}` : ""}
                  </code>
                </td>
                <td style={{ padding: "0.5rem", verticalAlign: "top" }}>
                  {f.fix}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p style={{ color: "var(--muted)" }}>
        Masked values show only the first 4 characters; full keys are never
        shown. Fingerprints are SHA-256 (first 16 hex chars).
      </p>
      <p>
        <a href="/vibe">Scan another repo →</a>
      </p>
    </main>
  );
}
