"use client";

// Pillar 2 — vibe-code security scanner: paste a public GitHub repo URL,
// get a security report. No account, no install.

import { useEffect, useState } from "react";
import CounterBadge from "../components/CounterBadge";

interface Counters {
  vibe_scans?: { used: number; limit: number | null };
}

export default function VibeScanPage() {
  const [repoUrl, setRepoUrl] = useState("");
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  const [upgradeNote, setUpgradeNote] = useState("");
  const [counters, setCounters] = useState<Counters | null>(null);
  const [planName, setPlanName] = useState("Free");
  const [result, setResult] = useState<{
    reportId: string;
    summary: { total: number; bySeverity: Record<string, number> };
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/usage/counters");
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) {
          setCounters(data.counters ?? null);
          if (typeof data.planName === "string") setPlanName(data.planName);
        }
      } catch {
        // Counters unavailable: the page still works, just no badge.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function runScan() {
    setError("");
    setUpgradeNote("");
    setResult(null);
    setStage("Fetching the repo file list from GitHub…");
    try {
      const res = await fetch("/api/vibe-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl }),
      });
      const data = (await res.json()) as {
        reportId?: string;
        summary?: { total: number; bySeverity: Record<string, number> };
        error?: string;
        usage?: { vibe_scans?: { used: number; limit: number | null } };
        upgrade?: { message?: string };
      };
      if (!res.ok) {
        setStage("");
        setError(data.error ?? "Scan failed.");
        if (data.upgrade?.message) setUpgradeNote(data.upgrade.message);
        return;
      }
      setStage("");
      if (data.usage?.vibe_scans) {
        setCounters((prev) => ({ ...prev, vibe_scans: data.usage!.vibe_scans }));
      }
      setResult({
        reportId: data.reportId ?? "",
        summary: data.summary ?? { total: 0, bySeverity: {} },
      });
    } catch {
      setStage("");
      setError("Could not reach the scan service. Try again.");
    }
  }

  return (
    <main style={{ maxWidth: 720, margin: "0 auto", padding: "2rem 1rem" }}>
      <h1>Vibe-code security scan</h1>
      <p>
        Paste a public GitHub repo link and get a plain-language security
        report: leaked API keys, open databases, missing sign-in checks,
        and more. No account, no install — and keys are never shown in
        full, only the first 4 characters.
      </p>
      {counters?.vibe_scans ? (
        <div style={{ marginBottom: "1rem" }}>
          <CounterBadge
            used={counters.vibe_scans.used}
            limit={counters.vibe_scans.limit}
            label="scans"
            planName={planName}
            suffix="Resets at midnight UTC"
          />
        </div>
      ) : null}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <input
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo or owner/repo"
          aria-label="Public GitHub repo URL"
          style={{
            flex: "1 1 320px",
            padding: "0.6rem 0.75rem",
            border: "1px solid var(--border)",
            borderRadius: "8px",
            background: "var(--surface)",
            color: "var(--text)",
          }}
        />
        <button
          onClick={runScan}
          disabled={!repoUrl.trim() || Boolean(stage)}
          style={{
            padding: "0.6rem 1rem",
            borderRadius: "8px",
            border: "none",
            background: "var(--accent)",
            color: "#fff",
            cursor: "pointer",
          }}
        >
          {stage ? "Scanning…" : "Scan repo"}
        </button>
      </div>
      {stage ? <p aria-live="polite">{stage}</p> : null}
      {error ? (
        <p style={{ color: "var(--danger-text)" }} role="alert">
          {error}
        </p>
      ) : null}
      {upgradeNote ? (
        <p style={{ color: "var(--muted)" }} role="note">
          {upgradeNote}
        </p>
      ) : null}
      {result ? (
        <section
          style={{
            marginTop: "1.5rem",
            padding: "1rem",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius)",
            background: "var(--surface)",
          }}
        >
          <h2>Scan complete — {result.summary.total} finding(s)</h2>
          <p>
            {Object.entries(result.summary.bySeverity)
              .map(([sev, n]) => `${sev}: ${n}`)
              .join(" · ") || "No issues found."}
          </p>
          <a href={`/vibe/${result.reportId}`}>View the full report →</a>
        </section>
      ) : null}
      <p style={{ color: "var(--muted)" }}>
        Only public repos. At most 100 files, 200 KB each, 5 MB total.
        Reports are shareable links and show masked values only.
      </p>
    </main>
  );
}
