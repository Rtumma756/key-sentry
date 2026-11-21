// Full-text scan pipeline: detect → dedupe → classify → sort by severity.
// Runs entirely in the browser. Findings carry masked keys only — the full
// credential value is kept in memory for dedup and never rendered.

import { maskKey, maskLine, scanLine, type MaskMode, type RawMatch } from "./detectors";

export interface Finding {
  id: string;
  provider: string;
  credType: string;
  severity: "high" | "medium";
  via: "regex" | "context" | "entropy";
  maskedKey: string;
  /** Full credential value — in-memory ONLY, like the CLI's Finding.value.
   * Never rendered, never serialized into reports. The ONLY place it
   * leaves the browser is an explicit "Store in vault" click, which
   * sends it to the server-side encrypted vault (see lib/vault-*). */
  value: string;
  source: string; // file name or "pasted code"
  lineNumber: number;
  contextLine: string; // line with the key masked
  consoleUrl: string;
}

export interface ScanMetrics {
  sourcesScanned: number;
  linesScanned: number;
  bytesScanned: number;
  candidatesFound: number;
  findingsAfterDedup: number;
  duplicatesRemoved: number;
  byProvider: Record<string, number>;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  scanTimeMs: number;
}

export interface ScanResult {
  findings: Finding[];
  metrics: ScanMetrics;
}

/** Scan one named text source (pasted code or a repo file). */
export function scanText(
  text: string,
  source: string,
  seen: Set<string>,
  maskMode: MaskMode = "prefix4",
): { findings: Finding[]; lines: number; candidates: number; duplicates: number } {
  const lines = text.split("\n");
  const findings: Finding[] = [];
  let candidates = 0;
  let duplicates = 0;

  lines.forEach((line, idx) => {
    const matches: RawMatch[] = scanLine(line);
    candidates += matches.length;
    for (const m of matches) {
      if (seen.has(m.value)) {
        duplicates++;
        continue;
      }
      seen.add(m.value);
      findings.push({
        id: `${source}:${idx + 1}:${m.start}`,
        provider: m.provider,
        credType: m.credType,
        severity: m.severity,
        via: m.via,
        maskedKey: maskKey(m.value, maskMode),
        value: m.value,
        source,
        lineNumber: idx + 1,
        contextLine: maskLine(line, maskMode).trim(),
        consoleUrl: m.consoleUrl,
      });
    }
  });

  return { findings, lines: lines.length, candidates, duplicates };
}

const SEVERITY_ORDER: Record<string, number> = { high: 0, medium: 1 };

/** Scan multiple named sources and build the full result with metrics. */
export function scanSources(
  sources: Array<{ name: string; text: string }>,
  maskMode: MaskMode = "prefix4",
): ScanResult {
  const started = performance.now();
  const seen = new Set<string>();
  const all: Finding[] = [];
  let lines = 0;
  let bytes = 0;
  let candidates = 0;
  let duplicates = 0;

  for (const s of sources) {
    bytes += new TextEncoder().encode(s.text).length;
    const r = scanText(s.text, s.name, seen, maskMode);
    all.push(...r.findings);
    lines += r.lines;
    candidates += r.candidates;
    duplicates += r.duplicates;
  }

  all.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.provider.localeCompare(b.provider) ||
      a.lineNumber - b.lineNumber,
  );

  const byProvider: Record<string, number> = {};
  const byType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const f of all) {
    byProvider[f.provider] = (byProvider[f.provider] ?? 0) + 1;
    byType[f.credType] = (byType[f.credType] ?? 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  return {
    findings: all,
    metrics: {
      sourcesScanned: sources.length,
      linesScanned: lines,
      bytesScanned: bytes,
      candidatesFound: candidates,
      findingsAfterDedup: all.length,
      duplicatesRemoved: duplicates,
      byProvider,
      byType,
      bySeverity,
      scanTimeMs: Math.round(performance.now() - started),
    },
  };
}
