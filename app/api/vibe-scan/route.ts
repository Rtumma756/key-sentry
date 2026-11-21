// Vibe-code repo scan API (Pillar 2).
// POST /api/vibe-scan  { repoUrl } -> { reportId, summary, findings }
//   Public GitHub repos only (owner/repo or full URL). Fetches the repo
//   file tree via the unauthenticated GitHub REST API (60 req/hour),
//   fetches raw contents of candidate files only (cap: 100 files,
//   200KB each, 5MB total), scans with the generated detector patterns
//   + the TS vibe config checks, stores the masked-only report in Neon,
//   and returns it.
//   Free-tier caps (FREE-TIER-CAPS.md): 2 vibe scans/day and 2
//   dashboard saves/day on Free (Maker: unlimited), tracked per
//   hashed client IP for anonymous users. A cap hit answers 429 with
//   {used, limit, resetsAt} and an upgrade prompt — never a bare
//   error. The scan and the save are one operation on the web side,
//   so both counters move together.
//   GitHub rate-limit 403s get a clear error, never a crash.
//   No database? 503, like the other DB-backed routes.
// GET  /api/vibe-scan -> latest reports (Free: latest 2 per type;
//   older reports stay reachable by direct GET /api/vibe-scan/[id],
//   so share links never die when a report rolls off the free list).

import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { NextResponse } from "next/server";
import { sql } from "@vercel/postgres";
import { VaultNotConfigured } from "@/lib/vault-crypto";
import { checkRateLimit } from "@/lib/rate-limit";
import {
  capHitResponse,
  recordDailyCount,
  scopeKeyForRequest,
  USAGE_KEY_DASHBOARD_SAVES,
  USAGE_KEY_VIBE_SCANS,
} from "@/lib/usage";
import {
  enforceDailyCap,
  resolveWorkspacePlanId,
} from "@/lib/plan-enforcement";
import { getPlan, latestReportsForPlan } from "@/lib/plans";
import { ensureVibeReportTables } from "@/lib/vibe-reports-db";
import { saveVibeReport } from "@/lib/vibe-reports-db";
import {
  buildVibeAuditEvents,
  checkVibeFile,
  parseVibeRepoUrl,
  scanVibeFileSecrets,
  type DetectorPattern,
  type VibeFinding,
} from "@/lib/vibe-checks";

export const dynamic = "force-dynamic";

const MAX_FILES = 100;
const MAX_FILE_BYTES = 200 * 1024;
const MAX_TOTAL_BYTES = 5 * 1024 * 1024;
/** Most reports the list endpoint ever reads from the table (the
 * free-list slice happens in latestReportsForPlan, not in SQL). */
const MAX_LISTED_REPORTS = 50;

const TEXT_EXTENSIONS = new Set([
  ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".env", ".txt", ".md",
  ".yaml", ".yml", ".toml", ".cfg", ".ini", ".sh", ".java", ".go", ".rb",
  ".php", ".cs", ".cpp", ".h", ".c", ".rs", ".swift", ".kt", ".xml",
  ".html", ".css", ".sql", ".tf", ".conf", ".properties", ".lock",
  ".rules",
]);

const SKIP_BASENAMES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.lock",
  "Gemfile.lock",
  "poetry.lock",
]);

function notConfiguredResponse() {
  return NextResponse.json(
    {
      error:
        "Vibe scan is not configured: no Postgres database is " +
        "connected. In Vercel: Storage → Create → Postgres (free tier), " +
        "then redeploy.",
    },
    { status: 503 },
  );
}

function loadDetectorPatterns(): DetectorPattern[] {
  const data = JSON.parse(
    readFileSync(
      join(process.cwd(), "lib", "detector-patterns.json"),
      "utf-8",
    ),
  ) as { detectors: DetectorPattern[] };
  return data.detectors;
}

async function githubJson<T>(url: string): Promise<T> {
  const res = await fetch(url, {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (res.status === 403) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = res.headers.get("x-ratelimit-reset");
    const when = reset
      ? new Date(Number(reset) * 1000).toLocaleTimeString()
      : "soon";
    throw new Error(
      remaining === "0"
        ? `GitHub API rate limit reached (60 requests/hour without a token). It resets around ${when} — try again then.`
        : "GitHub refused the request (HTTP 403).",
    );
  }
  if (res.status === 404) {
    throw new Error("Repository not found, or it is private.");
  }
  if (!res.ok) {
    throw new Error(`GitHub API error: HTTP ${res.status}.`);
  }
  return (await res.json()) as T;
}

function isCandidateFile(path: string, size: number): boolean {
  if (size > MAX_FILE_BYTES) return false;
  const base = path.split("/").pop() ?? "";
  if (SKIP_BASENAMES.has(base)) return false;
  if (base === ".env" || base.startsWith(".env.")) return true;
  if (base.endsWith(".rules")) return true;
  const dot = base.lastIndexOf(".");
  if (dot === -1) return false;
  return TEXT_EXTENSIONS.has(base.slice(dot).toLowerCase());
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3,
};

export async function POST(req: Request) {
  const limited = checkRateLimit(req, "mutate");
  if (limited) return limited;
  try {
    const body = (await req.json().catch(() => null)) as {
      repoUrl?: unknown;
    } | null;
    const repoUrl = typeof body?.repoUrl === "string" ? body.repoUrl : "";
    const parsed = parseVibeRepoUrl(repoUrl);
    if (!parsed) {
      return NextResponse.json(
        {
          error:
            "Provide a public GitHub repo: a full URL such as " +
            "https://github.com/owner/repo, or owner/repo. Other hosts " +
            "and private repos are not supported.",
        },
        { status: 400 },
      );
    }
    const { owner, repo } = parsed;
    const canonicalUrl = `https://github.com/${owner}/${repo}`;

    // Free-tier daily caps, before any GitHub work: 2 vibe scans/day
    // and 2 dashboard saves/day on Free. Anonymous users are tracked
    // by hashed IP (never a raw IP). A cap hit is a 429 with the
    // upgrade prompt — never a bare error, never a dead end.
    const planId = await resolveWorkspacePlanId("default");
    const scope = scopeKeyForRequest(req);
    const scanKey = `${USAGE_KEY_VIBE_SCANS}:${scope}`;
    const saveKey = `${USAGE_KEY_DASHBOARD_SAVES}:${scope}`;
    const scanCap = await enforceDailyCap(
      "default", planId, "scans_per_day", scanKey);
    if (!scanCap.allowed) {
      return capHitResponse(
        scanCap.message, scanCap.limit ?? 0, scanCap.used, scanCap.upgrade);
    }
    const saveCap = await enforceDailyCap(
      "default", planId, "dashboard_saves_per_day", saveKey);
    if (!saveCap.allowed) {
      return capHitResponse(
        saveCap.message, saveCap.limit ?? 0, saveCap.used, saveCap.upgrade);
    }

    const patterns = loadDetectorPatterns();
    const meta = await githubJson<{ default_branch: string }>(
      `https://api.github.com/repos/${owner}/${repo}`,
    );
    const branch = meta.default_branch;
    const tree = await githubJson<{
      tree: Array<{ path: string; type: string; size?: number }>;
      truncated?: boolean;
    }>(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    );

    const candidates = tree.tree
      .filter((e) => e.type === "blob" && e.size !== undefined)
      .filter((e) => isCandidateFile(e.path, e.size as number))
      .slice(0, MAX_FILES);

    const files: Array<{ name: string; text: string }> = [];
    let totalBytes = 0;
    for (const entry of candidates) {
      if (totalBytes >= MAX_TOTAL_BYTES) break;
      try {
        const res = await fetch(
          `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${entry.path}`,
        );
        if (!res.ok) continue;
        const text = await res.text();
        const bytes = new TextEncoder().encode(text).length;
        if (totalBytes + bytes > MAX_TOTAL_BYTES) break;
        totalBytes += bytes;
        files.push({ name: entry.path, text });
      } catch {
        continue; // Skip unreadable files and keep going.
      }
    }

    // Scan: secrets (generated patterns) + vibe config checks.
    // Findings carry masked values + fingerprints only.
    const findings: VibeFinding[] = [];
    const seenFingerprints = new Set<string>();
    for (const file of files) {
      for (const f of scanVibeFileSecrets(file.name, file.text, patterns)) {
        if (f.fingerprint && seenFingerprints.has(f.fingerprint)) continue;
        if (f.fingerprint) seenFingerprints.add(f.fingerprint);
        findings.push(f);
      }
      findings.push(...checkVibeFile(file.name, file.text));
    }
    findings.sort(
      (a, b) =>
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        a.file.localeCompare(b.file) ||
        a.line - b.line,
    );

    const bySeverity: Record<string, number> = {};
    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    }
    const summary = { total: findings.length, bySeverity };
    const reportId = createHash("sha256")
      .update(`${canonicalUrl}|${randomUUID()}`, "utf-8")
      .digest("hex")
      .slice(0, 16);
    const auditEvents = buildVibeAuditEvents(
      findings.length,
      canonicalUrl,
      reportId,
    );

    await saveVibeReport({
      id: reportId,
      repoUrl: canonicalUrl,
      summary,
      findings,
      auditEvents,
      filesScanned: files.length,
    });
    // The scan and the dashboard save are one web operation, so both
    // daily counters move together — only after the save succeeded.
    const scansUsed = await recordDailyCount(scanKey);
    const savesUsed = await recordDailyCount(saveKey);

    return NextResponse.json({
      reportId,
      summary,
      findings,
      usage: {
        vibe_scans: {
          used: scansUsed,
          limit: scanCap.limit,
          resetsAt: scanCap.resetsAt,
        },
        dashboard_saves: {
          used: savesUsed,
          limit: saveCap.limit,
          resetsAt: saveCap.resetsAt,
        },
      },
    });
  } catch (err) {
    if (err instanceof VaultNotConfigured) return notConfiguredResponse();
    if (err instanceof Error && /GitHub/.test(err.message)) {
      return NextResponse.json({ error: err.message }, { status: 502 });
    }
    return NextResponse.json(
      { error: "Vibe scan failed." },
      { status: 500 },
    );
  }
}

/** Latest stored reports, newest first (summary rows only — no
 * findings in the list). Free shows the latest 2 per type; the list
 * slice is the only thing that rolls — the reports themselves are
 * never deleted, so a direct GET /api/vibe-scan/[id] still works and
 * share links stay live.
 *
 * The SELECT lives here (not lib/vibe-reports-db.ts) because that
 * module is outside this build's file ownership; the coordinator can
 * move it into a listVibeReports() helper there later.
 */
export async function GET(req: Request) {
  const limited = checkRateLimit(req, "read");
  if (limited) return limited;
  try {
    const planId = await resolveWorkspacePlanId("default");
    const plan = getPlan(planId);
    await ensureVibeReportTables();
    const { rows } = await sql`
      SELECT id, repo_url, summary, files_scanned, created_at
      FROM vibe_reports
      ORDER BY created_at DESC
      LIMIT ${MAX_LISTED_REPORTS}`;
    const all = rows.map((row) => ({
      id: String(row.id),
      repoUrl: String(row.repo_url),
      summary:
        typeof row.summary === "string"
          ? JSON.parse(row.summary)
          : row.summary,
      filesScanned: Number(row.files_scanned ?? 0),
      createdAt: String(row.created_at),
      type: "vibe",
    }));
    const reports = latestReportsForPlan(all, planId);
    return NextResponse.json({
      reports,
      plan: planId,
      limit: plan.limits.shareable_reports,
      note:
        planId === "free"
          ? "Free shows the latest 2 reports per type. Older reports " +
            "stay reachable by their direct link."
          : null,
    });
  } catch (err) {
    if (err instanceof VaultNotConfigured) return notConfiguredResponse();
    return NextResponse.json(
      { error: "Could not list vibe reports." },
      { status: 500 },
    );
  }
}
