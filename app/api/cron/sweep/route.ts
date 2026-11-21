// Scheduled sweep: re-check open fingerprint matches against live files.
//
// GET /api/cron/sweep — called by the Vercel cron (daily 02:00 UTC on the
// Hobby plan — once per day is the most frequent Hobby schedule; the run
// may fire at any point within the 02:00–02:59 UTC hour) or by any
// external scheduler (GitHub Actions, crontab + curl) with the same
// Authorization header.
//
// Auth: requires Authorization: Bearer <CRON_SECRET>, where CRON_SECRET
// is a Vercel env var (Vercel sends the same bearer token when it fires
// the cron). If CRON_SECRET is unset the route answers 503 — it never
// runs unauthenticated.
//
// What it does, per open match (status new/acknowledged, max 50 per run):
// fetches the file from raw.githubusercontent.com (unauthenticated,
// main branch then master, 5 s per fetch), scans it with the existing
// TS detectors (lib/scan.ts), and compares SHA-256 fingerprints of the
// findings against the watched fingerprint. Files shared by several
// matches are fetched and scanned once. When the fingerprint is still
// present, last_seen is refreshed via recordMatch; when it is absent the
// match is left exactly as-is — never auto-resolved, since a missing
// fingerprint can also mean the file moved, was renamed, or the branch
// changed. Every check is reported in the JSON summary:
//
//   { checked, stillPresent, gone, errors, skipped, details: [
//       { fingerprint, repo, file, line, result:
//           "still-present" | "gone" | "error" | "skipped", note? } ] }
//
// The run is time-boxed to ~50 s of fetching so it stays inside the
// 60 s Hobby function limit; matches not reached in time are reported
// as "skipped", not as errors.
//
// Only fingerprints are handled here — findings' full key values exist
// in memory only while scanning and are never logged or returned.

import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { sha256Hex, VaultNotConfigured } from "@/lib/vault-crypto";
import { listMatches, recordMatch } from "@/lib/fingerprints-db";
import { scanText } from "@/lib/scan";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

const MAX_MATCHES_PER_RUN = 50;
const FETCH_TIMEOUT_MS = 5000;
const RUN_BUDGET_MS = 50_000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

type SweepResult = "still-present" | "gone" | "error" | "skipped";

interface SweepDetail {
  fingerprint: string;
  repo: string;
  file: string;
  line: number;
  result: SweepResult;
  note?: string;
}

function isAuthorized(req: Request): boolean {
  const secret = process.env.CRON_SECRET;
  if (!secret) return false;
  const auth = req.headers.get("authorization") ?? "";
  // Constant-time compare on SHA-256 digests (same pattern as
  // verifyAdminPass) so the secret is never held in a comparable string.
  const a = Buffer.from(sha256Hex(auth), "utf8");
  const b = Buffer.from(sha256Hex(`Bearer ${secret}`), "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

interface RawFetch {
  text: string | null;
  error: string | null;
}

/** Fetch a public file from raw.githubusercontent.com, main then master. */
async function fetchRawFile(
  repo: string,
  file: string,
): Promise<RawFetch> {
  const [owner, name] = repo.split("/");
  if (!owner || !name) {
    return { text: null, error: `repo "${repo}" is not owner/name` };
  }
  for (const branch of ["main", "master"]) {
    const url = `https://raw.githubusercontent.com/${owner}/${name}/${branch}/${file}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": "keysentry-sweep (read-only, public files)" },
      });
      if (res.status === 404) continue; // try the next branch
      if (!res.ok) {
        return { text: null, error: `raw fetch HTTP ${res.status}` };
      }
      const length = res.headers.get("content-length");
      if (length && Number(length) > MAX_FILE_BYTES) {
        return { text: null, error: "file too large to scan (> 2 MB)" };
      }
      const text = await res.text();
      if (text.length > MAX_FILE_BYTES) {
        return { text: null, error: "file too large to scan (> 2 MB)" };
      }
      return { text, error: null };
    } catch (err) {
      const aborted =
        err instanceof Error && err.name === "AbortError";
      return {
        text: null,
        error: aborted ? "fetch timed out (5 s)" : "fetch failed",
      };
    } finally {
      clearTimeout(timer);
    }
  }
  return { text: null, error: "file not found on main or master" };
}

export async function GET(req: Request) {
  if (!process.env.CRON_SECRET) {
    return NextResponse.json(
      {
        error:
          "Cron sweep is not configured: CRON_SECRET is not set. " +
          "Set it in Vercel (Project → Settings → Environment Variables) " +
          "and redeploy.",
      },
      { status: 503 },
    );
  }
  if (!isAuthorized(req)) {
    return NextResponse.json(
      {
        error:
          "Unauthorized: this route needs " +
          "Authorization: Bearer <CRON_SECRET>.",
      },
      { status: 401 },
    );
  }

  const startedAt = Date.now();
  try {
    const open = [
      ...(await listMatches("new", MAX_MATCHES_PER_RUN)),
      ...(await listMatches("acknowledged", MAX_MATCHES_PER_RUN)),
    ].slice(0, MAX_MATCHES_PER_RUN);

    // Group by file so one fetch/scan covers every match in it.
    const byFile = new Map<string, typeof open>();
    for (const m of open) {
      const key = JSON.stringify([m.repo, m.file]);
      const group = byFile.get(key) ?? [];
      group.push(m);
      byFile.set(key, group);
    }

    const details: SweepDetail[] = [];
    let stillPresent = 0;
    let gone = 0;
    let errors = 0;
    let skipped = 0;

    for (const [key, group] of byFile) {
      const [repo, file] = JSON.parse(key) as [string, string];
      if (Date.now() - startedAt > RUN_BUDGET_MS) {
        for (const m of group) {
          skipped++;
          details.push({
            fingerprint: m.fingerprint,
            repo: m.repo,
            file: m.file,
            line: m.line,
            result: "skipped",
            note: "run time budget reached; re-checked on the next sweep",
          });
        }
        continue;
      }
      if (!repo || !file) {
        for (const m of group) {
          errors++;
          details.push({
            fingerprint: m.fingerprint,
            repo: m.repo,
            file: m.file,
            line: m.line,
            result: "error",
            note: "no repo/file recorded for this match; cannot re-fetch",
          });
        }
        continue;
      }
      const { text, error } = await fetchRawFile(repo, file);
      if (error || text === null) {
        for (const m of group) {
          errors++;
          details.push({
            fingerprint: m.fingerprint,
            repo: m.repo,
            file: m.file,
            line: m.line,
            result: "error",
            note: error ?? "fetch failed",
          });
        }
        continue;
      }
      // Findings' full values live in memory only; only their SHA-256
      // fingerprints are compared against the watched fingerprint.
      const { findings } = scanText(text, file, new Set<string>());
      const live = new Set(
        findings.map((f) => sha256Hex(f.value).slice(0, 16)),
      );
      for (const m of group) {
        if (live.has(m.fingerprint)) {
          await recordMatch({
            fingerprint: m.fingerprint,
            provider: m.provider,
            repo: m.repo,
            file: m.file,
            line: m.line,
          });
          stillPresent++;
          details.push({
            fingerprint: m.fingerprint,
            repo: m.repo,
            file: m.file,
            line: m.line,
            result: "still-present",
            note: "last_seen refreshed",
          });
        } else {
          gone++;
          details.push({
            fingerprint: m.fingerprint,
            repo: m.repo,
            file: m.file,
            line: m.line,
            result: "gone",
            note:
              "fingerprint not found in the current file content; " +
              "match left as-is (not auto-resolved)",
          });
        }
      }
    }

    return NextResponse.json({
      checked: stillPresent + gone + errors,
      stillPresent,
      gone,
      errors,
      skipped,
      details,
    });
  } catch (err) {
    if (err instanceof VaultNotConfigured) {
      return NextResponse.json(
        {
          error:
            "Fingerprint monitoring is not configured: no Postgres " +
            "database is connected. In Vercel: Storage → Create → " +
            "Postgres (free tier), then redeploy.",
        },
        { status: 503 },
      );
    }
    return NextResponse.json(
      { error: "Sweep failed." },
      { status: 500 },
    );
  }
}
