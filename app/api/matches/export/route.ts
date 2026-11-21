// Export fingerprint matches.
// GET /api/matches/export?format=csv|json (admin only)
//   Passphrase via the `x-admin-pass` header (preferred) or the
//   `adminPass` query param. Admin-gated like the vault list: the export
//   lists fingerprints (16-hex SHA-256 hashes, no raw keys), but it is
//   still an admin operation.
//   CSV columns: id, fingerprint, provider, repo, file, line,
//   first_seen, last_seen, status, assignee.
//   JSON: the same objects.
//   Filename: keysentry-matches-YYYYMMDD.csv|.json

import { NextResponse } from "next/server";
import { VaultNotConfigured, verifyAdminPass } from "@/lib/vault-crypto";
import { listMatches, type FingerprintMatchRow } from "@/lib/fingerprints-db";

export const dynamic = "force-dynamic";

const EXPORT_LIMIT = 10000;

function notConfiguredResponse() {
  return NextResponse.json(
    {
      error:
        "Fingerprint monitoring is not configured: no Postgres database " +
        "is connected. In Vercel: Storage → Create → Postgres (free tier), " +
        "then redeploy.",
    },
    { status: 503 },
  );
}

function errorResponse(err: unknown) {
  if (err instanceof VaultNotConfigured) {
    return notConfiguredResponse();
  }
  return NextResponse.json(
    { error: "Match export failed." },
    { status: 500 },
  );
}

function csvCell(value: string | number): string {
  const text = String(value);
  if (/[",\n\r]/.test(text)) {
    return '"' + text.replace(/"/g, '""') + '"';
  }
  return text;
}

function toCsv(matches: FingerprintMatchRow[]): string {
  const header = [
    "id",
    "fingerprint",
    "provider",
    "repo",
    "file",
    "line",
    "first_seen",
    "last_seen",
    "status",
    "assignee",
  ];
  const lines = [header.join(",")];
  for (const m of matches) {
    lines.push(
      [
        m.id,
        m.fingerprint,
        m.provider,
        m.repo,
        m.file,
        m.line,
        m.firstSeen,
        m.lastSeen,
        m.status,
        m.assignee,
      ]
        .map(csvCell)
        .join(","),
    );
  }
  return lines.join("\r\n") + "\r\n";
}

export async function GET(req: Request) {
  try {
    const url = new URL(req.url);
    const format = (url.searchParams.get("format") ?? "csv").toLowerCase();
    if (format !== "csv" && format !== "json") {
      return NextResponse.json(
        { error: "format must be csv or json." },
        { status: 400 },
      );
    }
    const adminPass =
      req.headers.get("x-admin-pass") ??
      url.searchParams.get("adminPass") ??
      "";
    if (!verifyAdminPass(adminPass)) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    const matches = await listMatches(undefined, EXPORT_LIMIT);
    const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    if (format === "json") {
      return new NextResponse(JSON.stringify({ matches }, null, 2), {
        headers: {
          "Content-Type": "application/json",
          "Content-Disposition":
            `attachment; filename="keysentry-matches-${stamp}.json"`,
        },
      });
    }
    return new NextResponse(toCsv(matches), {
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition":
          `attachment; filename="keysentry-matches-${stamp}.csv"`,
      },
    });
  } catch (err) {
    return errorResponse(err);
  }
}
