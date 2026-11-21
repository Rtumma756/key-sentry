// Audit compliance export API.
// GET /api/audit/export?format=soc2|iso27001|eu-ai-act|siem&md=1
// (admin passphrase required) -> the same reports as the CLI
// (`audit.py export`), from the same mapping tables
// (lib/audit-export.ts mirrors ai-key-scanner/audit/export.py).
//
// The mapping tables are templates, not certification claims — see
// lib/audit-export.ts. SIEM format returns one JSON object per line.

import { NextResponse } from "next/server";
import { VaultNotConfigured, verifyAdminPass } from "@/lib/vault-crypto";
import { checkRateLimit } from "@/lib/rate-limit";
import { listAuditEventsChained } from "@/lib/audit-db";
import {
  euAiActReport,
  iso27001Report,
  renderMarkdown,
  siemExport,
  soc2Report,
} from "@/lib/audit-export";

export const dynamic = "force-dynamic";

const FORMATS = ["soc2", "iso27001", "eu-ai-act", "siem"] as const;

function adminPassFrom(req: Request): string {
  return (
    req.headers.get("x-admin-pass") ??
    new URL(req.url).searchParams.get("adminPass") ??
    ""
  );
}

export async function GET(req: Request) {
  const limited = checkRateLimit(req, "read");
  if (limited) return limited;
  try {
    if (!verifyAdminPass(adminPassFrom(req))) {
      return NextResponse.json(
        { error: "Wrong admin passphrase." },
        { status: 401 },
      );
    }
    const params = new URL(req.url).searchParams;
    const format = params.get("format") ?? "";
    if (!(FORMATS as readonly string[]).includes(format)) {
      return NextResponse.json(
        { error: `format must be one of ${FORMATS.join(", ")}` },
        { status: 400 },
      );
    }
    const events = await listAuditEventsChained();
    if (format === "siem") {
      return new NextResponse(siemExport(events), {
        headers: { "content-type": "application/x-ndjson" },
      });
    }
    const report =
      format === "soc2"
        ? soc2Report(events)
        : format === "iso27001"
          ? iso27001Report(events)
          : euAiActReport(events);
    if (params.get("md") === "1") {
      return new NextResponse(renderMarkdown(report), {
        headers: { "content-type": "text/markdown" },
      });
    }
    return NextResponse.json(report);
  } catch (err) {
    if (err instanceof VaultNotConfigured) {
      return NextResponse.json(
        {
          error:
            "Audit trail is not configured: no Postgres database is " +
            "connected. In Vercel: Storage → Create → Postgres (free " +
            "tier), then redeploy.",
        },
        { status: 503 },
      );
    }
    return NextResponse.json(
      { error: "Audit export failed." },
      { status: 500 },
    );
  }
}
