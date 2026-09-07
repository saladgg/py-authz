import type { NextRequest } from "next/server";

import { apiFetch } from "@/lib/api";
import { getValidSession } from "@/lib/session";
import type { AuditLogEntry, ListResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

const EXPORT_ROW_LIMIT = 2000;

/**
 * CSV/JSON export for the Audit Log screen (CP-14). A Route Handler
 * (not a Server Action) because the result needs to be a real file
 * download with a `Content-Disposition` header, which a Server Action's
 * return value can't produce directly.
 */
export async function GET(request: NextRequest) {
  const session = await getValidSession();
  if (!session) {
    // A Route Handler serving a download shouldn't redirect a `fetch`/
    // link click into an HTML login page — a clean 401 is more useful to
    // whatever's on the other end (a browser navigation still shows
    // *something* readable).
    return new Response("Not authenticated", { status: 401 });
  }
  const format = request.nextUrl.searchParams.get("format") === "json" ? "json" : "csv";
  const filters = Object.fromEntries(
    ["tenant_id", "user_id", "action", "resource", "allowed", "since", "until"]
      .map((key) => [key, request.nextUrl.searchParams.get(key) ?? undefined])
      .filter(([, value]) => value !== undefined),
  );

  const result = await apiFetch<ListResponse<AuditLogEntry>>("/api/v1/audit-logs", {
    session,
    searchParams: { ...filters, limit: EXPORT_ROW_LIMIT },
  });

  const filename = `audit-log.${format}`;

  if (format === "json") {
    return new Response(JSON.stringify(result.items, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${filename}"`,
      },
    });
  }

  return new Response(toCsv(result.items), {
    headers: {
      "Content-Type": "text/csv",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}

function toCsv(rows: AuditLogEntry[]): string {
  const headers = [
    "id",
    "timestamp",
    "tenant_id",
    "user_id",
    "action",
    "resource",
    "allowed",
    "reason",
    "request_id",
  ] as const;

  const escape = (value: unknown) => {
    const str = value === null || value === undefined ? "" : String(value);
    return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
  };

  const lines = [headers.join(",")];
  for (const row of rows) {
    lines.push(headers.map((header) => escape(row[header])).join(","));
  }
  return lines.join("\n");
}
