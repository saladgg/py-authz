import { Download } from "lucide-react";
import Link from "next/link";

import { AuditDetailDialog } from "@/components/app/audit-detail-dialog";
import { AuditFilterBar } from "@/components/app/audit-filter-bar";
import { AllowedBadge } from "@/components/app/status-badge";
import { DataTable } from "@/components/app/data-table";
import { PageHeader } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";
import { ApiError, apiFetch } from "@/lib/api";
import type { AuditLogEntry, ListResponse } from "@/lib/types";

const PAGE_SIZE = 50;

type SearchParams = Record<string, string | undefined>;

export default async function AuditLogPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const offset = Number(params.offset ?? "0") || 0;

  let entries: AuditLogEntry[] = [];
  let accessError: string | null = null;

  try {
    const result = await apiFetch<ListResponse<AuditLogEntry>>("/api/v1/audit-logs", {
      searchParams: {
        tenant_id: params.tenant_id,
        user_id: params.user_id,
        action: params.action,
        resource: params.resource,
        allowed: params.allowed,
        limit: PAGE_SIZE,
        offset,
      },
    });
    entries = result.items;
  } catch (error) {
    accessError =
      error instanceof ApiError && error.status === 403
        ? "Filtering across every tenant requires system#auditor — try adding a tenant_id, or ask for that role."
        : "Failed to load the audit log.";
  }

  const exportQuery = new URLSearchParams(
    Object.entries(params).filter(([key, value]) => key !== "offset" && value) as [string, string][],
  ).toString();

  return (
    <div>
      <PageHeader
        title="Audit Log"
        description="Every authorization decision, grant, and revoke this deployment has logged."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              render={<Link href={`/api/export/audit-logs?format=csv&${exportQuery}`} />}
            >
              <Download className="size-4" />
              CSV
            </Button>
            <Button
              variant="outline"
              size="sm"
              render={<Link href={`/api/export/audit-logs?format=json&${exportQuery}`} />}
            >
              <Download className="size-4" />
              JSON
            </Button>
          </>
        }
      />

      <div className="mb-4">
        <AuditFilterBar />
      </div>

      {accessError ? (
        <p className="text-sm text-destructive">{accessError}</p>
      ) : (
        <>
          <DataTable
            columns={[
              {
                header: "Timestamp",
                cell: (e: AuditLogEntry) => new Date(e.timestamp).toLocaleString(),
              },
              { header: "Tenant", cell: (e: AuditLogEntry) => e.tenant_id ?? "—" },
              { header: "User", cell: (e: AuditLogEntry) => e.user_id },
              { header: "Action", cell: (e: AuditLogEntry) => <code className="text-xs">{e.action}</code> },
              { header: "Resource", cell: (e: AuditLogEntry) => <code className="text-xs">{e.resource}</code> },
              { header: "Decision", cell: (e: AuditLogEntry) => <AllowedBadge allowed={e.allowed} /> },
              {
                header: "",
                className: "text-right",
                cell: (e: AuditLogEntry) => <AuditDetailDialog entry={e} />,
              },
            ]}
            rows={entries}
            rowKey={(e) => String(e.id)}
            emptyMessage="No audit events match these filters."
          />

          <div className="mt-4 flex justify-between">
            <Button
              variant="outline"
              size="sm"
              disabled={offset === 0}
              className={offset === 0 ? "pointer-events-none opacity-50" : ""}
              render={<Link href={buildPageLink(params, Math.max(0, offset - PAGE_SIZE))} />}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={entries.length < PAGE_SIZE}
              className={entries.length < PAGE_SIZE ? "pointer-events-none opacity-50" : ""}
              render={<Link href={buildPageLink(params, offset + PAGE_SIZE)} />}
            >
              Next
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

function buildPageLink(params: SearchParams, offset: number): string {
  const next = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value && key !== "offset") next.set(key, value);
  }
  next.set("offset", String(offset));
  return `/audit?${next.toString()}`;
}
