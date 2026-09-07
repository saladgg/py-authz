import { DataTable } from "@/components/app/data-table";
import { JobStatusBadge } from "@/components/app/status-badge";
import { MigrationRunner } from "@/components/app/migration-runner";
import { PageHeader } from "@/components/app/page-header";
import { apiFetch } from "@/lib/api";
import type { ListResponse, MigrationJob } from "@/lib/types";

export default async function MigrationsPage() {
  const [tenants, jobs] = await Promise.all([
    apiFetch<ListResponse<string>>("/api/v1/tenants", { searchParams: { limit: 500 } }).catch(() => ({
      items: [] as string[],
    })),
    apiFetch<ListResponse<MigrationJob>>("/api/v1/migrations", { searchParams: { limit: 20 } }).catch(
      () => ({ items: [] as MigrationJob[] }),
    ),
  ]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Migrations"
        description="Roll the currently registered model out across one or every tenant."
      />

      <MigrationRunner tenantIds={tenants.items} />

      <div>
        <h2 className="mb-2 text-sm font-semibold">Recent jobs</h2>
        <DataTable
          columns={[
            { header: "Job", cell: (j: MigrationJob) => <code className="text-xs">{j.id}</code> },
            { header: "Status", cell: (j: MigrationJob) => <JobStatusBadge status={j.status} /> },
            {
              header: "Started",
              cell: (j: MigrationJob) => (j.started_at ? new Date(j.started_at).toLocaleString() : "—"),
            },
            {
              header: "Finished",
              cell: (j: MigrationJob) => (j.finished_at ? new Date(j.finished_at).toLocaleString() : "—"),
            },
            { header: "Initiated by", cell: (j: MigrationJob) => j.initiated_by ?? "—" },
          ]}
          rows={jobs.items}
          rowKey={(j) => j.id}
          emptyMessage="No migration jobs yet."
        />
      </div>
    </div>
  );
}
