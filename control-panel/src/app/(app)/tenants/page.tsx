import Link from "next/link";

import { CreateTenantDialog } from "@/components/app/create-tenant-dialog";
import { DataTable } from "@/components/app/data-table";
import { PageHeader } from "@/components/app/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { ApiError, apiFetch } from "@/lib/api";
import type { ListResponse } from "@/lib/types";

export default async function TenantsPage() {
  let tenantIds: string[] = [];
  let accessError: string | null = null;

  try {
    const result = await apiFetch<ListResponse<string>>("/api/v1/tenants", {
      searchParams: { limit: 500 },
    });
    tenantIds = result.items;
  } catch (error) {
    accessError =
      error instanceof ApiError && error.status === 403
        ? "You need system#auditor (or higher) to list tenants."
        : "Failed to load tenants.";
  }

  return (
    <div>
      <PageHeader
        title="Tenants"
        description="Every tenant this deployment knows about."
        actions={<CreateTenantDialog />}
      />

      {accessError ? (
        <Alert variant="destructive">
          <AlertTitle>Couldn&apos;t load tenants</AlertTitle>
          <AlertDescription>{accessError}</AlertDescription>
        </Alert>
      ) : (
        <DataTable
          columns={[
            {
              header: "Tenant ID",
              cell: (tenantId: string) => <span className="font-medium">{tenantId}</span>,
            },
            {
              header: "",
              className: "text-right",
              cell: (tenantId: string) => (
                <Button variant="outline" size="sm" render={<Link href={`/tenants/${encodeURIComponent(tenantId)}`} />}>
                  View
                </Button>
              ),
            },
          ]}
          rows={tenantIds}
          rowKey={(tenantId) => tenantId}
          emptyMessage="No tenants yet — provision one to get started."
        />
      )}
    </div>
  );
}
