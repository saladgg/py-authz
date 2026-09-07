import { Badge } from "@/components/ui/badge";
import { CreateServiceAccountDialog } from "@/components/app/create-service-account-dialog";
import { DataTable } from "@/components/app/data-table";
import { PageHeader } from "@/components/app/page-header";
import { ServiceAccountRowActions } from "@/components/app/service-account-row-actions";
import { RevokedBadge } from "@/components/app/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ApiError, apiFetch } from "@/lib/api";
import type { ListResponse, ServiceAccount } from "@/lib/types";

export default async function ServiceAccountsPage() {
  let accounts: ServiceAccount[] = [];
  let accessError: string | null = null;

  try {
    const result = await apiFetch<ListResponse<ServiceAccount>>("/api/v1/service-accounts");
    accounts = result.items;
  } catch (error) {
    accessError =
      error instanceof ApiError && error.status === 403
        ? "You need system#auditor (or higher) to view service accounts."
        : "Failed to load service accounts.";
  }

  return (
    <div>
      <PageHeader
        title="Service Accounts"
        description="Machine identities for automation — CI pipelines, backing services."
        actions={<CreateServiceAccountDialog />}
      />

      {accessError ? (
        <Alert variant="destructive">
          <AlertTitle>Couldn&apos;t load service accounts</AlertTitle>
          <AlertDescription>{accessError}</AlertDescription>
        </Alert>
      ) : (
        <DataTable
          columns={[
            { header: "Name", cell: (a: ServiceAccount) => <span className="font-medium">{a.name}</span> },
            {
              header: "Scopes",
              cell: (a: ServiceAccount) => (
                <div className="flex flex-wrap gap-1">
                  {a.scopes.length ? (
                    a.scopes.map((scope) => (
                      <Badge key={scope} variant="secondary" className="text-xs">
                        {scope}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-muted-foreground">none</span>
                  )}
                </div>
              ),
            },
            { header: "Status", cell: (a: ServiceAccount) => <RevokedBadge revokedAt={a.revoked_at} /> },
            {
              header: "Last used",
              cell: (a: ServiceAccount) => (a.last_used_at ? new Date(a.last_used_at).toLocaleString() : "never"),
            },
            { header: "Created by", cell: (a: ServiceAccount) => a.created_by ?? "—" },
            {
              header: "",
              className: "text-right",
              cell: (a: ServiceAccount) => (
                <ServiceAccountRowActions id={a.id} name={a.name} revoked={a.revoked_at !== null} />
              ),
            },
          ]}
          rows={accounts}
          rowKey={(a) => a.id}
          emptyMessage="No service accounts yet."
        />
      )}
    </div>
  );
}
