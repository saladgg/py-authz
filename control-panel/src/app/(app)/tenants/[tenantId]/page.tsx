import Link from "next/link";

import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { PageHeader } from "@/components/app/page-header";
import { TenantModelPanel } from "@/components/app/tenant-model-panel";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { deprovisionTenant, provisionTenant } from "@/lib/actions";
import { ApiError, apiFetch } from "@/lib/api";
import type { ListResponse, ModelVersion, Tenant } from "@/lib/types";

export default async function TenantDetailPage({
  params,
}: {
  params: Promise<{ tenantId: string }>;
}) {
  const { tenantId } = await params;

  let tenant: Tenant | null = null;
  let history: ModelVersion[] = [];
  let accessError: string | null = null;

  try {
    tenant = await apiFetch<Tenant>(`/api/v1/tenants/${encodeURIComponent(tenantId)}`);
    const historyResult = await apiFetch<ListResponse<ModelVersion>>(
      `/api/v1/tenants/${encodeURIComponent(tenantId)}/models/history`,
    ).catch(() => ({ items: [] }));
    history = historyResult.items;
  } catch (error) {
    accessError =
      error instanceof ApiError && error.status === 403
        ? "You need tenant#auditor on this tenant (or system#owner) to view it."
        : error instanceof ApiError && error.status === 404
          ? "This tenant doesn't exist."
          : "Failed to load this tenant.";
  }

  return (
    <div>
      <PageHeader
        title={tenantId}
        description={tenant ? `Store ID: ${tenant.store_id}` : undefined}
        actions={
          <>
            <form action={async () => { "use server"; await provisionTenant(tenantId); }}>
              <Button type="submit" variant="outline" size="sm">
                Re-provision
              </Button>
            </form>
            <ConfirmDialog
              triggerElement={<Button variant="destructive" size="sm" />}
              triggerLabel="Deprovision"
              title={`Deprovision ${tenantId}?`}
              description="This permanently deletes the real OpenFGA store and this tenant's records. This cannot be undone."
              confirmLabel="Deprovision"
              destructive
              onConfirm={() => deprovisionTenant(tenantId)}
              successMessage="Tenant deprovisioned."
            />
          </>
        }
      />

      {accessError ? (
        <Alert variant="destructive">
          <AlertTitle>Couldn&apos;t load tenant</AlertTitle>
          <AlertDescription>{accessError}</AlertDescription>
        </Alert>
      ) : (
        <div className="space-y-6">
          <div className="flex gap-2 text-sm">
            <Button
              variant="link"
              className="h-auto p-0"
              render={<Link href={`/explorer?tenant_id=${encodeURIComponent(tenantId)}`} />}
            >
              Relationship explorer for this tenant →
            </Button>
            <span className="text-muted-foreground">·</span>
            <Button
              variant="link"
              className="h-auto p-0"
              render={<Link href={`/audit?tenant_id=${encodeURIComponent(tenantId)}`} />}
            >
              Audit log for this tenant →
            </Button>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Authorization model</CardTitle>
            </CardHeader>
            <CardContent>
              <TenantModelPanel tenantId={tenantId} history={history} />
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
