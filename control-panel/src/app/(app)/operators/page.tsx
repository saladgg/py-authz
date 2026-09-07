import { DataTable } from "@/components/app/data-table";
import { PageHeader } from "@/components/app/page-header";
import { RolesPanel } from "@/components/app/roles-panel";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, apiFetch } from "@/lib/api";
import type { ListResponse, Operator } from "@/lib/types";

export default async function OperatorsPage() {
  let operators: Operator[] = [];
  let tenantIds: string[] = [];
  let accessError: string | null = null;

  try {
    const [operatorsResult, tenantsResult] = await Promise.all([
      apiFetch<ListResponse<Operator>>("/api/v1/operators"),
      apiFetch<ListResponse<string>>("/api/v1/tenants", { searchParams: { limit: 500 } }).catch(() => ({
        items: [] as string[],
      })),
    ]);
    operators = operatorsResult.items;
    tenantIds = tenantsResult.items;
  } catch (error) {
    accessError =
      error instanceof ApiError && error.status === 403
        ? "You need system#auditor (or higher) to view operators."
        : "Failed to load operators.";
  }

  if (accessError) {
    return (
      <div>
        <PageHeader title="Operators & Roles" />
        <Alert variant="destructive">
          <AlertTitle>Couldn&apos;t load this screen</AlertTitle>
          <AlertDescription>{accessError}</AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Operators & Roles"
        description="Who can use the control panel, and for what — assign a role scoped to the whole system or one tenant."
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Role assignment</CardTitle>
        </CardHeader>
        <CardContent>
          <RolesPanel tenantIds={tenantIds} />
        </CardContent>
      </Card>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Known operators</h2>
        <p className="mb-2 text-sm text-muted-foreground">
          Every subject that has ever logged in — grant one a role above using their subject (without the
          &quot;user:&quot; prefix).
        </p>
        <DataTable
          columns={[
            { header: "Subject", cell: (o: Operator) => o.subject },
            { header: "Email", cell: (o: Operator) => o.email ?? "—" },
            {
              header: "First seen",
              cell: (o: Operator) => new Date(o.created_at).toLocaleString(),
            },
          ]}
          rows={operators}
          rowKey={(o) => o.id}
          emptyMessage="No operators have logged in yet."
        />
      </div>
    </div>
  );
}
