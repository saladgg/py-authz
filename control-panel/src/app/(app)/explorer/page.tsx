import { PageHeader } from "@/components/app/page-header";
import { RelationshipExplorer } from "@/components/app/relationship-explorer";
import { apiFetch } from "@/lib/api";
import type { ListResponse } from "@/lib/types";

export default async function ExplorerPage({
  searchParams,
}: {
  searchParams: Promise<{ tenant_id?: string }>;
}) {
  const { tenant_id: initialTenantId } = await searchParams;
  const tenants = await apiFetch<ListResponse<string>>("/api/v1/tenants", {
    searchParams: { limit: 500 },
  }).catch(() => ({ items: [] as string[] }));

  return (
    <div>
      <PageHeader
        title="Relationship Explorer"
        description={'"Who has viewer on document:roadmap?" / "What can user:alice access?" — plus manual grant/revoke.'}
      />
      <RelationshipExplorer tenantIds={tenants.items} initialTenantId={initialTenantId} />
    </div>
  );
}
