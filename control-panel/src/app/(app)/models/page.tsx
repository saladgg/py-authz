import Link from "next/link";

import { ModelSchemaView, type OpenFgaModel } from "@/components/app/model-schema-view";
import { PageHeader } from "@/components/app/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { apiFetch } from "@/lib/api";

export default async function ModelsPage() {
  const model = await apiFetch<OpenFgaModel>("/api/v1/models").catch(() => null);

  return (
    <div>
      <PageHeader
        title="Authorization Models"
        description="The model currently registered in the control-plane API's own process — what the next sync of any tenant would upload."
      />

      <Alert className="mb-4">
        <AlertTitle>Per-tenant sync, history &amp; rollback live on each tenant&apos;s own page</AlertTitle>
        <AlertDescription>
          This screen shows the source-of-truth schema. Open a{" "}
          <Button variant="link" className="h-auto p-0" render={<Link href="/tenants" />}>
            tenant
          </Button>{" "}
          to preview/sync it there, or view that tenant&apos;s version history and roll back.
        </AlertDescription>
      </Alert>

      {model ? (
        <ModelSchemaView model={model} />
      ) : (
        <p className="text-sm text-muted-foreground">Failed to load the registered model.</p>
      )}
    </div>
  );
}
