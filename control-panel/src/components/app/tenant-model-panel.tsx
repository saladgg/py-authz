"use client";

import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { DataTable } from "@/components/app/data-table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { rollbackModel, syncModel } from "@/lib/actions";
import type { DryRunResult, ModelSyncResult, ModelVersion } from "@/lib/types";

interface TenantModelPanelProps {
  tenantId: string;
  history: ModelVersion[];
}

export function TenantModelPanel({ tenantId, history }: TenantModelPanelProps) {
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null);
  const [pending, setPending] = useState(false);

  async function handleDryRun() {
    setPending(true);
    setDryRunResult(null);
    try {
      const result = await syncModel(tenantId, true);
      if (result.success) {
        setDryRunResult(result.data as DryRunResult);
      } else {
        toast.error(result.error);
      }
    } finally {
      setPending(false);
    }
  }

  async function handleSync() {
    setPending(true);
    try {
      const result = await syncModel(tenantId, false);
      if (result.success) {
        const data = result.data as ModelSyncResult;
        toast.success(data.changed ? "Model synced — schema changed." : "Already up to date.");
        setDryRunResult(null);
      } else {
        toast.error(result.error);
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" onClick={handleDryRun} disabled={pending}>
          Preview (dry run)
        </Button>
        <Button size="sm" onClick={handleSync} disabled={pending}>
          Sync now
        </Button>
      </div>

      {dryRunResult ? (
        <Alert>
          <AlertTitle>Dry-run preview</AlertTitle>
          <AlertDescription>
            {dryRunResult.would_change[tenantId]
              ? "The currently registered model differs from what's synced — syncing now would change this tenant's schema."
              : "No change — this tenant's schema already matches the currently registered model."}
          </AlertDescription>
        </Alert>
      ) : null}

      <div>
        <h3 className="mb-2 text-sm font-semibold">Version history</h3>
        <DataTable
          columns={[
            {
              header: "Recorded",
              cell: (v: ModelVersion) => new Date(v.created_at).toLocaleString(),
            },
            { header: "Model ID", cell: (v: ModelVersion) => <code className="text-xs">{v.model_id}</code> },
            { header: "Change summary", cell: (v: ModelVersion) => v.change_summary ?? "—" },
            { header: "By", cell: (v: ModelVersion) => v.created_by ?? "—" },
            {
              header: "",
              className: "text-right",
              cell: (v: ModelVersion) => (
                <ConfirmDialog
                  triggerElement={<Button variant="outline" size="sm" />}
                  triggerLabel="Roll back to this"
                  title={`Roll back ${tenantId} to version ${v.id}?`}
                  description="This re-syncs this tenant to this version's schema — a forward sync to an old schema, not an undo of everything that happened since. It's recorded as its own new version."
                  confirmLabel="Roll back"
                  destructive
                  onConfirm={() => rollbackModel(tenantId, v.id)}
                  successMessage="Rolled back."
                />
              ),
            },
          ]}
          rows={history}
          rowKey={(v) => String(v.id)}
          emptyMessage="No recorded syncs yet for this tenant."
        />
      </div>
    </div>
  );
}
