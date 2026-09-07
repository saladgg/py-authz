"use client";

import { useState } from "react";
import { toast } from "sonner";

import { JobStatusPoller } from "@/components/app/job-status-poller";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { startMigration } from "@/lib/actions";
import type { DryRunResult, MigrationJob } from "@/lib/types";

export function MigrationRunner({ tenantIds }: { tenantIds: string[] }) {
  const [allTenants, setAllTenants] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [pending, setPending] = useState(false);
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null);
  const [job, setJob] = useState<MigrationJob | null>(null);

  const targetTenantIds = allTenants ? undefined : Array.from(selected);

  async function handleRun(dryRun: boolean) {
    if (!allTenants && selected.size === 0) {
      toast.error("Select at least one tenant, or choose \"All tenants\".");
      return;
    }
    setPending(true);
    setDryRunResult(null);
    try {
      const result = await startMigration({ dryRun, allTenants, tenantIds: targetTenantIds });
      if (!result.success) {
        toast.error(result.error);
        return;
      }
      if (dryRun) {
        setDryRunResult(result.data as DryRunResult);
      } else {
        setJob(result.data as MigrationJob);
        toast.success("Migration started.");
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Roll out the current model</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={allTenants} onCheckedChange={(v) => setAllTenants(Boolean(v))} />
            All tenants ({tenantIds.length})
          </label>

          {!allTenants ? (
            <div className="grid max-h-48 grid-cols-2 gap-2 overflow-y-auto rounded-md border p-3 sm:grid-cols-3">
              {tenantIds.map((tenantId) => (
                <label key={tenantId} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={selected.has(tenantId)}
                    onCheckedChange={(checked) => {
                      setSelected((prev) => {
                        const next = new Set(prev);
                        if (checked) next.add(tenantId);
                        else next.delete(tenantId);
                        return next;
                      });
                    }}
                  />
                  {tenantId}
                </label>
              ))}
            </div>
          ) : null}

          <div className="flex gap-2">
            <Button variant="outline" onClick={() => handleRun(true)} disabled={pending}>
              Preview (dry run)
            </Button>
            <Button onClick={() => handleRun(false)} disabled={pending}>
              Apply
            </Button>
          </div>

          {dryRunResult ? (
            <div className="rounded-md border p-3 text-sm">
              <p className="mb-2 font-medium">Dry-run result — would change:</p>
              <ul className="space-y-1">
                {Object.entries(dryRunResult.would_change).map(([tenantId, wouldChange]) => (
                  <li key={tenantId} className="flex items-center justify-between">
                    <span>{tenantId}</span>
                    <span className={wouldChange ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"}>
                      {wouldChange ? "Would change" : "No change"}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {job ? <JobStatusPoller initialJob={job} /> : null}
    </div>
  );
}
