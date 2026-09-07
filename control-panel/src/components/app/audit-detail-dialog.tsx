"use client";

import { useState } from "react";

import { AllowedBadge } from "@/components/app/status-badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import type { AuditLogEntry } from "@/lib/types";

/** Per-row detail, surfacing `reason`/`reason_data` (CP-14) — including
 * an `AuthzExplanation`-shaped payload when the decision came from
 * `AuthzEngine.explain()`, though most decisions here are plain
 * `enforce()`/grant/revoke events (`reason_data` shaped accordingly —
 * see `core/enforcement.py`'s `_audit_decision`/`record_write`). */
export function AuditDetailDialog({ entry }: { entry: AuditLogEntry }) {
  const [open, setOpen] = useState(false);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button variant="outline" size="sm" />}>Details</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Audit event #{entry.id}</DialogTitle>
        </DialogHeader>
        <dl className="grid grid-cols-3 gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Timestamp</dt>
          <dd className="col-span-2">{new Date(entry.timestamp).toLocaleString()}</dd>
          <dt className="text-muted-foreground">Tenant</dt>
          <dd className="col-span-2">{entry.tenant_id ?? "—"}</dd>
          <dt className="text-muted-foreground">User</dt>
          <dd className="col-span-2">{entry.user_id}</dd>
          <dt className="text-muted-foreground">Action</dt>
          <dd className="col-span-2 font-mono">{entry.action}</dd>
          <dt className="text-muted-foreground">Resource</dt>
          <dd className="col-span-2 font-mono">{entry.resource}</dd>
          <dt className="text-muted-foreground">Decision</dt>
          <dd className="col-span-2">
            <AllowedBadge allowed={entry.allowed} />
          </dd>
          <dt className="text-muted-foreground">Reason</dt>
          <dd className="col-span-2">{entry.reason ?? "—"}</dd>
          <dt className="text-muted-foreground">Request ID</dt>
          <dd className="col-span-2 font-mono text-xs">{entry.request_id ?? "—"}</dd>
        </dl>
        {entry.reason_data ? (
          <pre className="max-h-64 overflow-auto rounded-md border bg-muted p-3 text-xs">
            {JSON.stringify(entry.reason_data, null, 2)}
          </pre>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
