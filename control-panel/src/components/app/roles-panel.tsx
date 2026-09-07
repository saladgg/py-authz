"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { DataTable } from "@/components/app/data-table";
import { RoleBadge } from "@/components/app/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { grantRole, listRoles, revokeRole } from "@/lib/actions";
import { ROLE_LABELS } from "@/lib/rbac";
import type { Role, RoleGrant } from "@/lib/types";

const ROLES: Role[] = ["owner", "admin", "operator", "auditor", "viewer"];

export function RolesPanel({ tenantIds }: { tenantIds: string[] }) {
  return (
    <Tabs defaultValue="system">
      <TabsList>
        <TabsTrigger value="system">System roles</TabsTrigger>
        <TabsTrigger value="tenant">Tenant roles</TabsTrigger>
      </TabsList>
      <TabsContent value="system" className="pt-4">
        <ScopeGrants scope="system" />
      </TabsContent>
      <TabsContent value="tenant" className="pt-4">
        <ScopeGrants scope="tenant" tenantIds={tenantIds} />
      </TabsContent>
    </Tabs>
  );
}

function ScopeGrants({ scope, tenantIds }: { scope: "system" | "tenant"; tenantIds?: string[] }) {
  const [tenantId, setTenantId] = useState(tenantIds?.[0] ?? "");
  const [grants, setGrants] = useState<RoleGrant[]>([]);
  const [loading, setLoading] = useState(true);
  const [subject, setSubject] = useState("");
  const [role, setRole] = useState<Role>("auditor");
  const [pending, setPending] = useState(false);

  const activeTenantId = scope === "tenant" ? tenantId : undefined;
  const ready = scope === "system" || Boolean(activeTenantId);

  useEffect(() => {
    if (!ready) return;
    // A loading flag set right before an async fetch, cleared in
    // `.finally()`, is the standard shape for this — the newer
    // `set-state-in-effect` lint rule flags any synchronous `setState`
    // in an effect body on general principle, but there's no external-
    // system subscription to restructure this into here.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoading(true);
    listRoles(scope, activeTenantId)
      .then((result) => {
        if (result.success) setGrants(result.data.items);
        else toast.error(result.error);
      })
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, activeTenantId]);

  async function refetch() {
    const result = await listRoles(scope, activeTenantId);
    if (result.success) setGrants(result.data.items);
  }

  async function handleGrant() {
    if (!subject.trim()) return;
    setPending(true);
    try {
      const result = await grantRole({ subject: subject.trim(), scope, tenantId: activeTenantId, role });
      if (result.success) {
        toast.success(`Granted ${role} to ${subject}.`);
        setSubject("");
        await refetch();
      } else {
        toast.error(result.error);
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-4">
      {scope === "tenant" ? (
        <div className="grid max-w-xs gap-2">
          <Select value={tenantId} onValueChange={(value) => setTenantId(value ?? "")}>
            <SelectTrigger>
              <SelectValue placeholder="Choose a tenant" />
            </SelectTrigger>
            <SelectContent>
              {(tenantIds ?? []).map((id) => (
                <SelectItem key={id} value={id}>
                  {id}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      ) : null}

      {ready ? (
        <>
          <div className="flex flex-wrap items-end gap-2">
            <div className="grid gap-1">
              <label className="text-xs font-medium text-muted-foreground">Subject</label>
              <Input
                placeholder="alice"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="w-48"
              />
            </div>
            <div className="grid gap-1">
              <label className="text-xs font-medium text-muted-foreground">Role</label>
              <Select value={role} onValueChange={(v) => setRole(v as Role)}>
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {ROLE_LABELS[r]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={handleGrant} disabled={pending || !subject.trim()}>
              Grant
            </Button>
          </div>

          <DataTable
            columns={[
              { header: "Subject", cell: (g: RoleGrant) => g.subject },
              { header: "Role", cell: (g: RoleGrant) => <RoleBadge role={g.role} /> },
              {
                header: "",
                className: "text-right",
                cell: (g: RoleGrant) => (
                  <ConfirmDialog
                    triggerElement={<Button variant="outline" size="sm" />}
                    triggerLabel="Revoke"
                    title={`Revoke ${g.role} from ${g.subject}?`}
                    description={`This removes their ${scope === "system" ? "system-wide" : `tenant:${activeTenantId}`} ${g.role} role.`}
                    confirmLabel="Revoke"
                    destructive
                    onConfirm={async () => {
                      const result = await revokeRole({
                        subject: g.subject.replace(/^user:/, ""),
                        scope,
                        tenantId: activeTenantId,
                        role: g.role,
                      });
                      if (result.success) await refetch();
                      return result;
                    }}
                    successMessage="Role revoked."
                  />
                ),
              },
            ]}
            rows={grants}
            rowKey={(g) => `${g.subject}:${g.role}`}
            emptyMessage={loading ? "Loading…" : "No roles granted at this scope yet."}
          />
        </>
      ) : (
        <p className="text-sm text-muted-foreground">Choose a tenant to manage its roles.</p>
      )}
    </div>
  );
}
