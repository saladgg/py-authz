"use client";

import { useState } from "react";
import { toast } from "sonner";

import { DataTable } from "@/components/app/data-table";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { grantTuple, listTuples, revokeTuple } from "@/lib/actions";
import type { RelationshipTuple } from "@/lib/types";

export function RelationshipExplorer({ tenantIds, initialTenantId }: { tenantIds: string[]; initialTenantId?: string }) {
  const [tenantId, setTenantId] = useState(initialTenantId ?? tenantIds[0] ?? "");
  const [user, setUser] = useState("");
  const [relation, setRelation] = useState("");
  const [objectFilter, setObjectFilter] = useState("");
  const [results, setResults] = useState<RelationshipTuple[]>([]);
  const [searched, setSearched] = useState(false);
  const [loading, setLoading] = useState(false);

  const [grantUser, setGrantUser] = useState("");
  const [grantRelation, setGrantRelation] = useState("");
  const [grantObjectType, setGrantObjectType] = useState("");
  const [grantObjectId, setGrantObjectId] = useState("");
  const [reason, setReason] = useState("");
  const [mutating, setMutating] = useState(false);

  async function handleSearch() {
    if (!tenantId) {
      toast.error("Choose a tenant first.");
      return;
    }
    setLoading(true);
    try {
      const result = await listTuples(tenantId, {
        user: user || undefined,
        relation: relation || undefined,
        object: objectFilter || undefined,
      });
      if (result.success) {
        setResults(result.data.tuples);
        setSearched(true);
      } else {
        toast.error(result.error);
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleMutate(kind: "grant" | "revoke") {
    if (!tenantId || !grantUser || !grantRelation || !grantObjectType || !grantObjectId || !reason.trim()) {
      toast.error("Fill in user, relation, object type/ID, and a reason.");
      return;
    }
    setMutating(true);
    try {
      const action = kind === "grant" ? grantTuple : revokeTuple;
      const result = await action({
        tenantId,
        user: grantUser,
        relation: grantRelation,
        objectType: grantObjectType,
        objectId: grantObjectId,
        reason: reason.trim(),
      });
      if (result.success) {
        toast.success(kind === "grant" ? "Granted." : "Revoked.");
        setReason("");
        if (searched) void handleSearch();
      } else {
        toast.error(result.error);
      }
    } finally {
      setMutating(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="grid max-w-xs gap-2">
        <Label>Tenant</Label>
        <Select value={tenantId} onValueChange={(value) => setTenantId(value ?? "")}>
          <SelectTrigger>
            <SelectValue placeholder="Choose a tenant" />
          </SelectTrigger>
          <SelectContent>
            {tenantIds.map((id) => (
              <SelectItem key={id} value={id}>
                {id}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Search</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Leave <code>user</code> empty to answer &quot;who has this relation on this object&quot;; leave{" "}
            <code>relation</code>/<code>object</code> empty to answer &quot;what does this user hold&quot;.
          </p>
          <div className="flex flex-wrap items-end gap-2">
            <Field label="User" value={user} onChange={setUser} placeholder="user:alice" />
            <Field label="Relation" value={relation} onChange={setRelation} placeholder="viewer" />
            <Field label="Object" value={objectFilter} onChange={setObjectFilter} placeholder="document:roadmap" />
            <Button onClick={handleSearch} disabled={loading}>
              Search
            </Button>
          </div>

          <DataTable
            columns={[
              { header: "User", cell: (t: RelationshipTuple) => t.user },
              { header: "Relation", cell: (t: RelationshipTuple) => <code className="text-xs">{t.relation}</code> },
              { header: "Object", cell: (t: RelationshipTuple) => <code className="text-xs">{t.object}</code> },
            ]}
            rows={results}
            rowKey={(t) => `${t.user}|${t.relation}|${t.object}`}
            emptyMessage={searched ? "No matching tuples." : "Run a search to see results."}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Manual grant / revoke</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="User" value={grantUser} onChange={setGrantUser} placeholder="user:alice" />
            <Field label="Relation" value={grantRelation} onChange={setGrantRelation} placeholder="viewer" />
            <Field label="Object type" value={grantObjectType} onChange={setGrantObjectType} placeholder="document" />
            <Field label="Object ID" value={grantObjectId} onChange={setGrantObjectId} placeholder="roadmap" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="reason">Reason (required)</Label>
            <Textarea
              id="reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why is this being granted/revoked? — recorded in the audit trail."
              rows={2}
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={() => handleMutate("grant")} disabled={mutating}>
              Grant
            </Button>
            <Button variant="destructive" onClick={() => handleMutate("revoke")} disabled={mutating}>
              Revoke
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <div className="grid gap-1">
      <Label className="text-xs font-medium text-muted-foreground">{label}</Label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className="w-44" />
    </div>
  );
}
