"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const ALLOWED_OPTIONS = [
  { value: "any", label: "Allowed or denied" },
  { value: "true", label: "Allowed only" },
  { value: "false", label: "Denied only" },
];

export function AuditFilterBar() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [tenantId, setTenantId] = useState(searchParams.get("tenant_id") ?? "");
  const [userId, setUserId] = useState(searchParams.get("user_id") ?? "");
  const [action, setAction] = useState(searchParams.get("action") ?? "");
  const [resource, setResource] = useState(searchParams.get("resource") ?? "");
  const [allowed, setAllowed] = useState(searchParams.get("allowed") ?? "any");

  function applyFilters() {
    const params = new URLSearchParams();
    if (tenantId) params.set("tenant_id", tenantId);
    if (userId) params.set("user_id", userId);
    if (action) params.set("action", action);
    if (resource) params.set("resource", resource);
    if (allowed !== "any") params.set("allowed", allowed);
    router.push(`/audit?${params.toString()}`);
  }

  return (
    <div className="flex flex-wrap items-end gap-2 rounded-md border p-3">
      <Field label="Tenant ID" value={tenantId} onChange={setTenantId} placeholder="acme-corp" />
      <Field label="User ID" value={userId} onChange={setUserId} placeholder="user:alice" />
      <Field label="Action" value={action} onChange={setAction} placeholder="viewer" />
      <Field label="Resource" value={resource} onChange={setResource} placeholder="document:roadmap" />
      <div className="grid gap-1">
        <label className="text-xs font-medium text-muted-foreground">Decision</label>
        <Select value={allowed} onValueChange={(value) => setAllowed(value ?? "any")}>
          <SelectTrigger className="w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ALLOWED_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <Button onClick={applyFilters}>Filter</Button>
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
      <label className="text-xs font-medium text-muted-foreground">{label}</label>
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-44"
      />
    </div>
  );
}
