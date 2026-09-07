"use client";

import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { invalidateCache } from "@/lib/actions";

export function CacheInvalidateForm() {
  const [mode, setMode] = useState<"key" | "user" | "tenant">("tenant");
  const [key, setKey] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [userId, setUserId] = useState("");
  const [pending, setPending] = useState(false);

  async function handleSubmit() {
    setPending(true);
    try {
      const result = await invalidateCache(
        mode === "key"
          ? { key }
          : mode === "user"
            ? { userId, tenantId: tenantId || undefined }
            : { tenantId },
      );
      if (result.success) {
        toast.success(
          typeof result.data.deleted === "number"
            ? `Invalidated ${result.data.deleted} key(s).`
            : "Invalidated.",
        );
      } else {
        toast.error(result.error);
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {(["tenant", "user", "key"] as const).map((m) => (
          <Button key={m} variant={mode === m ? "default" : "outline"} size="sm" onClick={() => setMode(m)}>
            By {m}
          </Button>
        ))}
      </div>

      {mode === "tenant" ? (
        <Field label="Tenant ID" value={tenantId} onChange={setTenantId} placeholder="acme-corp" />
      ) : mode === "user" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="User ID" value={userId} onChange={setUserId} placeholder="user:alice" />
          <Field label="Tenant ID (optional — narrows the match)" value={tenantId} onChange={setTenantId} placeholder="acme-corp" />
        </div>
      ) : (
        <Field label="Exact cache key" value={key} onChange={setKey} placeholder="opaque key from an audit event" />
      )}

      <Button
        onClick={handleSubmit}
        disabled={
          pending ||
          (mode === "tenant" && !tenantId) ||
          (mode === "user" && !userId) ||
          (mode === "key" && !key)
        }
      >
        Invalidate
      </Button>
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
    <div className="grid gap-2">
      <Label>{label}</Label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  );
}
