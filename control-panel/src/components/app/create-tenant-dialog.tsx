"use client";

import { Plus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createTenant } from "@/lib/actions";

export function CreateTenantDialog() {
  const [open, setOpen] = useState(false);
  const [tenantId, setTenantId] = useState("");
  const [pending, setPending] = useState(false);

  async function handleSubmit() {
    setPending(true);
    try {
      const result = await createTenant(tenantId.trim());
      if (result.success) {
        toast.success(`Provisioned tenant ${result.data.tenant_id}`);
        setOpen(false);
        setTenantId("");
      } else {
        toast.error(result.error);
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm" />}>
        <Plus className="size-4" />
        New tenant
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Provision a tenant</DialogTitle>
          <DialogDescription>
            Creates a real OpenFGA store and syncs the currently registered model into it.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-2">
          <Label htmlFor="tenant-id">Tenant ID</Label>
          <Input
            id="tenant-id"
            placeholder="acme-corp"
            value={tenantId}
            onChange={(event) => setTenantId(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && tenantId.trim()) void handleSubmit();
            }}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={pending}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={pending || !tenantId.trim()}>
            {pending ? "Provisioning…" : "Provision"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
