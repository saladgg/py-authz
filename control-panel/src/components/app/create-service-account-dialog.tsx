"use client";

import { Plus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { SecretRevealOnce } from "@/components/app/secret-reveal-once";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Textarea } from "@/components/ui/textarea";
import { createServiceAccount } from "@/lib/actions";

const COMMON_SCOPES = ["models:sync", "models:read", "tenants:read", "audit:read"];

export function CreateServiceAccountDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scopes, setScopes] = useState<Set<string>>(new Set());
  const [pending, setPending] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);

  function reset() {
    setName("");
    setDescription("");
    setScopes(new Set());
    setSecret(null);
  }

  async function handleSubmit() {
    setPending(true);
    try {
      const result = await createServiceAccount({
        name: name.trim(),
        description,
        scopes: Array.from(scopes),
      });
      if (result.success) {
        setSecret(result.data.secret);
        toast.success(`Service account "${result.data.name}" created.`);
      } else {
        toast.error(result.error);
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) reset();
      }}
    >
      <DialogTrigger render={<Button size="sm" />}>
        <Plus className="size-4" />
        New service account
      </DialogTrigger>
      <DialogContent>
        {secret ? (
          <>
            <DialogHeader>
              <DialogTitle>Service account created</DialogTitle>
            </DialogHeader>
            <SecretRevealOnce secret={secret} />
            <DialogFooter>
              <Button onClick={() => setOpen(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>New service account</DialogTitle>
              <DialogDescription>
                For automation — CI pipelines, backing services — not a human operator.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4">
              <div className="grid gap-2">
                <Label htmlFor="sa-name">Name</Label>
                <Input id="sa-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-bot" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="sa-description">Description (optional)</Label>
                <Textarea
                  id="sa-description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                />
              </div>
              <div className="grid gap-2">
                <Label>Scopes</Label>
                {COMMON_SCOPES.map((scope) => (
                  <label key={scope} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={scopes.has(scope)}
                      onCheckedChange={(checked) => {
                        setScopes((prev) => {
                          const next = new Set(prev);
                          if (checked) next.add(scope);
                          else next.delete(scope);
                          return next;
                        });
                      }}
                    />
                    <code>{scope}</code>
                  </label>
                ))}
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)} disabled={pending}>
                Cancel
              </Button>
              <Button onClick={handleSubmit} disabled={pending || !name.trim()}>
                {pending ? "Creating…" : "Create"}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
