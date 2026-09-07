"use client";

import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { SecretRevealOnce } from "@/components/app/secret-reveal-once";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { revokeServiceAccount, rotateServiceAccount } from "@/lib/actions";

export function ServiceAccountRowActions({ id, name, revoked }: { id: string; name: string; revoked: boolean }) {
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [rotating, setRotating] = useState(false);

  async function handleRotate() {
    setRotating(true);
    try {
      const result = await rotateServiceAccount(id);
      if (result.success) {
        setNewSecret(result.data.secret);
      } else {
        toast.error(result.error);
      }
    } finally {
      setRotating(false);
    }
  }

  return (
    <div className="flex justify-end gap-2">
      <Button variant="outline" size="sm" onClick={handleRotate} disabled={revoked || rotating}>
        Rotate
      </Button>
      <ConfirmDialog
        triggerElement={<Button variant="destructive" size="sm" disabled={revoked} />}
        triggerLabel="Revoke"
        title={`Revoke "${name}"?`}
        description="Its secret is invalidated immediately — this cannot be undone."
        confirmLabel="Revoke"
        destructive
        onConfirm={() => revokeServiceAccount(id)}
        successMessage="Service account revoked."
      />

      <Dialog open={newSecret !== null} onOpenChange={(open) => !open && setNewSecret(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Secret rotated for &quot;{name}&quot;</DialogTitle>
          </DialogHeader>
          {newSecret ? <SecretRevealOnce secret={newSecret} /> : null}
          <DialogFooter>
            <Button onClick={() => setNewSecret(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
