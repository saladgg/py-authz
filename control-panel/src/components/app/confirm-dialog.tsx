"use client";

import { useState, type ReactElement, type ReactNode } from "react";
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

interface ConfirmDialogProps {
  /**
   * An element providing the trigger's *props* only (variant, size,
   * disabled, ...) — e.g. `<Button variant="destructive" size="sm" />`
   * with no children. Base UI's `render` prop pattern (which every
   * primitive in `components/ui/` uses instead of Radix's old `asChild`)
   * takes the element's props but always renders *this* component's own
   * `children` as the content — see `triggerLabel`.
   */
  triggerElement: ReactElement;
  triggerLabel: ReactNode;
  title: string;
  description: ReactNode;
  confirmLabel?: string;
  destructive?: boolean;
  /** Typically a Server Action bound to its arguments — see
   * `lib/actions.ts`. Returning `{ success: false, error }` shows the
   * error via toast without closing the dialog; throwing does the same. */
  onConfirm: () => Promise<{ success: boolean; error?: string }>;
  successMessage?: string;
}

/**
 * Shared confirmation step for every destructive/high-stakes action in
 * this app (tenant deprovision, service-account revoke, role revoke,
 * ...) — see CP-11's "shared <ConfirmDialog>" component and CP-12's note
 * that deprovisioning a tenant should be "at least as deliberate as
 * `migrate --all-tenants`'s existing prompt-or-`--yes` pattern."
 */
export function ConfirmDialog({
  triggerElement,
  triggerLabel,
  title,
  description,
  confirmLabel = "Confirm",
  destructive = false,
  onConfirm,
  successMessage,
}: ConfirmDialogProps) {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);

  async function handleConfirm() {
    setPending(true);
    try {
      const result = await onConfirm();
      if (result.success) {
        toast.success(successMessage ?? "Done.");
        setOpen(false);
      } else {
        toast.error(result.error ?? "Something went wrong.");
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Something went wrong.");
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={triggerElement}>{triggerLabel}</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription render={<div />}>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={pending}>
            Cancel
          </Button>
          <Button variant={destructive ? "destructive" : "default"} onClick={handleConfirm} disabled={pending}>
            {pending ? "Working…" : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
