"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

/**
 * A service-account secret, shown exactly once (see CP-3/CP-13) —
 * visually distinct as "you will not see this again," copy-to-clipboard,
 * and nothing in this component (or anywhere else in the app) offers a
 * way to navigate back to it: the secret only ever exists in the props
 * of whatever create/rotate response rendered it, never persisted client-
 * side or re-fetchable from the backend (which only ever stores its
 * argon2 hash — see `py_authz/control_plane/security.py`).
 */
export function SecretRevealOnce({ secret }: { secret: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    await navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <Alert className="border-amber-400 bg-amber-50 dark:border-amber-700 dark:bg-amber-950">
      <AlertTitle className="font-semibold text-amber-900 dark:text-amber-200">
        Copy this secret now — you will not see it again
      </AlertTitle>
      <AlertDescription>
        <div className="mt-2 flex items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded bg-background px-2 py-1.5 text-sm">
            {secret}
          </code>
          <Button type="button" size="sm" variant="outline" onClick={handleCopy}>
            {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  );
}
