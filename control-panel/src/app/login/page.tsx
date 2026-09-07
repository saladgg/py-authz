import { ShieldCheck } from "lucide-react";
import Link from "next/link";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const ERROR_MESSAGES: Record<string, string> = {
  state_mismatch: "Login session expired or was tampered with — please try again.",
  missing_callback_params: "The identity provider didn't return the expected response — please try again.",
  token_exchange_failed: "Couldn't complete sign-in with the identity provider — please try again.",
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  const message = error
    ? (ERROR_MESSAGES[error] ?? `Sign-in failed (${error}) — please try again.`)
    : null;

  return (
    <div className="flex flex-1 items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="items-center text-center">
          <ShieldCheck className="mb-2 size-8 text-primary" />
          <CardTitle>py-authz control panel</CardTitle>
          <CardDescription>Sign in with your operator identity to continue.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {message ? (
            <Alert variant="destructive">
              <AlertTitle>Couldn&apos;t sign in</AlertTitle>
              <AlertDescription>{message}</AlertDescription>
            </Alert>
          ) : null}
          <Button size="lg" render={<Link href="/api/auth/login" />}>
            Sign in
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
