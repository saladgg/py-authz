import { cookies } from "next/headers";
import { type NextRequest, NextResponse } from "next/server";

import { env } from "@/lib/env";
import { exchangeCodeForTokens } from "@/lib/oidc";
import { PKCE_COOKIE_NAME, STATE_COOKIE_NAME, writeSessionCookie } from "@/lib/session";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const returnedState = request.nextUrl.searchParams.get("state");
  const oidcError = request.nextUrl.searchParams.get("error");

  const cookieStore = await cookies();
  const expectedState = cookieStore.get(STATE_COOKIE_NAME)?.value;
  const codeVerifier = cookieStore.get(PKCE_COOKIE_NAME)?.value;

  // Always consume the flow cookies on the way out, success or failure —
  // they're single-use.
  cookieStore.delete(STATE_COOKIE_NAME);
  cookieStore.delete(PKCE_COOKIE_NAME);

  if (oidcError) {
    return loginErrorRedirect(request, `oidc_error:${oidcError}`);
  }
  if (!code || !returnedState || !codeVerifier) {
    return loginErrorRedirect(request, "missing_callback_params");
  }
  if (returnedState !== expectedState) {
    // CSRF check — the state we handed out at /api/auth/login must come
    // back unchanged.
    return loginErrorRedirect(request, "state_mismatch");
  }

  let tokens;
  try {
    tokens = await exchangeCodeForTokens({
      issuer: env.oidcIssuer(),
      clientId: env.oidcClientId(),
      redirectUri: env.oidcRedirectUri(),
      code,
      codeVerifier,
    });
  } catch {
    return loginErrorRedirect(request, "token_exchange_failed");
  }

  await writeSessionCookie({
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresAt: tokens.expiresAt,
  });

  return NextResponse.redirect(new URL("/dashboard", request.url));
}

function loginErrorRedirect(request: NextRequest, reason: string): NextResponse {
  const url = new URL("/login", request.url);
  url.searchParams.set("error", reason);
  return NextResponse.redirect(url);
}
