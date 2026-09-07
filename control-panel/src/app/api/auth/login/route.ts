import { NextResponse } from "next/server";

import { env } from "@/lib/env";
import {
  buildAuthorizationUrl,
  codeChallengeFromVerifier,
  generateCodeVerifier,
  generateState,
} from "@/lib/oidc";
import { LOGIN_FLOW_COOKIE_MAX_AGE_SECONDS, PKCE_COOKIE_NAME, STATE_COOKIE_NAME } from "@/lib/session";

/**
 * Starts the OIDC authorization-code + PKCE flow. `state` (CSRF) and the
 * PKCE `code_verifier` are stashed in short-lived httpOnly cookies —
 * `/api/auth/callback` reads them back to verify the response actually
 * belongs to this login attempt before exchanging the code.
 */
export async function GET() {
  const state = generateState();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = codeChallengeFromVerifier(codeVerifier);

  const authorizationUrl = await buildAuthorizationUrl({
    issuer: env.oidcIssuer(),
    clientId: env.oidcClientId(),
    redirectUri: env.oidcRedirectUri(),
    state,
    codeChallenge,
  });

  const response = NextResponse.redirect(authorizationUrl);
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge: LOGIN_FLOW_COOKIE_MAX_AGE_SECONDS,
  };
  response.cookies.set(STATE_COOKIE_NAME, state, cookieOptions);
  response.cookies.set(PKCE_COOKIE_NAME, codeVerifier, cookieOptions);

  return response;
}

// Generates a fresh state/PKCE pair on every hit — must never be
// prerendered/cached.
export const dynamic = "force-dynamic";
