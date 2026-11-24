import { NextResponse } from "next/server";

import { env } from "@/lib/env";
import { buildEndSessionUrl, revokeRefreshToken } from "@/lib/oidc";
import { clearSessionCookie, readSession } from "@/lib/session";

export const dynamic = "force-dynamic";

/**
 * Sign out (SEC3-12). Previously a `GET` that only deleted the cookie:
 * triggerable cross-site by any `<img src>`, it left the refresh token
 * valid at the IdP, and the IdP's own SSO session alive — so the next
 * "Sign in" silently logged the same user straight back in.
 *
 * Now: a same-origin `POST` that revokes the refresh token (best effort),
 * clears the cookie, and hands the browser to the IdP's
 * `end_session_endpoint` (falling back to /login). Route Handlers don't
 * get Server Actions' built-in Origin check, so it's done here.
 */
export async function POST(request: Request) {
  const requestOrigin = new URL(request.url).origin;
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if ((origin && origin !== requestOrigin) || (!origin && fetchSite && fetchSite !== "same-origin")) {
    return new NextResponse("Cross-site logout refused", { status: 403 });
  }

  const session = await readSession();
  if (session?.refreshToken) {
    await revokeRefreshToken({
      issuer: env.oidcIssuer(),
      clientId: env.oidcClientId(),
      refreshToken: session.refreshToken,
    });
  }
  await clearSessionCookie();

  const loginUrl = new URL("/login", request.url).toString();
  const endSession = await buildEndSessionUrl({
    issuer: env.oidcIssuer(),
    clientId: env.oidcClientId(),
    postLogoutRedirectUri: loginUrl,
  });

  // 303: the browser follows with a GET.
  return NextResponse.redirect(endSession ?? loginUrl, 303);
}
