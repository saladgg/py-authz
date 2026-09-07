import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { SESSION_COOKIE_NAME } from "@/lib/session";

/**
 * Optimistic auth gate — runs before every matched request, checking
 * only whether a session cookie is *present*, never decrypting or
 * validating it (this runs in a restricted runtime, and per the Next.js
 * BFF guide's own guidance: "Do not rely on proxy alone for
 * authentication and authorization"). The actual, load-bearing check is
 * `requireSession()`/`apiFetch()` (`lib/api.ts`), which every protected
 * page and every backend call goes through regardless — this just saves
 * a render for the common "no cookie at all" case and gives a
 * same-origin redirect before React ever runs.
 *
 * Named `proxy` (not `middleware`) and in this file (not
 * `middleware.ts`) — Next.js 16 renamed the convention; `middleware.ts`
 * still works but is deprecated.
 */
export function proxy(request: NextRequest) {
  const hasSessionCookie = request.cookies.has(SESSION_COOKIE_NAME);

  if (!hasSessionCookie) {
    const loginUrl = new URL("/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  // Everything under the protected route group, never /login or the
  // auth/static routes.
  matcher: ["/dashboard/:path*", "/tenants/:path*", "/models/:path*", "/migrations/:path*",
    "/service-accounts/:path*", "/operators/:path*", "/audit/:path*", "/explorer/:path*",
    "/cache/:path*"],
};
