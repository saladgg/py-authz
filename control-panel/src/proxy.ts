import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { securityHeaders } from "@/lib/security-headers";
import { SESSION_COOKIE_NAME } from "@/lib/session";

/** Routes that require a session (the `(app)` route group). */
const PROTECTED_PREFIXES = [
  "/dashboard",
  "/tenants",
  "/models",
  "/migrations",
  "/service-accounts",
  "/operators",
  "/audit",
  "/explorer",
  "/cache",
];

function isProtected(pathname: string): boolean {
  return PROTECTED_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/**
 * Runs before every page request:
 *
 * 1. Optimistic auth gate for protected routes — checks only that a
 *    session cookie is *present*, never decrypting or validating it (per
 *    the Next.js BFF guide: "Do not rely on proxy alone for
 *    authentication and authorization"). The load-bearing check is
 *    `requireSession()`/`apiFetch()` (`lib/api.ts`), which every
 *    protected page and backend call goes through regardless.
 * 2. Security headers on every response (SEC3-12) — see
 *    `lib/security-headers.ts` for why they're set here at runtime.
 *
 * Named `proxy` (not `middleware`) — Next.js 16 renamed the convention.
 */
export function proxy(request: NextRequest) {
  let response: NextResponse;
  if (isProtected(request.nextUrl.pathname) && !request.cookies.has(SESSION_COOKIE_NAME)) {
    response = NextResponse.redirect(new URL("/login", request.url));
  } else {
    response = NextResponse.next();
  }

  const headers = securityHeaders({
    issuer: process.env.OIDC_ISSUER,
    isDev: process.env.NODE_ENV === "development",
  });
  for (const [key, value] of Object.entries(headers)) {
    response.headers.set(key, value);
  }
  return response;
}

export const config = {
  // Every page, not static assets or image optimization.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
