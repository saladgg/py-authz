/**
 * Security headers for every page response (SEC3-12), applied by
 * `proxy.ts` per request.
 *
 * Set at runtime rather than in `next.config.ts`'s `headers()`: those are
 * resolved at *build* time, but `form-action` must name the IdP's origin
 * (from the runtime `OIDC_ISSUER`). Sign-out POSTs to /api/auth/logout,
 * which redirects to the IdP's `end_session_endpoint`, and browsers
 * enforce `form-action` on redirects that follow a form submission.
 *
 * The CSP is Next's documented "without nonces" variant
 * (node_modules/next/dist/docs/01-app/02-guides/content-security-policy.md).
 * No `upgrade-insecure-requests`: it breaks plain-HTTP deployments (local
 * Docker); HTTPS enforcement belongs at the TLS terminator (HSTS).
 */

export function idpOrigin(issuer: string | undefined): string {
  if (!issuer) return "";
  try {
    return new URL(issuer).origin;
  } catch {
    return "";
  }
}

export function contentSecurityPolicy({
  issuer,
  isDev,
}: {
  issuer: string | undefined;
  isDev: boolean;
}): string {
  const formAction = ["'self'", idpOrigin(issuer)].filter(Boolean).join(" ");
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' blob: data:",
    "font-src 'self'",
    // The browser only ever talks to this app (BFF) — never the API.
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    `form-action ${formAction}`,
    // Blocks clickjacking of the destructive confirm dialogs.
    "frame-ancestors 'none'",
  ].join("; ");
}

export function securityHeaders(opts: {
  issuer: string | undefined;
  isDev: boolean;
}): Record<string, string> {
  return {
    "Content-Security-Policy": contentSecurityPolicy(opts),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  };
}
