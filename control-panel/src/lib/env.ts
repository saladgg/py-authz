/**
 * Server-only environment configuration. Importing this from a Client
 * Component is a build error (see the `server-only` package) — every
 * value here (API URLs, the session secret) must never reach the
 * browser bundle.
 */
import "server-only";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name} — see .env.local.example`,
    );
  }
  return value;
}

export const env = {
  controlPlaneApiUrl: () => required("CONTROL_PLANE_API_URL"),
  oidcIssuer: () => required("OIDC_ISSUER"),
  oidcClientId: () => required("OIDC_CLIENT_ID"),
  oidcRedirectUri: () => required("OIDC_REDIRECT_URI"),
  sessionSecret: () => required("SESSION_SECRET"),
};
