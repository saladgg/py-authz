/**
 * OIDC authorization-code + PKCE flow against the same provider the
 * control-plane API's own `OIDCJWTValidator` validates tokens against
 * (`OIDC_ISSUER`/`OIDC_CLIENT_ID` — see .env.local.example). This module
 * only ever runs server-side (Route Handlers), never in the browser —
 * that's the whole point of the BFF pattern: the browser gets an
 * httpOnly session cookie, never a raw OIDC token.
 */
import "server-only";
import { createHash, randomBytes } from "node:crypto";

interface DiscoveryDocument {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
  revocation_endpoint?: string;
}

let cachedDiscovery: DiscoveryDocument | null = null;

async function getDiscovery(issuer: string): Promise<DiscoveryDocument> {
  if (cachedDiscovery) return cachedDiscovery;
  const res = await fetch(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
  if (!res.ok) {
    throw new Error(`Failed to fetch OIDC discovery document from ${issuer}: ${res.status}`);
  }
  cachedDiscovery = (await res.json()) as DiscoveryDocument;
  return cachedDiscovery;
}

/** Base64url — used for both PKCE (`code_verifier`/`code_challenge`) and
 * the CSRF `state` value. */
function base64url(input: Buffer): string {
  return input.toString("base64url");
}

export function generateState(): string {
  return base64url(randomBytes(24));
}

export function generateCodeVerifier(): string {
  return base64url(randomBytes(32));
}

export function codeChallengeFromVerifier(verifier: string): string {
  return base64url(createHash("sha256").update(verifier).digest());
}

export interface TokenSet {
  accessToken: string;
  refreshToken: string | null;
  /** Epoch milliseconds. */
  expiresAt: number;
}

function toTokenSet(payload: {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
}): TokenSet {
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token ?? null,
    expiresAt: Date.now() + payload.expires_in * 1000,
  };
}

export async function buildAuthorizationUrl(args: {
  issuer: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
}): Promise<string> {
  const discovery = await getDiscovery(args.issuer);
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", args.clientId);
  url.searchParams.set("redirect_uri", args.redirectUri);
  url.searchParams.set("scope", "openid profile email");
  url.searchParams.set("state", args.state);
  url.searchParams.set("code_challenge", args.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export async function exchangeCodeForTokens(args: {
  issuer: string;
  clientId: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
}): Promise<TokenSet> {
  const discovery = await getDiscovery(args.issuer);
  const res = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: args.clientId,
      redirect_uri: args.redirectUri,
      code: args.code,
      code_verifier: args.codeVerifier,
    }),
  });

  if (!res.ok) {
    throw new Error(`Token exchange failed: ${res.status} ${await res.text()}`);
  }

  return toTokenSet(await res.json());
}

export async function refreshTokens(args: {
  issuer: string;
  clientId: string;
  refreshToken: string;
}): Promise<TokenSet> {
  const discovery = await getDiscovery(args.issuer);
  const res = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: args.clientId,
      refresh_token: args.refreshToken,
    }),
  });

  if (!res.ok) {
    throw new Error(`Token refresh failed: ${res.status} ${await res.text()}`);
  }

  return toTokenSet(await res.json());
}

/** Best-effort RFC 7009 revocation of a refresh token at logout
 * (SEC3-12). Never throws — a logout must complete even if the IdP is
 * unreachable; the cookie is cleared regardless. */
export async function revokeRefreshToken(args: {
  issuer: string;
  clientId: string;
  refreshToken: string;
}): Promise<void> {
  try {
    const discovery = await getDiscovery(args.issuer);
    if (!discovery.revocation_endpoint) return;
    await fetch(discovery.revocation_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: args.clientId,
        token: args.refreshToken,
        token_type_hint: "refresh_token",
      }),
    });
  } catch {
    // best effort
  }
}

/** RP-initiated logout URL, so signing out also ends the IdP's SSO
 * session — otherwise the next "Sign in" silently re-authenticates.
 * Returns null if the provider doesn't advertise one. */
export async function buildEndSessionUrl(args: {
  issuer: string;
  clientId: string;
  postLogoutRedirectUri: string;
}): Promise<string | null> {
  try {
    const discovery = await getDiscovery(args.issuer);
    if (!discovery.end_session_endpoint) return null;
    const url = new URL(discovery.end_session_endpoint);
    url.searchParams.set("client_id", args.clientId);
    url.searchParams.set("post_logout_redirect_uri", args.postLogoutRedirectUri);
    return url.toString();
  } catch {
    return null;
  }
}

/** Decode a JWT's payload without verifying it — the control-plane API
 * is the one that actually verifies signatures; this is only used
 * client-... er, server-side, to read the `sub` claim for display (e.g.
 * pre-filling "grant a role to yourself"), never for an authorization
 * decision. */
export function decodeJwtPayloadUnsafe(token: string): Record<string, unknown> | null {
  try {
    const [, payloadB64] = token.split(".");
    if (!payloadB64) return null;
    const json = Buffer.from(payloadB64, "base64url").toString("utf8");
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}
