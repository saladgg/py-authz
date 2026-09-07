/**
 * The BFF session cookie: an encrypted blob (see `crypto.ts`) holding
 * the OIDC access/refresh tokens. The browser only ever holds this one
 * httpOnly cookie — never the raw tokens.
 */
import "server-only";
import { cookies } from "next/headers";

import { decrypt, encrypt } from "./crypto";
import { env } from "./env";
import { refreshTokens } from "./oidc";

export const SESSION_COOKIE_NAME = "cp_session";
export const PKCE_COOKIE_NAME = "cp_pkce";
export const STATE_COOKIE_NAME = "cp_state";

/** Short-lived — only alive between `/api/auth/login` and
 * `/api/auth/callback`, never meant to outlive that round trip. */
export const LOGIN_FLOW_COOKIE_MAX_AGE_SECONDS = 5 * 60;

export interface Session {
  accessToken: string;
  refreshToken: string | null;
  /** Epoch milliseconds. */
  expiresAt: number;
}

function isExpired(session: Session): boolean {
  // 10s leeway so a request that's mid-flight right as the token expires
  // gets a clean refresh instead of a 401 from the backend.
  return Date.now() >= session.expiresAt - 10_000;
}

/**
 * Read the session as stored, with NO refresh attempt — safe to call
 * from a Server Component (read-only). May return an *expired* session;
 * most callers want `getValidSession()` instead.
 */
export async function readSession(): Promise<Session | null> {
  const store = await cookies();
  const raw = store.get(SESSION_COOKIE_NAME)?.value;
  if (!raw) return null;

  const decrypted = decrypt(raw);
  if (!decrypted) return null;

  try {
    const parsed = JSON.parse(decrypted) as Partial<Session>;
    if (typeof parsed.accessToken !== "string" || typeof parsed.expiresAt !== "number") {
      return null;
    }
    return {
      accessToken: parsed.accessToken,
      refreshToken: parsed.refreshToken ?? null,
      expiresAt: parsed.expiresAt,
    };
  } catch {
    return null;
  }
}

/**
 * Return a session with a *usable* access token, transparently
 * refreshing via the OIDC refresh grant if the stored one has expired.
 *
 * Next.js only allows writing cookies from a Route Handler or Server
 * Action, never a plain Server Component render (see `cookies()`'s own
 * docs) — so a read-only call site (a page doing a GET against the
 * control-plane API) can't persist a just-refreshed token back into the
 * cookie. That's fine: the refreshed token is used for *this* request
 * only, and the next request refreshes again from the same (still-valid)
 * refresh token — redundant work, never incorrect. A Route Handler /
 * Server Action performing a mutation calls `writeSessionCookie()`
 * itself and so naturally keeps the cookie in sync as a side effect of
 * normal use.
 */
export async function getValidSession(): Promise<Session | null> {
  const session = await readSession();
  if (!session) return null;
  if (!isExpired(session)) return session;
  if (!session.refreshToken) return null;

  try {
    const refreshed = await refreshTokens({
      issuer: env.oidcIssuer(),
      clientId: env.oidcClientId(),
      refreshToken: session.refreshToken,
    });
    return {
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken ?? session.refreshToken,
      expiresAt: refreshed.expiresAt,
    };
  } catch {
    return null; // refresh token itself expired/revoked — session is over
  }
}

/**
 * Same as `getValidSession()`, but for Server Actions specifically:
 * Server Actions (unlike a plain Server Component render) are allowed to
 * write cookies, so a token refreshed here is persisted back into the
 * cookie instead of being used for one request and discarded. Every
 * mutation in this app (`lib/actions.ts`) goes through this instead of
 * `getValidSession()` — the natural place for a long-lived session to
 * pick up a refreshed token, since an admin tool's mutations (grant,
 * revoke, provision, ...) happen often enough in a normal session.
 */
export async function getValidSessionForAction(): Promise<Session | null> {
  const before = await readSession();
  const valid = await getValidSession();
  if (valid && (!before || valid.accessToken !== before.accessToken)) {
    await writeSessionCookie(valid);
  }
  return valid;
}

/** Route Handler / Server Action only. */
export async function writeSessionCookie(session: Session): Promise<void> {
  const store = await cookies();
  store.set(SESSION_COOKIE_NAME, encrypt(JSON.stringify(session)), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    // A Keycloak refresh token often outlives this by a lot — bound the
    // cookie itself to something finite regardless, so an abandoned
    // browser tab doesn't stay silently authenticated indefinitely.
    maxAge: 60 * 60 * 8,
  });
}

/** Route Handler / Server Action only. */
export async function clearSessionCookie(): Promise<void> {
  const store = await cookies();
  store.delete(SESSION_COOKIE_NAME);
}
