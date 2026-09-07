import "server-only";
import { redirect } from "next/navigation";

import { env } from "./env";
import { getValidSession, getValidSessionForAction, type Session } from "./session";

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, body: unknown, message?: string) {
    super(message ?? `Control-plane API request failed with status ${status}`);
    this.status = status;
    this.body = body;
  }
}

/** For Server Component pages: resolve a valid session or send the
 * browser to `/login`. Route Handlers should call `getValidSession()`
 * directly instead and return a 401 JSON body — redirecting a `fetch`
 * caller isn't useful the way it is for a page navigation. */
export async function requireSession(): Promise<Session> {
  const session = await getValidSession();
  if (!session) {
    redirect("/login");
  }
  return session;
}

interface ApiFetchOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  searchParams?: Record<string, string | number | boolean | undefined>;
  /** Pass an already-resolved session to avoid a redundant
   * `requireSession()` call when a caller already has one (e.g. a page
   * making several calls). */
  session?: Session;
}

function buildUrl(path: string, searchParams?: ApiFetchOptions["searchParams"]): string {
  const base = env.controlPlaneApiUrl().replace(/\/$/, "");
  const url = new URL(`${base}${path.startsWith("/") ? "" : "/"}${path}`);
  if (searchParams) {
    for (const [key, value] of Object.entries(searchParams)) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

/**
 * Server-side call to the control-plane API, attaching the session's
 * bearer token explicitly. Deliberately builds a fresh request rather
 * than forwarding anything from the browser's own incoming request — see
 * the Next.js BFF guide's "Working with headers" guidance: an explicit
 * allow-list, never a blanket header/cookie passthrough (the encrypted
 * session cookie is meaningless to the control-plane API anyway; what it
 * needs is the bearer token inside it).
 */
export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const session = options.session ?? (await requireSession());

  const res = await fetch(buildUrl(path, options.searchParams), {
    method: options.method ?? "GET",
    headers: {
      Authorization: `Bearer ${session.accessToken}`,
      ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    // Every screen here shows live operational state (tenant lists, job
    // status, audit trail, cache stats) — none of it should ever be
    // served from Next.js's own fetch cache.
    cache: "no-store",
  });

  const text = await res.text();
  const data: unknown = text ? JSON.parse(text) : null;

  if (!res.ok) {
    const detail =
      data && typeof data === "object" && "detail" in data && typeof data.detail === "string"
        ? data.detail
        : undefined;
    throw new ApiError(res.status, data, detail);
  }

  return data as T;
}

/**
 * Same as `apiFetch()`, but for Server Actions (`lib/actions.ts`):
 * resolves the session via `getValidSessionForAction()` so a refreshed
 * token is persisted back into the cookie, since Server Actions are
 * allowed to write cookies (see `session.ts`). Every mutation in this
 * app should use this, not `apiFetch()`.
 */
export async function apiAction<T>(
  path: string,
  options: Omit<ApiFetchOptions, "session"> = {},
): Promise<T> {
  const session = await getValidSessionForAction();
  if (!session) {
    throw new ApiError(401, null, "Session expired — please sign in again.");
  }
  return apiFetch<T>(path, { ...options, session });
}
