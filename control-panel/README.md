# py-authz control panel

The Next.js frontend for [`py_authz.control_plane`](../py_authz/control_plane/) — the optional HTTP
management API for operating a py-authz deployment. See
[`../docs/control_plane.md`](../docs/control_plane.md) for the full walkthrough (standing up the dev
stack, creating the RBAC store, break-glass bootstrap) — this file only covers the frontend itself.

## Architecture

- **Next.js App Router**, TypeScript, Tailwind v4, shadcn/ui (Base UI primitives).
- **BFF (Backend-for-Frontend) session pattern**: the browser holds exactly one httpOnly,
  AES-256-GCM-encrypted session cookie (`lib/session.ts`, `lib/crypto.ts`) — never a raw OIDC token.
  The Next.js *server* (Route Handlers, Server Components, Server Actions) decrypts it and attaches
  `Authorization: Bearer <token>` when calling the control-plane API (`lib/api.ts`). Client JS never
  sees a bearer token or talks to the control-plane API directly.
- **Auth flow**: `/api/auth/login` (redirect to Keycloak, PKCE) → `/api/auth/callback` (exchange code,
  set session cookie) → `/api/auth/logout` (clear cookie). See `lib/oidc.ts`.
- **Route gating**: `proxy.ts` (Next.js 16's renamed `middleware.ts`) does a cheap, optimistic
  cookie-presence check before render; `(app)/layout.tsx` does the real check — a valid/refreshable
  session *and* a successful `GET /auth/me` against the control-plane API. Nav items are further
  gated by the operator's system role (`lib/rbac.ts`), but that's UI convenience only — every route
  re-checks authorization server-side regardless.
- **Mutations** go through Server Actions (`lib/actions.ts`), not client-side `fetch` — each one calls
  the control-plane API server-side and revalidates the relevant page.

## Running it

```bash
pnpm install
cp .env.local.example .env.local   # then fill in the values — see docs/control_plane.md
pnpm dev                            # http://localhost:3001
```

Requires the control-plane API running (`docs/control_plane.md` §6) and the dev stack
(`docker compose up -d openfga keycloak redis postgres` from the repo root).

```bash
pnpm build   # production build + typecheck
pnpm lint    # eslint
```

## Project layout

```
src/
├── app/
│   ├── api/auth/{login,callback,logout}/route.ts   # OIDC flow (server-only)
│   ├── api/export/audit-logs/route.ts              # CSV/JSON download
│   ├── login/page.tsx
│   ├── (app)/                                       # protected route group (no URL segment)
│   │   ├── layout.tsx                               # real auth check + nav
│   │   ├── dashboard/, tenants/, models/, migrations/
│   │   ├── service-accounts/, operators/, audit/, explorer/, cache/
├── components/
│   ├── ui/                                          # shadcn-generated primitives
│   └── app/                                         # DataTable, ConfirmDialog, SecretRevealOnce, ...
├── lib/
│   ├── session.ts, crypto.ts, oidc.ts                # BFF session
│   ├── api.ts, actions.ts                            # control-plane API client + Server Actions
│   ├── types.ts, rbac.ts                             # shared types, role-chain helper
└── proxy.ts                                          # optimistic route gate
```
