import { type Role, ROLE_CHAIN } from "./types";

/**
 * Mirrors the backend's union-chain semantics
 * (`py_authz/control_plane/rbac_model.py`'s `owner -> admin -> operator
 * -> auditor -> viewer`): holding a role also satisfies any requirement
 * at or below it in `ROLE_CHAIN`. Used here only to decide what nav/UI
 * to *show* — the backend re-checks every request regardless (see the
 * BFF guide's own "don't rely on the edge/UI layer for authorization"
 * principle, which `lib/api.ts` already follows).
 */
export function roleSatisfies(held: Role | null | undefined, required: Role): boolean {
  if (!held) return false;
  return ROLE_CHAIN.indexOf(held) <= ROLE_CHAIN.indexOf(required);
}

export const ROLE_LABELS: Record<Role, string> = {
  owner: "Owner",
  admin: "Admin",
  operator: "Operator",
  auditor: "Auditor",
  viewer: "Viewer",
};
