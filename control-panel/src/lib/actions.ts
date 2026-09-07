"use server";

import { revalidatePath } from "next/cache";

import { apiAction, ApiError } from "./api";
import type {
  DryRunResult,
  ListResponse,
  MigrationJob,
  ModelSyncResult,
  RoleGrant,
  ServiceAccountWithSecret,
  Tenant,
  TupleReadResult,
} from "./types";

export type ActionResult<T> = { success: true; data: T } | { success: false; error: string };

async function run<T>(fn: () => Promise<T>): Promise<ActionResult<T>> {
  try {
    return { success: true, data: await fn() };
  } catch (error) {
    if (error instanceof ApiError) {
      return { success: false, error: error.message };
    }
    return { success: false, error: error instanceof Error ? error.message : "Unknown error" };
  }
}

// -------------------------------------------------------------------
// Tenants (CP-4)
// -------------------------------------------------------------------

export async function createTenant(tenantId: string): Promise<ActionResult<Tenant>> {
  const result = await run(() =>
    apiAction<Tenant>("/api/v1/tenants", { method: "POST", body: { tenant_id: tenantId } }),
  );
  if (result.success) revalidatePath("/tenants");
  return result;
}

export async function provisionTenant(tenantId: string): Promise<ActionResult<Tenant>> {
  const result = await run(() =>
    apiAction<Tenant>(`/api/v1/tenants/${encodeURIComponent(tenantId)}/provision`, {
      method: "POST",
    }),
  );
  if (result.success) revalidatePath(`/tenants/${tenantId}`);
  return result;
}

export async function deprovisionTenant(tenantId: string): Promise<ActionResult<{ status: string }>> {
  const result = await run(() =>
    apiAction<{ status: string }>(`/api/v1/tenants/${encodeURIComponent(tenantId)}`, {
      method: "DELETE",
    }),
  );
  if (result.success) revalidatePath("/tenants");
  return result;
}

// -------------------------------------------------------------------
// Models (CP-6)
// -------------------------------------------------------------------

export async function syncModel(
  tenantId: string,
  dryRun: boolean,
): Promise<ActionResult<ModelSyncResult | DryRunResult>> {
  const result = await run(() =>
    apiAction<ModelSyncResult>("/api/v1/models/sync", {
      method: "POST",
      searchParams: { tenant_id: tenantId, dry_run: dryRun },
    }),
  );
  if (result.success && !dryRun) {
    revalidatePath(`/tenants/${tenantId}`);
    revalidatePath("/models");
  }
  return result;
}

export async function rollbackModel(
  tenantId: string,
  versionId: number,
): Promise<ActionResult<ModelSyncResult>> {
  const result = await run(() =>
    apiAction<ModelSyncResult>(`/api/v1/tenants/${encodeURIComponent(tenantId)}/models/rollback`, {
      method: "POST",
      body: { version_id: versionId },
    }),
  );
  if (result.success) revalidatePath("/models");
  return result;
}

// -------------------------------------------------------------------
// Migrations (CP-7)
// -------------------------------------------------------------------

/** Read-only, but exposed as a Server Action too (not `apiFetch()`
 * directly) so a client component can poll job status via `setInterval`
 * without a dedicated Route Handler — see `components/app/job-status-poller.tsx`. */
export async function getMigrationJob(jobId: string): Promise<ActionResult<MigrationJob>> {
  return run(() => apiAction<MigrationJob>(`/api/v1/migrations/${encodeURIComponent(jobId)}`));
}

export async function startMigration(args: {
  dryRun: boolean;
  allTenants: boolean;
  tenantIds?: string[];
}): Promise<ActionResult<MigrationJob | DryRunResult>> {
  const result = await run(() =>
    apiAction<MigrationJob>("/api/v1/migrations", {
      method: "POST",
      body: { dry_run: args.dryRun, all_tenants: args.allTenants, tenant_ids: args.tenantIds },
    }),
  );
  if (result.success) revalidatePath("/migrations");
  return result;
}

// -------------------------------------------------------------------
// Service accounts (CP-3)
// -------------------------------------------------------------------

export async function createServiceAccount(args: {
  name: string;
  description: string;
  scopes: string[];
}): Promise<ActionResult<ServiceAccountWithSecret>> {
  const result = await run(() =>
    apiAction<ServiceAccountWithSecret>("/api/v1/service-accounts", {
      method: "POST",
      body: { name: args.name, description: args.description || null, scopes: args.scopes },
    }),
  );
  if (result.success) revalidatePath("/service-accounts");
  return result;
}

export async function rotateServiceAccount(
  id: string,
): Promise<ActionResult<ServiceAccountWithSecret>> {
  const result = await run(() =>
    apiAction<ServiceAccountWithSecret>(`/api/v1/service-accounts/${encodeURIComponent(id)}/rotate`, {
      method: "POST",
    }),
  );
  if (result.success) revalidatePath("/service-accounts");
  return result;
}

export async function revokeServiceAccount(id: string): Promise<ActionResult<{ status: string }>> {
  const result = await run(() =>
    apiAction<{ status: string }>(`/api/v1/service-accounts/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  );
  if (result.success) revalidatePath("/service-accounts");
  return result;
}

// -------------------------------------------------------------------
// Operators & roles
// -------------------------------------------------------------------

interface RoleAssignmentArgs {
  subject: string;
  scope: "system" | "tenant";
  tenantId?: string;
  role: string;
}

/** Read-only query, exposed as a Server Action so the client-side
 * "Tenant roles" tab (`components/app/roles-panel.tsx`) can refetch when
 * the selected tenant changes without a full page navigation. */
export async function listRoles(
  scope: "system" | "tenant",
  tenantId?: string,
): Promise<ActionResult<ListResponse<RoleGrant>>> {
  return run(() =>
    apiAction<ListResponse<RoleGrant>>("/api/v1/operators/roles", {
      searchParams: { scope, tenant_id: tenantId },
    }),
  );
}

export async function grantRole(
  args: RoleAssignmentArgs,
): Promise<ActionResult<{ status: string }>> {
  const result = await run(() =>
    apiAction<{ status: string }>("/api/v1/operators/roles", {
      method: "POST",
      body: { subject: args.subject, scope: args.scope, tenant_id: args.tenantId, role: args.role },
    }),
  );
  if (result.success) revalidatePath("/operators");
  return result;
}

export async function revokeRole(
  args: RoleAssignmentArgs,
): Promise<ActionResult<{ status: string }>> {
  const result = await run(() =>
    apiAction<{ status: string }>("/api/v1/operators/roles", {
      method: "DELETE",
      body: { subject: args.subject, scope: args.scope, tenant_id: args.tenantId, role: args.role },
    }),
  );
  if (result.success) revalidatePath("/operators");
  return result;
}

// -------------------------------------------------------------------
// Relationship explorer: manual grant/revoke (CP-8)
// -------------------------------------------------------------------

/** Read-only query, exposed as a Server Action for the same reason
 * `listRoles`/`getMigrationJob` are — the Relationship Explorer refetches
 * client-side as the operator changes filters. */
export async function listTuples(
  tenantId: string,
  filters: { user?: string; relation?: string; object?: string },
): Promise<ActionResult<TupleReadResult>> {
  return run(() =>
    apiAction<TupleReadResult>(`/api/v1/tenants/${encodeURIComponent(tenantId)}/tuples`, {
      searchParams: filters,
    }),
  );
}

interface GrantRevokeTupleArgs {
  tenantId: string;
  user: string;
  relation: string;
  objectType: string;
  objectId: string;
  reason: string;
}

export async function grantTuple(
  args: GrantRevokeTupleArgs,
): Promise<ActionResult<{ status: string }>> {
  const result = await run(() =>
    apiAction<{ status: string }>(`/api/v1/tenants/${encodeURIComponent(args.tenantId)}/grants`, {
      method: "POST",
      body: {
        user: args.user,
        relation: args.relation,
        object: { type: args.objectType, id: args.objectId },
        reason: args.reason,
      },
    }),
  );
  if (result.success) revalidatePath("/explorer");
  return result;
}

export async function revokeTuple(
  args: GrantRevokeTupleArgs,
): Promise<ActionResult<{ status: string }>> {
  const result = await run(() =>
    apiAction<{ status: string }>(`/api/v1/tenants/${encodeURIComponent(args.tenantId)}/revokes`, {
      method: "POST",
      body: {
        user: args.user,
        relation: args.relation,
        object: { type: args.objectType, id: args.objectId },
        reason: args.reason,
      },
    }),
  );
  if (result.success) revalidatePath("/explorer");
  return result;
}

// -------------------------------------------------------------------
// Cache (CP-9)
// -------------------------------------------------------------------

export async function invalidateCache(args: {
  key?: string;
  tenantId?: string;
  userId?: string;
}): Promise<ActionResult<{ status: string; deleted?: number }>> {
  const result = await run(() =>
    apiAction<{ status: string; deleted?: number }>("/api/v1/cache/invalidate", {
      method: "POST",
      body: { key: args.key || undefined, tenant_id: args.tenantId || undefined, user_id: args.userId || undefined },
    }),
  );
  if (result.success) revalidatePath("/cache");
  return result;
}
