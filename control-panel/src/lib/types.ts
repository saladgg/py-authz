/**
 * TypeScript mirrors of `py_authz/control_plane/routes/*.py`'s response
 * shapes. Kept as one file, hand-written rather than generated — the
 * backend has no OpenAPI-client codegen step yet (it does emit an
 * OpenAPI schema at `/openapi.json` via FastAPI, so generating this file
 * instead is a reasonable follow-up once these shapes need to stay in
 * lockstep more strictly than an admin tool's read-mostly screens do).
 */

export type Role = "owner" | "admin" | "operator" | "auditor" | "viewer";

export const ROLE_CHAIN: Role[] = ["owner", "admin", "operator", "auditor", "viewer"];

export interface Principal {
  id: string;
  kind: "operator" | "service_account";
  scopes: string[] | null;
  system_role: Role | null;
}

export interface HealthStatus {
  status: "ok" | "degraded";
  checks: Record<string, string>;
}

export interface MetricsSnapshot {
  counters: Record<string, number>;
  durations: Record<string, { count: number; sum: number; avg: number }>;
}

export interface Tenant {
  tenant_id: string;
  store_id: string;
}

export interface ServiceAccount {
  id: string;
  name: string;
  description: string | null;
  scopes: string[];
  created_by: string | null;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface ServiceAccountWithSecret extends ServiceAccount {
  secret: string;
}

export interface Operator {
  id: string;
  subject: string;
  email: string | null;
  created_at: string;
}

/** Who a role is granted to — `user:<sub>` or `service_account:<sa_id>`
 * (SEC3-3). */
export type SubjectKind = "user" | "service_account";

export interface RoleGrant {
  subject: string;
  role: Role;
}

export interface ModelVersion {
  id: number;
  tenant_id: string | null;
  model_id: string;
  change_summary: string | null;
  created_by: string | null;
  created_at: string;
}

export interface ModelSyncResult {
  tenant_id: string;
  model_id?: string;
  changed?: boolean;
  dry_run?: boolean;
  would_change?: boolean;
}

export interface MigrationJob {
  id: string;
  kind: string;
  status: "pending" | "running" | "succeeded" | "failed";
  params: Record<string, unknown> | null;
  result: {
    succeeded?: Record<string, string>;
    failed?: Record<string, string>;
    error?: string;
    error_type?: string;
  } | null;
  initiated_by: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface DryRunResult {
  dry_run: true;
  would_change: Record<string, boolean>;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  tenant_id: string | null;
  user_id: string;
  action: string;
  resource: string;
  allowed: boolean;
  reason: string | null;
  reason_data: Record<string, unknown> | null;
  request_id: string | null;
}

export interface RelationshipTuple {
  user: string;
  relation: string;
  object: string;
  timestamp: string | null;
}

export interface TupleReadResult {
  tuples: RelationshipTuple[];
  continuation_token: string | null;
}

export interface CacheStats {
  key_count: number;
}

export interface ListResponse<T> {
  items: T[];
}
