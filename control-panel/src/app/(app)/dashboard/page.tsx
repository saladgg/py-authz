import { Activity, CheckCircle2, Database, XCircle } from "lucide-react";

import { PageHeader } from "@/components/app/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiFetch } from "@/lib/api";
import { env } from "@/lib/env";
import type { HealthStatus, ListResponse, MetricsSnapshot } from "@/lib/types";

/** Backend `GET /health` is unauthenticated/unversioned (see
 * `routes/health.py`) — fetched directly rather than through
 * `apiFetch()`, which always attaches a bearer token. */
async function fetchHealth(): Promise<HealthStatus | null> {
  try {
    const base = env.controlPlaneApiUrl().replace(/\/$/, "");
    const res = await fetch(`${base}/health`, { cache: "no-store" });
    if (!res.ok) return null;
    return (await res.json()) as HealthStatus;
  } catch {
    return null;
  }
}

export default async function DashboardPage() {
  const [health, metrics, tenants] = await Promise.all([
    fetchHealth(),
    apiFetch<MetricsSnapshot>("/api/v1/metrics").catch(() => null),
    apiFetch<ListResponse<string>>("/api/v1/tenants", { searchParams: { limit: 1000 } }).catch(
      () => null,
    ),
  ]);

  const checkCounts = metrics?.counters ?? {};
  const allowed = checkCounts["authz_allowed_total"] ?? 0;
  const denied = checkCounts["authz_denied_total"] ?? 0;
  const cacheHits = checkCounts["authz_cache_hit_total"] ?? 0;

  return (
    <div>
      <PageHeader title="Dashboard" description="At-a-glance system health and activity." />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard
          title="OpenFGA reachability"
          value={health?.status === "ok" ? "Healthy" : health?.status === "degraded" ? "Degraded" : "Unknown"}
          icon={health?.status === "ok" ? CheckCircle2 : XCircle}
          tone={health?.status === "ok" ? "success" : "danger"}
        />
        <SummaryCard title="Tenants" value={String(tenants?.items.length ?? "—")} icon={Database} tone="neutral" />
        <SummaryCard title="Checks allowed" value={String(allowed)} icon={CheckCircle2} tone="success" />
        <SummaryCard title="Checks denied" value={String(denied)} icon={Activity} tone="warning" />
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Health checks</CardTitle>
          </CardHeader>
          <CardContent>
            {health ? (
              <ul className="space-y-1 text-sm">
                {Object.entries(health.checks).map(([name, status]) => (
                  <li key={name} className="flex items-center justify-between border-b py-1.5 last:border-0">
                    <span className="font-medium">{name}</span>
                    <span className="text-muted-foreground">{status}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">Couldn&apos;t reach the control-plane API&apos;s health endpoint.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Cache</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              {cacheHits} cache hit{cacheHits === 1 ? "" : "s"} recorded this process. See{" "}
              <span className="font-medium text-foreground">Cache &amp; Performance</span> for stats and
              invalidation.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function SummaryCard({
  title,
  value,
  icon: Icon,
  tone,
}: {
  title: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  tone: "success" | "warning" | "danger" | "neutral";
}) {
  const toneClass = {
    success: "text-emerald-600 dark:text-emerald-400",
    warning: "text-amber-600 dark:text-amber-400",
    danger: "text-red-600 dark:text-red-400",
    neutral: "text-muted-foreground",
  }[tone];

  return (
    <Card>
      <CardContent className="flex items-center gap-3 pt-6">
        <Icon className={`size-8 ${toneClass}`} />
        <div>
          <div className="text-2xl font-semibold">{value}</div>
          <div className="text-xs text-muted-foreground">{title}</div>
        </div>
      </CardContent>
    </Card>
  );
}
