import { CacheInvalidateForm } from "@/components/app/cache-invalidate-form";
import { DataTable } from "@/components/app/data-table";
import { PageHeader } from "@/components/app/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, apiFetch } from "@/lib/api";
import type { CacheStats, MetricsSnapshot } from "@/lib/types";

export default async function CachePage() {
  let stats: CacheStats | null = null;
  let statsError: string | null = null;
  try {
    stats = await apiFetch<CacheStats>("/api/v1/cache/stats");
  } catch (error) {
    statsError =
      error instanceof ApiError && error.status === 503
        ? "No Redis cache is configured for this deployment."
        : "Failed to load cache stats.";
  }

  const metrics = await apiFetch<MetricsSnapshot>("/api/v1/metrics").catch(() => null);

  const durationRows = metrics ? Object.entries(metrics.durations) : [];

  return (
    <div className="space-y-6">
      <PageHeader title="Cache & Performance" description="Cache hit rate, check volume/latency, and manual invalidation." />

      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Cache</CardTitle>
          </CardHeader>
          <CardContent>
            {statsError ? (
              <Alert variant="destructive">
                <AlertTitle>Unavailable</AlertTitle>
                <AlertDescription>{statsError}</AlertDescription>
              </Alert>
            ) : (
              <div className="text-2xl font-semibold">
                {stats?.key_count ?? "—"} <span className="text-sm font-normal text-muted-foreground">keys cached</span>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Counters</CardTitle>
          </CardHeader>
          <CardContent>
            {metrics ? (
              <ul className="space-y-1 text-sm">
                {Object.entries(metrics.counters).map(([name, value]) => (
                  <li key={name} className="flex justify-between border-b py-1 last:border-0">
                    <span>{name}</span>
                    <span className="font-medium">{value}</span>
                  </li>
                ))}
                {Object.keys(metrics.counters).length === 0 ? (
                  <p className="text-muted-foreground">No counters recorded yet.</p>
                ) : null}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">Failed to load metrics.</p>
            )}
          </CardContent>
        </Card>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Check latency</h2>
        <DataTable
          columns={[
            { header: "Metric", cell: (row: [string, { count: number; sum: number; avg: number }]) => row[0] },
            { header: "Count", cell: (row) => row[1].count },
            { header: "Avg (ms)", cell: (row) => row[1].avg.toFixed(2) },
            { header: "Total (ms)", cell: (row) => row[1].sum.toFixed(2) },
          ]}
          rows={durationRows}
          rowKey={(row) => row[0]}
          emptyMessage="No duration metrics recorded yet."
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Invalidate</CardTitle>
        </CardHeader>
        <CardContent>
          <CacheInvalidateForm />
        </CardContent>
      </Card>
    </div>
  );
}
