"use client";

import { useEffect, useState } from "react";

import { JobStatusBadge } from "@/components/app/status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getMigrationJob } from "@/lib/actions";
import type { MigrationJob } from "@/lib/types";

const TERMINAL_STATUSES = new Set(["succeeded", "failed"]);
const POLL_INTERVAL_MS = 2000;

/**
 * Live job-progress polling against `GET /migrations/{job_id}` (CP-7/
 * CP-12) — plain polling rather than a websocket, matching the
 * architecture doc's own stated v1 choice (`control_plane_jobs` already
 * gives every poll a consistent row to read).
 */
export function JobStatusPoller({ initialJob }: { initialJob: MigrationJob }) {
  const [job, setJob] = useState(initialJob);

  useEffect(() => {
    if (TERMINAL_STATUSES.has(job.status)) return;

    const interval = setInterval(async () => {
      const result = await getMigrationJob(job.id);
      if (result.success) setJob(result.data);
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [job.id, job.status]);

  const succeeded = job.result?.succeeded ?? {};
  const failed = job.result?.failed ?? {};

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">
          Job <code className="text-xs">{job.id}</code>
        </CardTitle>
        <JobStatusBadge status={job.status} />
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        {job.status === "running" || job.status === "pending" ? (
          <p className="text-muted-foreground">Running…</p>
        ) : null}
        {Object.keys(succeeded).length > 0 ? (
          <p>
            <span className="font-medium text-emerald-700 dark:text-emerald-400">
              {Object.keys(succeeded).length} succeeded:
            </span>{" "}
            {Object.entries(succeeded)
              .map(([tenant, modelId]) => `${tenant} → ${modelId}`)
              .join(", ")}
          </p>
        ) : null}
        {Object.keys(failed).length > 0 ? (
          <p>
            <span className="font-medium text-red-700 dark:text-red-400">
              {Object.keys(failed).length} failed:
            </span>{" "}
            {Object.entries(failed)
              .map(([tenant, error]) => `${tenant} (${error})`)
              .join(", ")}
          </p>
        ) : null}
        {job.result?.error ? (
          <p className="text-red-700 dark:text-red-400">{job.result.error}</p>
        ) : null}
      </CardContent>
    </Card>
  );
}
