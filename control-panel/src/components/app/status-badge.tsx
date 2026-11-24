import { Badge } from "@/components/ui/badge";

type Tone = "success" | "warning" | "danger" | "neutral" | "info";

const TONE_CLASSES: Record<Tone, string> = {
  success: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  warning: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  danger: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  info: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  neutral: "bg-muted text-muted-foreground",
};

export function ToneBadge({ label, tone }: { label: string; tone: Tone }) {
  return (
    <Badge variant="outline" className={TONE_CLASSES[tone]}>
      {label}
    </Badge>
  );
}

export function AllowedBadge({ allowed }: { allowed: boolean }) {
  return <ToneBadge label={allowed ? "Allowed" : "Denied"} tone={allowed ? "success" : "danger"} />;
}

export function JobStatusBadge({ status }: { status: string }) {
  const tone: Tone =
    status === "succeeded"
      ? "success"
      : status === "failed" || status === "cancelled"
        ? "danger"
        : status === "partial"
          ? "warning"
          : status === "running"
            ? "info"
            : "neutral";
  return <ToneBadge label={status} tone={tone} />;
}

export function RevokedBadge({ revokedAt }: { revokedAt: string | null }) {
  return revokedAt ? (
    <ToneBadge label="Revoked" tone="danger" />
  ) : (
    <ToneBadge label="Active" tone="success" />
  );
}

export function RoleBadge({ role }: { role: string }) {
  const tone: Tone = role === "owner" || role === "admin" ? "warning" : "neutral";
  return <ToneBadge label={role} tone={tone} />;
}
