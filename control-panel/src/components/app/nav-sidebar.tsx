"use client";

import {
  Activity,
  ClipboardList,
  Database,
  Gauge,
  KeyRound,
  LayoutDashboard,
  Network,
  ShieldCheck,
  Users,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { roleSatisfies } from "@/lib/rbac";
import type { Role } from "@/lib/types";
import { cn } from "@/lib/utils";

interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  /** Nav visibility only — every route re-checks the real permission
   * server-side regardless (see `lib/api.ts`'s `apiFetch`, which always
   * hits the control-plane API). Omitted for screens whose access
   * depends on a *tenant*-scoped role `GET /auth/me` doesn't report. */
  requiredSystemRole?: Role;
}

const NAV_ITEMS: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/tenants", label: "Tenants", icon: Database },
  { href: "/models", label: "Authorization Models", icon: ShieldCheck },
  { href: "/migrations", label: "Migrations", icon: Activity, requiredSystemRole: "auditor" },
  { href: "/service-accounts", label: "Service Accounts", icon: KeyRound, requiredSystemRole: "auditor" },
  { href: "/operators", label: "Operators & Roles", icon: Users, requiredSystemRole: "auditor" },
  { href: "/audit", label: "Audit Log", icon: ClipboardList },
  { href: "/explorer", label: "Relationship Explorer", icon: Network },
  { href: "/cache", label: "Cache & Performance", icon: Gauge, requiredSystemRole: "auditor" },
];

export function NavSidebar({ systemRole }: { systemRole: Role | null }) {
  const pathname = usePathname();

  return (
    <nav className="flex flex-col gap-1 p-3">
      {NAV_ITEMS.filter(
        (item) => !item.requiredSystemRole || roleSatisfies(systemRole, item.requiredSystemRole),
      ).map((item) => {
        const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
        const Icon = item.icon;
        return (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
              active
                ? "bg-secondary text-secondary-foreground"
                : "text-muted-foreground hover:bg-secondary/60 hover:text-foreground",
            )}
          >
            <Icon className="size-4 shrink-0" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
