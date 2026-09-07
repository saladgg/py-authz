import type { ReactNode } from "react";

import { NavSidebar } from "@/components/app/nav-sidebar";
import { UserMenu } from "@/components/app/user-menu";
import { apiFetch, requireSession } from "@/lib/api";
import type { Principal } from "@/lib/types";

/**
 * The real, load-bearing auth check for every screen under this route
 * group (`proxy.ts` only does an optimistic cookie-presence check —
 * see its own comment). `requireSession()` redirects to `/login` if
 * there's no valid/refreshable session; `GET /auth/me` both confirms the
 * session is actually accepted by the control-plane API (not just
 * well-formed) and gives us the operator's system role to gate nav with.
 */
export default async function AppLayout({ children }: { children: ReactNode }) {
  const session = await requireSession();
  const principal = await apiFetch<Principal>("/api/v1/auth/me", { session });

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-64 shrink-0 border-r bg-muted/30 md:block">
        <div className="flex h-14 items-center border-b px-4 text-sm font-semibold">
          py-authz control panel
        </div>
        <NavSidebar systemRole={principal.system_role} />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-between border-b px-4 md:px-6">
          <div className="text-sm text-muted-foreground md:hidden">py-authz control panel</div>
          <div className="ml-auto">
            <UserMenu principal={principal} />
          </div>
        </header>
        <main className="flex-1 overflow-x-hidden p-4 md:p-6">{children}</main>
      </div>
    </div>
  );
}
