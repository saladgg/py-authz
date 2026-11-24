"use client";

import { LogOut } from "lucide-react";
import { useRef } from "react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ROLE_LABELS } from "@/lib/rbac";
import type { Principal } from "@/lib/types";

export function UserMenu({ principal }: { principal: Principal }) {
  // Sign-out is a same-origin POST (SEC3-12), so it's a form submit
  // rather than a link.
  const logoutForm = useRef<HTMLFormElement>(null);

  return (
    <>
      <form ref={logoutForm} action="/api/auth/logout" method="post" hidden />
      <DropdownMenu>
        <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>{principal.id}</DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>
            <div className="font-normal text-muted-foreground">Signed in as</div>
            <div className="truncate">{principal.id}</div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem disabled>
            System role: {principal.system_role ? ROLE_LABELS[principal.system_role] : "none"}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => logoutForm.current?.requestSubmit()}>
            <LogOut className="size-4" />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
