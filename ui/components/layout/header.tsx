"use client";

import { useAuth } from "@/context/auth-context";
import { UserMenu } from "@/components/auth/user-menu";

interface HeaderProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export function Header({ title, description, action }: HeaderProps) {
  const { user } = useAuth();

  return (
    <header className="sticky top-0 z-30 border-b border-border/50 bg-background/80 backdrop-blur-xl supports-[backdrop-filter]:bg-background/60">
      <div className="flex h-14 items-center justify-between px-6">
        <div className="flex flex-col justify-center min-w-0">
          <h1 className="text-sm font-semibold tracking-tight truncate">{title}</h1>
          {description && (
            <p className="text-xs text-muted-foreground truncate">{description}</p>
          )}
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {action}
          {user && <UserMenu user={user} />}
        </div>
      </div>
    </header>
  );
}
