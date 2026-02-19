"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { navigation } from "@/config/navigation";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const NAV_GROUPS = {
  main: ["/", "/keys", "/operations"],
  web3: ["/blockchain"],
  system: ["/audit", "/webhooks", "/policies", "/namespaces"],
  config: ["/settings"],
};

function getGroup(href: string): string {
  for (const [group, paths] of Object.entries(NAV_GROUPS)) {
    if (paths.includes(href)) return group;
  }
  return "main";
}

export function Sidebar() {
  const pathname = usePathname();

  const grouped: { group: string; items: typeof navigation }[] = [];
  let currentGroup = "";
  for (const item of navigation) {
    const group = getGroup(item.href);
    if (group !== currentGroup) {
      currentGroup = group;
      grouped.push({ group, items: [] });
    }
    grouped[grouped.length - 1].items.push(item);
  }

  return (
    <TooltipProvider delayDuration={0}>
      <aside className="fixed left-0 top-0 z-40 h-screen w-16 border-r border-border/50 bg-[var(--sidebar,var(--card))]">
        <div className="flex h-full flex-col">
          {/* Logo */}
          <div className="flex h-14 items-center justify-center">
            <Link href="/" className="flex items-center justify-center">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary">
                <Shield className="h-4.5 w-4.5 text-primary-foreground" />
              </div>
            </Link>
          </div>

          {/* Navigation */}
          <nav className="flex-1 overflow-y-auto px-2 pt-2">
            {grouped.map((section, sectionIdx) => (
              <div key={section.group}>
                {sectionIdx > 0 && (
                  <div className="mx-3 my-2 h-px bg-border/50" />
                )}
                <div className="space-y-1">
                  {section.items.map((item) => {
                    const isActive =
                      pathname === item.href ||
                      (item.href !== "/" && pathname.startsWith(item.href));
                    const Icon = item.icon;

                    return (
                      <Tooltip key={item.href}>
                        <TooltipTrigger asChild>
                          <Link
                            href={item.href}
                            className={cn(
                              "relative flex h-9 w-9 items-center justify-center rounded-lg transition-all duration-150 mx-auto",
                              isActive
                                ? "bg-primary/15 text-primary"
                                : "text-muted-foreground hover:bg-accent hover:text-foreground"
                            )}
                          >
                            {isActive && (
                              <span className="absolute -left-2 top-1/2 -translate-y-1/2 h-5 w-0.5 rounded-full bg-primary" />
                            )}
                            <Icon className="h-[18px] w-[18px]" />
                            <span className="sr-only">{item.title}</span>
                          </Link>
                        </TooltipTrigger>
                        <TooltipContent side="right" sideOffset={8} className="flex flex-col">
                          <span className="font-medium">{item.title}</span>
                          {item.description && (
                            <span className="text-xs text-muted-foreground">
                              {item.description}
                            </span>
                          )}
                        </TooltipContent>
                      </Tooltip>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>

          {/* Status indicator */}
          <div className="px-2 pb-3">
            <div className="mx-3 mb-2 h-px bg-border/50" />
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex h-9 w-9 items-center justify-center mx-auto">
                  <div className="h-2 w-2 rounded-full bg-success status-active" />
                </div>
              </TooltipTrigger>
              <TooltipContent side="right" sideOffset={8}>
                <span className="font-medium">HSM Online</span>
                <span className="block text-xs text-muted-foreground">All systems operational</span>
              </TooltipContent>
            </Tooltip>
          </div>
        </div>
      </aside>
    </TooltipProvider>
  );
}
