"use client";

import { useState, useEffect } from "react";
import { useTheme } from "next-themes";
import { Moon, Sun, Monitor } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useAuth } from "@/context/auth-context";
import { hsmApi } from "@/lib/api";

export default function SettingsPage() {
  const { user } = useAuth();
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [healthStatus, setHealthStatus] = useState<{
    status?: string;
    version?: string;
    uptime?: number;
  }>({});

  useEffect(() => {
    setMounted(true);
    const fetchHealth = async () => {
      try {
        const response = await hsmApi.health();
        if (response.data) {
          setHealthStatus({
            status: response.data.status,
            version: response.data.version,
            uptime: response.data.uptime_seconds,
          });
        }
      } catch {
        // Ignore health check failures
      }
    };
    fetchHealth();
  }, []);

  const formatUptime = (seconds?: number) => {
    if (!seconds) return "-";
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h ${mins}m`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
  };

  const themeOptions = [
    { value: "light", label: "Light", icon: Sun },
    { value: "dark", label: "Dark", icon: Moon },
    { value: "system", label: "System", icon: Monitor },
  ];

  return (
    <>
      <Header title="Settings" description="Account and application preferences" />
      <PageContainer>
        <div className="space-y-6 max-w-2xl animate-fade-in-up">
          {/* Profile */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Profile</CardTitle>
              <CardDescription>Your account information</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Username</p>
                  <p className="text-sm font-medium">{user?.username}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Namespace</p>
                  <Badge variant="outline" className="mt-0.5">{user?.namespace}</Badge>
                </div>
              </div>

              <Separator className="my-4" />

              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Roles</p>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {user?.roles.map((role) => (
                    <Badge key={role} variant="secondary" className="text-xs">
                      {role}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* HSM Status */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">HSM Status</CardTitle>
              <CardDescription>Connected module information</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Status</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <div className="h-2 w-2 rounded-full bg-success status-active" />
                    <span className="text-sm font-medium capitalize">
                      {healthStatus.status || "Connected"}
                    </span>
                  </div>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Version</p>
                  <p className="text-sm font-medium font-mono">
                    {healthStatus.version || "1.0.0"}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Uptime</p>
                  <p className="text-sm font-medium">
                    {formatUptime(healthStatus.uptime)}
                  </p>
                </div>
              </div>

              <Separator className="my-4" />

              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase tracking-wider">API Endpoint</p>
                <code className="text-sm font-mono text-muted-foreground">/api/hsm</code>
              </div>
            </CardContent>
          </Card>

          {/* Appearance */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Appearance</CardTitle>
              <CardDescription>Customize the interface theme</CardDescription>
            </CardHeader>
            <CardContent>
              {mounted && (
                <div className="flex gap-2">
                  {themeOptions.map((opt) => {
                    const Icon = opt.icon;
                    const isActive = theme === opt.value;
                    return (
                      <Button
                        key={opt.value}
                        variant={isActive ? "primary" : "ghost"}
                        size="sm"
                        onClick={() => setTheme(opt.value)}
                        className="gap-2"
                      >
                        <Icon className="h-4 w-4" />
                        {opt.label}
                      </Button>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </PageContainer>
    </>
  );
}
