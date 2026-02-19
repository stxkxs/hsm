"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Key,
  Shield,
  FileText,
  Activity,
  Plus,
  ArrowRight,
  PenTool,
  CheckCircle,
  XCircle,
  Clock,
} from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { hsmApi } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import type { Key as KeyType, AuditEntry } from "@/lib/types";

export default function DashboardPage() {
  const [stats, setStats] = useState({
    totalKeys: 0,
    activeKeys: 0,
    operationsToday: 0,
    namespaces: 0,
  });
  const [recentActivity, setRecentActivity] = useState<AuditEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [keysRes, auditRes, namespacesRes] = await Promise.all([
          hsmApi.listKeys(),
          hsmApi.getAuditLog({ limit: 5 }),
          hsmApi.listNamespaces(),
        ]);

        if (keysRes.data) {
          const keys = keysRes.data.keys;
          setStats((prev) => ({
            ...prev,
            totalKeys: keysRes.data!.total,
            activeKeys: keys.filter((k) => k.active).length,
          }));
        }

        if (auditRes.data) {
          setRecentActivity(auditRes.data.entries);
          const today = new Date().toDateString();
          const todayOps = auditRes.data.entries.filter(
            (e) => new Date(e.timestamp).toDateString() === today
          ).length;
          setStats((prev) => ({
            ...prev,
            operationsToday: todayOps,
          }));
        }

        if (namespacesRes.data) {
          setStats((prev) => ({
            ...prev,
            namespaces: namespacesRes.data!.length,
          }));
        }
      } catch (error) {
        console.error("Failed to fetch dashboard data:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const statCards = [
    {
      title: "Total Keys",
      value: stats.totalKeys,
      icon: Key,
      href: "/keys",
      color: "text-primary",
    },
    {
      title: "Active Keys",
      value: stats.activeKeys,
      icon: Shield,
      href: "/keys?status=active",
      color: "text-success",
    },
    {
      title: "Operations Today",
      value: stats.operationsToday,
      icon: Activity,
      href: "/audit",
      color: "text-chart-4",
    },
    {
      title: "Namespaces",
      value: stats.namespaces,
      icon: FileText,
      href: "/namespaces",
      color: "text-chart-3",
    },
  ];

  const quickActions = [
    { title: "Create Key", description: "Generate a new cryptographic key", href: "/keys", icon: Plus },
    { title: "Sign Data", description: "Create a digital signature", href: "/operations/sign", icon: PenTool },
    { title: "View Audit Log", description: "Review security events", href: "/audit", icon: FileText },
  ];

  return (
    <>
      <Header title="Dashboard" description="Overview of your HSM" />
      <PageContainer>
        <div className="space-y-6 animate-fade-in-up">
          {/* Stats */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {statCards.map((stat) => (
              <Link key={stat.title} href={stat.href}>
                <Card className="card-hover-glow stat-card-gradient transition-all duration-200 hover:translate-y-[-1px]">
                  <CardContent className="pt-5 pb-4 px-5">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        {stat.title}
                      </p>
                      <stat.icon className={`h-4 w-4 ${stat.color} opacity-70`} />
                    </div>
                    <div className="mt-2">
                      {isLoading ? (
                        <Skeleton className="h-8 w-16" />
                      ) : (
                        <p className="text-2xl font-semibold tabular-nums">{stat.value}</p>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>

          <div className="grid gap-6 lg:grid-cols-5">
            {/* Quick Actions */}
            <Card className="lg:col-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1">
                {quickActions.map((action) => (
                  <Link key={action.title} href={action.href}>
                    <div className="flex items-center gap-3 rounded-lg p-2.5 -mx-1 transition-colors hover:bg-accent group">
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
                        <action.icon className="h-4 w-4" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium">{action.title}</p>
                        <p className="text-xs text-muted-foreground truncate">{action.description}</p>
                      </div>
                      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </Link>
                ))}
              </CardContent>
            </Card>

            {/* Recent Activity */}
            <Card className="lg:col-span-3">
              <CardHeader className="flex flex-row items-center justify-between pb-3">
                <CardTitle className="text-sm font-medium">Recent Activity</CardTitle>
                <Link href="/audit">
                  <Button variant="ghost" size="sm" className="text-xs h-7">
                    View All
                  </Button>
                </Link>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="space-y-3">
                    {[1, 2, 3].map((i) => (
                      <div key={i} className="flex items-center gap-3">
                        <Skeleton className="h-8 w-8 rounded-full" />
                        <div className="flex-1 space-y-1.5">
                          <Skeleton className="h-3.5 w-32" />
                          <Skeleton className="h-3 w-20" />
                        </div>
                        <Skeleton className="h-5 w-14" />
                      </div>
                    ))}
                  </div>
                ) : recentActivity.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-8 text-center">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted mb-3">
                      <Clock className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <p className="text-sm text-muted-foreground">No recent activity</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">
                      Operations will appear here as they occur
                    </p>
                  </div>
                ) : (
                  <div className="space-y-1">
                    {recentActivity.map((entry) => (
                      <div
                        key={entry.id}
                        className="flex items-center gap-3 rounded-lg p-2 -mx-1"
                      >
                        <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${
                          entry.status === "success"
                            ? "bg-success/10 text-success"
                            : "bg-destructive/10 text-destructive"
                        }`}>
                          {entry.status === "success" ? (
                            <CheckCircle className="h-4 w-4" />
                          ) : (
                            <XCircle className="h-4 w-4" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{entry.operation}</p>
                          <p className="text-xs text-muted-foreground">{entry.actor}</p>
                        </div>
                        <div className="flex flex-col items-end shrink-0">
                          <Badge
                            variant={entry.status === "success" ? "success" : "destructive"}
                            className="text-[10px] px-1.5 py-0"
                          >
                            {entry.status}
                          </Badge>
                          <span className="text-[10px] text-muted-foreground/60 mt-0.5">
                            {formatDate(entry.timestamp)}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </PageContainer>
    </>
  );
}
