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
} from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
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
          // Count today's operations
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
    },
    {
      title: "Active Keys",
      value: stats.activeKeys,
      icon: Shield,
      href: "/keys?status=active",
    },
    {
      title: "Operations Today",
      value: stats.operationsToday,
      icon: Activity,
      href: "/audit",
    },
    {
      title: "Namespaces",
      value: stats.namespaces,
      icon: FileText,
      href: "/namespaces",
    },
  ];

  const quickActions = [
    { title: "Create Key", href: "/keys", icon: Plus },
    { title: "Sign Data", href: "/operations/sign", icon: Shield },
    { title: "View Audit Log", href: "/audit", icon: FileText },
  ];

  return (
    <>
      <Header title="Dashboard" description="Overview of your HSM" />
      <PageContainer>
        <div className="space-y-6">
          {/* Stats */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {statCards.map((stat) => (
              <Link key={stat.title} href={stat.href}>
                <Card className="hover:border-primary/50 transition-colors">
                  <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      {stat.title}
                    </CardTitle>
                    <stat.icon className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">
                      {isLoading ? "-" : stat.value}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {quickActions.map((action) => (
                  <Link key={action.title} href={action.href}>
                    <Button
                      variant="ghost"
                      className="w-full justify-between"
                    >
                      <span className="flex items-center gap-2">
                        <action.icon className="h-4 w-4" />
                        {action.title}
                      </span>
                      <ArrowRight className="h-4 w-4" />
                    </Button>
                  </Link>
                ))}
              </CardContent>
            </Card>

            {/* Recent Activity */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Recent Activity</CardTitle>
                <Link href="/audit">
                  <Button variant="ghost" size="sm">
                    View All
                  </Button>
                </Link>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="space-y-3">
                    {[1, 2, 3].map((i) => (
                      <div
                        key={i}
                        className="h-12 animate-pulse rounded bg-muted"
                      />
                    ))}
                  </div>
                ) : recentActivity.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No recent activity
                  </p>
                ) : (
                  <div className="space-y-3">
                    {recentActivity.map((entry) => (
                      <div
                        key={entry.id}
                        className="flex items-center justify-between text-sm"
                      >
                        <div className="flex flex-col">
                          <span className="font-medium">{entry.operation}</span>
                          <span className="text-xs text-muted-foreground">
                            {entry.actor}
                          </span>
                        </div>
                        <div className="flex flex-col items-end">
                          <span
                            className={
                              entry.status === "success"
                                ? "text-success"
                                : "text-destructive"
                            }
                          >
                            {entry.status}
                          </span>
                          <span className="text-xs text-muted-foreground">
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
