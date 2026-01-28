"use client";

import { useState, useEffect, useCallback } from "react";
import { RefreshCw, Download, Filter } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { hsmApi } from "@/lib/api";
import { formatDate, truncateMiddle } from "@/lib/utils";
import type { AuditEntry, AuditParams } from "@/lib/types";

export default function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [cursor, setCursor] = useState<string | undefined>();
  const [hasMore, setHasMore] = useState(false);
  const [filters, setFilters] = useState<AuditParams>({
    limit: 50,
  });
  const [showFilters, setShowFilters] = useState(false);

  const fetchAuditLog = useCallback(async (append = false) => {
    setIsLoading(true);
    try {
      const params: AuditParams = {
        ...filters,
        cursor: append ? cursor : undefined,
      };
      const response = await hsmApi.getAuditLog(params);
      if (response.data) {
        setEntries((prev) =>
          append ? [...prev, ...response.data!.entries] : response.data!.entries
        );
        setCursor(response.data.next_cursor);
        setHasMore(!!response.data.next_cursor);
      }
    } catch (err) {
      console.error("Failed to fetch audit log:", err);
    } finally {
      setIsLoading(false);
    }
  }, [filters, cursor]);

  useEffect(() => {
    fetchAuditLog(false);
  }, [filters]);

  const handleExport = () => {
    const csv = [
      ["Timestamp", "Operation", "Actor", "Resource", "Status", "Hash"].join(","),
      ...entries.map((e) =>
        [e.timestamp, e.operation, e.actor, `${e.resource_type}:${e.resource_id}`, e.status, e.hash].join(",")
      ),
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-log-${new Date().toISOString()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <Header
        title="Audit Log"
        description="Tamper-evident security audit trail"
        action={
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              icon={<Filter className="h-4 w-4" />}
              onClick={() => setShowFilters(!showFilters)}
            >
              Filters
            </Button>
            <Button
              variant="ghost"
              icon={<Download className="h-4 w-4" />}
              onClick={handleExport}
            >
              Export
            </Button>
          </div>
        }
      />
      <PageContainer>
        {showFilters && (
          <Card className="mb-4">
            <CardContent className="pt-4">
              <div className="grid gap-4 md:grid-cols-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Operation</label>
                  <Input
                    placeholder="e.g., key.created"
                    value={filters.operation || ""}
                    onChange={(e) =>
                      setFilters({ ...filters, operation: e.target.value || undefined })
                    }
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Actor</label>
                  <Input
                    placeholder="Username"
                    value={filters.actor || ""}
                    onChange={(e) =>
                      setFilters({ ...filters, actor: e.target.value || undefined })
                    }
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Status</label>
                  <Select
                    value={filters.status || "all"}
                    onValueChange={(v) =>
                      setFilters({
                        ...filters,
                        status: v === "all" ? undefined : (v as "success" | "failure"),
                      })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="success">Success</SelectItem>
                      <SelectItem value="failure">Failure</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Resource ID</label>
                  <Input
                    placeholder="Resource ID"
                    value={filters.resource_id || ""}
                    onChange={(e) =>
                      setFilters({ ...filters, resource_id: e.target.value || undefined })
                    }
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Events</CardTitle>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => fetchAuditLog(false)}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
            </Button>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Operation</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Hash</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="text-muted-foreground whitespace-nowrap">
                      {formatDate(entry.timestamp)}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{entry.operation}</Badge>
                    </TableCell>
                    <TableCell>{entry.actor}</TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">{entry.resource_type}:</span>
                      <code className="ml-1 text-xs font-mono">
                        {truncateMiddle(entry.resource_id, 16)}
                      </code>
                    </TableCell>
                    <TableCell>
                      <Badge variant={entry.status === "success" ? "success" : "destructive"}>
                        {entry.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs font-mono text-muted-foreground">
                        {truncateMiddle(entry.hash, 12)}
                      </code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>

            {hasMore && (
              <div className="mt-4 flex justify-center">
                <Button
                  variant="ghost"
                  onClick={() => fetchAuditLog(true)}
                  loading={isLoading}
                >
                  Load More
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </PageContainer>
    </>
  );
}
