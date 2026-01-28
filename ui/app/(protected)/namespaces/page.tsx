"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { Plus, RefreshCw, MoreHorizontal, Trash2, Eye } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/context/toast-context";
import { hsmApi } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import type { Namespace } from "@/lib/types";

export default function NamespacesPage() {
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const { success, error } = useToast();

  const fetchNamespaces = async () => {
    setIsLoading(true);
    try {
      const response = await hsmApi.listNamespaces();
      if (response.data) {
        setNamespaces(response.data);
      }
    } catch (err) {
      console.error("Failed to fetch namespaces:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchNamespaces();
  }, []);

  const handleCreate = async () => {
    if (!name) return;

    // Validate name format
    if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/.test(name)) {
      error("Invalid Name", "Namespace must be lowercase alphanumeric with optional hyphens");
      return;
    }

    setIsCreating(true);
    try {
      const response = await hsmApi.createNamespace(name);
      if (response.data) {
        success("Namespace Created", `Namespace "${name}" has been created`);
        setName("");
        setCreateOpen(false);
        fetchNamespaces();
      } else if (response.error) {
        error("Failed to create namespace", response.error.message);
      }
    } catch (err) {
      error("Failed to create namespace", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsCreating(false);
    }
  };

  const handleDelete = async (namespaceName: string) => {
    if (namespaceName === "default") {
      error("Cannot Delete", "The default namespace cannot be deleted");
      return;
    }

    try {
      const response = await hsmApi.deleteNamespace(namespaceName);
      if (response.error) {
        error("Failed to delete namespace", response.error.message);
      } else {
        success("Namespace Deleted", `Namespace "${namespaceName}" has been deleted`);
        fetchNamespaces();
      }
    } catch (err) {
      error("Failed to delete namespace", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <>
      <Header
        title="Namespaces"
        description="Organize keys into logical groups"
        action={
          <Button
            variant="primary"
            icon={<Plus className="h-4 w-4" />}
            onClick={() => setCreateOpen(true)}
          >
            Create Namespace
          </Button>
        }
      />
      <PageContainer>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Namespaces</CardTitle>
            <Button
              variant="ghost"
              size="icon"
              onClick={fetchNamespaces}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
            </Button>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="py-8 text-center">
                <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Keys</TableHead>
                    <TableHead>Policies</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="w-[50px]"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {namespaces.map((ns) => (
                    <TableRow key={ns.name}>
                      <TableCell>
                        <Badge variant="outline">{ns.name}</Badge>
                      </TableCell>
                      <TableCell>{ns.key_count}</TableCell>
                      <TableCell>
                        {ns.policies.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {ns.policies.map((policy) => (
                              <Badge key={policy} variant="secondary" className="text-xs">
                                {policy}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {formatDate(ns.created_at)}
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem asChild>
                              <Link href={`/keys?namespace=${ns.name}`}>
                                <Eye className="mr-2 h-4 w-4" />
                                View Keys
                              </Link>
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              onClick={() => handleDelete(ns.name)}
                              className="text-destructive focus:text-destructive"
                              disabled={ns.name === "default"}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </PageContainer>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Namespace</DialogTitle>
            <DialogDescription>
              Create a new namespace to organize your keys
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                placeholder="my-namespace"
                value={name}
                onChange={(e) => setName(e.target.value.toLowerCase())}
              />
              <p className="text-xs text-muted-foreground">
                Lowercase alphanumeric with hyphens (e.g., my-namespace)
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleCreate}
              disabled={!name}
              loading={isCreating}
            >
              Create Namespace
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
