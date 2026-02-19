"use client";

import { useState, useEffect } from "react";
import { Plus, RefreshCw, MoreHorizontal, Trash2, Upload } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/context/toast-context";
import { hsmApi } from "@/lib/api";
import { formatDate, truncateMiddle, formatBytes } from "@/lib/utils";
import type { Policy } from "@/lib/types";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [wasmFile, setWasmFile] = useState<File | null>(null);
  const [fuelLimit, setFuelLimit] = useState("1000000");
  const [memoryLimit, setMemoryLimit] = useState("1048576");
  const [isCreating, setIsCreating] = useState(false);
  const { success, error } = useToast();

  const fetchPolicies = async () => {
    setIsLoading(true);
    try {
      const response = await hsmApi.listPolicies();
      if (response.data) {
        setPolicies(response.data);
      }
    } catch (err) {
      console.error("Failed to fetch policies:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleCreate = async () => {
    if (!name || !wasmFile) return;

    setIsCreating(true);
    try {
      const formData = new FormData();
      formData.append("name", name);
      if (description) formData.append("description", description);
      formData.append("wasm", wasmFile);
      formData.append("fuel_limit", fuelLimit);
      formData.append("memory_limit", memoryLimit);

      const response = await hsmApi.createPolicy(formData);
      if (response.data) {
        success("Policy Created", "Policy has been created successfully");
        setName("");
        setDescription("");
        setWasmFile(null);
        setCreateOpen(false);
        fetchPolicies();
      } else if (response.error) {
        error("Failed to create policy", response.error.message);
      }
    } catch (err) {
      error("Failed to create policy", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsCreating(false);
    }
  };

  const handleDelete = async (policyId: string) => {
    try {
      const response = await hsmApi.deletePolicy(policyId);
      if (response.error) {
        error("Failed to delete policy", response.error.message);
      } else {
        success("Policy Deleted", "Policy has been deleted");
        fetchPolicies();
      }
    } catch (err) {
      error("Failed to delete policy", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <>
      <Header
        title="WASM Policies"
        description="Manage transaction validation policies"
        action={
          <Button
            variant="primary"
            icon={<Plus className="h-4 w-4" />}
            onClick={() => setCreateOpen(true)}
          >
            Create Policy
          </Button>
        }
      />
      <PageContainer>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Policies</CardTitle>
            <Button
              variant="ghost"
              size="icon"
              onClick={fetchPolicies}
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
            ) : policies.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted mb-4">
                  <Upload className="h-6 w-6 text-muted-foreground" />
                </div>
                <p className="text-sm font-medium text-foreground">No policies configured</p>
                <p className="text-xs text-muted-foreground mt-1">Upload a WASM policy to enforce transaction rules</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Namespaces</TableHead>
                    <TableHead>Limits</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="w-[50px]"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {policies.map((policy) => (
                    <TableRow key={policy.id}>
                      <TableCell className="font-medium">{policy.name}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {policy.description || "-"}
                      </TableCell>
                      <TableCell>
                        {policy.attached_namespaces.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {policy.attached_namespaces.map((ns) => (
                              <Badge key={ns} variant="outline" className="text-xs">
                                {ns}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="text-xs text-muted-foreground">
                          <div>Fuel: {policy.fuel_limit.toLocaleString()}</div>
                          <div>Memory: {formatBytes(policy.memory_limit)}</div>
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {formatDate(policy.created_at)}
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onClick={() => handleDelete(policy.id)}
                              className="text-destructive focus:text-destructive"
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
            <DialogTitle>Create Policy</DialogTitle>
            <DialogDescription>
              Upload a WASM module to create a transaction validation policy
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                placeholder="Policy name"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Description (optional)</Label>
              <Textarea
                id="description"
                placeholder="Policy description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="wasm">WASM File</Label>
              <div className="flex items-center gap-2">
                <Input
                  id="wasm"
                  type="file"
                  accept=".wasm"
                  onChange={(e) => setWasmFile(e.target.files?.[0] || null)}
                  className="flex-1"
                />
              </div>
              {wasmFile && (
                <p className="text-xs text-muted-foreground">
                  Selected: {wasmFile.name} ({formatBytes(wasmFile.size)})
                </p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="fuel">Fuel Limit</Label>
                <Input
                  id="fuel"
                  type="number"
                  value={fuelLimit}
                  onChange={(e) => setFuelLimit(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="memory">Memory Limit (bytes)</Label>
                <Input
                  id="memory"
                  type="number"
                  value={memoryLimit}
                  onChange={(e) => setMemoryLimit(e.target.value)}
                />
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleCreate}
              disabled={!name || !wasmFile}
              loading={isCreating}
            >
              Create Policy
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
