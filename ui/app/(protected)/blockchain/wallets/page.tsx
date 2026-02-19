"use client";

import { useState, useEffect } from "react";
import { ArrowLeft, Plus, RefreshCw } from "lucide-react";
import Link from "next/link";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/context/toast-context";
import { hsmApi } from "@/lib/api";
import { formatDate, truncateMiddle } from "@/lib/utils";
import type { Wallet } from "@/lib/types";

export default function WalletsPage() {
  const [wallets, setWallets] = useState<Wallet[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [mnemonic, setMnemonic] = useState("");
  const [name, setName] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const { success, error } = useToast();

  const fetchWallets = async () => {
    setIsLoading(true);
    try {
      const response = await hsmApi.listWallets();
      if (response.data) {
        setWallets(response.data);
      }
    } catch (err) {
      console.error("Failed to fetch wallets:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchWallets();
  }, []);

  const handleCreate = async () => {
    if (!mnemonic) return;

    setIsCreating(true);
    try {
      const response = await hsmApi.createWallet(mnemonic, name || undefined);
      if (response.data) {
        success("Wallet Created", `Wallet ${response.data.id} created successfully`);
        setMnemonic("");
        setName("");
        setCreateOpen(false);
        fetchWallets();
      } else if (response.error) {
        error("Failed to create wallet", response.error.message);
      }
    } catch (err) {
      error("Failed to create wallet", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <>
      <Header
        title="HD Wallets"
        description="Manage hierarchical deterministic wallets"
        action={
          <Button
            variant="primary"
            icon={<Plus className="h-4 w-4" />}
            onClick={() => setCreateOpen(true)}
          >
            Create Wallet
          </Button>
        }
      />
      <PageContainer>
        <div className="mb-4">
          <Link href="/blockchain">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Blockchain
            </Button>
          </Link>
        </div>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Wallets</CardTitle>
            <Button
              variant="ghost"
              size="icon"
              onClick={fetchWallets}
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
            ) : wallets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted mb-4">
                  <Plus className="h-6 w-6 text-muted-foreground" />
                </div>
                <p className="text-sm font-medium text-foreground">No wallets found</p>
                <p className="text-xs text-muted-foreground mt-1">Create a wallet from a BIP-39 mnemonic</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Wallet ID</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Derived Keys</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {wallets.map((wallet) => (
                    <TableRow key={wallet.id}>
                      <TableCell>
                        <code className="text-sm font-mono">
                          {truncateMiddle(wallet.id, 20)}
                        </code>
                      </TableCell>
                      <TableCell>{wallet.name || "-"}</TableCell>
                      <TableCell>{wallet.derived_keys_count}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {formatDate(wallet.created_at)}
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
            <DialogTitle>Create HD Wallet</DialogTitle>
            <DialogDescription>
              Import a BIP-39 mnemonic to create a hierarchical deterministic wallet
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Wallet Name (optional)</Label>
              <Input
                id="name"
                placeholder="My Wallet"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="mnemonic">BIP-39 Mnemonic</Label>
              <Textarea
                id="mnemonic"
                placeholder="Enter your 12 or 24 word mnemonic..."
                value={mnemonic}
                onChange={(e) => setMnemonic(e.target.value)}
                className="min-h-[100px] font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Your mnemonic is encrypted and stored securely in the HSM
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
              disabled={!mnemonic}
              loading={isCreating}
            >
              Create Wallet
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
