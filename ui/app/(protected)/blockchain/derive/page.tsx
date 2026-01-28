"use client";

import { useState, useEffect } from "react";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { OperationResult } from "@/components/operations/operation-result";
import { hsmApi } from "@/lib/api";
import { truncateMiddle } from "@/lib/utils";
import { chains, buildBip44Path } from "@/config/chains";
import type { Wallet } from "@/lib/types";

export default function DerivePage() {
  const [wallets, setWallets] = useState<Wallet[]>([]);
  const [walletId, setWalletId] = useState("");
  const [chainId, setChainId] = useState("ethereum");
  const [account, setAccount] = useState("0");
  const [change, setChange] = useState("0");
  const [index, setIndex] = useState("0");
  const [customPath, setCustomPath] = useState("");
  const [useCustomPath, setUseCustomPath] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingWallets, setIsLoadingWallets] = useState(true);
  const [result, setResult] = useState<{
    key_id?: string;
    public_key?: string;
    path?: string;
    error?: string;
  } | null>(null);

  useEffect(() => {
    const fetchWallets = async () => {
      setIsLoadingWallets(true);
      try {
        const response = await hsmApi.listWallets();
        if (response.data) {
          setWallets(response.data);
        }
      } catch (err) {
        console.error("Failed to fetch wallets:", err);
      } finally {
        setIsLoadingWallets(false);
      }
    };
    fetchWallets();
  }, []);

  const selectedChain = chains.find((c) => c.id === chainId);
  const derivationPath = useCustomPath
    ? customPath
    : buildBip44Path(
        selectedChain?.bip44CoinType ?? 60,
        parseInt(account) || 0,
        parseInt(change) || 0,
        parseInt(index) || 0
      );

  const handleDerive = async () => {
    if (!walletId || !derivationPath) return;

    setIsLoading(true);
    setResult(null);

    try {
      const response = await hsmApi.deriveKey(walletId, { path: derivationPath });
      if (response.data) {
        setResult({
          key_id: response.data.key_id,
          public_key: response.data.public_key,
          path: response.data.path,
        });
      } else if (response.error) {
        setResult({ error: response.error.message });
      }
    } catch (err) {
      setResult({ error: err instanceof Error ? err.message : "Unknown error" });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <Header
        title="Derive Keys"
        description="Derive child keys using BIP-32/44 paths"
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

        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Derivation Settings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Wallet</Label>
                <Select value={walletId} onValueChange={setWalletId}>
                  <SelectTrigger>
                    <SelectValue placeholder={isLoadingWallets ? "Loading..." : "Select wallet"} />
                  </SelectTrigger>
                  <SelectContent>
                    {wallets.map((wallet) => (
                      <SelectItem key={wallet.id} value={wallet.id}>
                        {wallet.name || truncateMiddle(wallet.id, 16)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center gap-4">
                <Button
                  variant={!useCustomPath ? "primary" : "ghost"}
                  size="sm"
                  onClick={() => setUseCustomPath(false)}
                >
                  BIP-44 Builder
                </Button>
                <Button
                  variant={useCustomPath ? "primary" : "ghost"}
                  size="sm"
                  onClick={() => setUseCustomPath(true)}
                >
                  Custom Path
                </Button>
              </div>

              {!useCustomPath ? (
                <>
                  <div className="space-y-2">
                    <Label>Chain</Label>
                    <Select value={chainId} onValueChange={setChainId}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {chains.map((chain) => (
                          <SelectItem key={chain.id} value={chain.id}>
                            {chain.name} ({chain.symbol})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="account">Account</Label>
                      <Input
                        id="account"
                        type="number"
                        min="0"
                        value={account}
                        onChange={(e) => setAccount(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="change">Change</Label>
                      <Input
                        id="change"
                        type="number"
                        min="0"
                        max="1"
                        value={change}
                        onChange={(e) => setChange(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="index">Index</Label>
                      <Input
                        id="index"
                        type="number"
                        min="0"
                        value={index}
                        onChange={(e) => setIndex(e.target.value)}
                      />
                    </div>
                  </div>
                </>
              ) : (
                <div className="space-y-2">
                  <Label htmlFor="customPath">Custom Path</Label>
                  <Input
                    id="customPath"
                    placeholder="m/44'/60'/0'/0/0"
                    value={customPath}
                    onChange={(e) => setCustomPath(e.target.value)}
                    className="font-mono"
                  />
                </div>
              )}

              <div className="rounded-lg bg-muted p-3">
                <p className="text-sm text-muted-foreground">Derivation Path:</p>
                <code className="text-sm font-mono">{derivationPath}</code>
              </div>

              <Button
                variant="primary"
                className="w-full"
                onClick={handleDerive}
                disabled={!walletId || !derivationPath}
                loading={isLoading}
              >
                Derive Key
              </Button>
            </CardContent>
          </Card>

          <div>
            {result && (
              <OperationResult
                title="Derived Key"
                data={
                  result.error
                    ? undefined
                    : {
                        key_id: result.key_id!,
                        path: result.path!,
                        public_key: result.public_key!,
                      }
                }
                error={result.error}
              />
            )}
          </div>
        </div>
      </PageContainer>
    </>
  );
}
