"use client";

import { useState } from "react";
import { ArrowLeft, Copy } from "lucide-react";
import Link from "next/link";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { KeySelector } from "@/components/operations/key-selector";
import { useToast } from "@/context/toast-context";
import { hsmApi } from "@/lib/api";
import { copyToClipboard } from "@/lib/utils";
import { chains } from "@/config/chains";

export default function AddressesPage() {
  const [keyId, setKeyId] = useState("");
  const [selectedChains, setSelectedChains] = useState<string[]>(["ethereum"]);
  const [addresses, setAddresses] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { success } = useToast();

  const toggleChain = (chainId: string) => {
    setSelectedChains((prev) =>
      prev.includes(chainId)
        ? prev.filter((c) => c !== chainId)
        : [...prev, chainId]
    );
  };

  const handleGetAddresses = async () => {
    if (!keyId || selectedChains.length === 0) return;

    setIsLoading(true);
    setError(null);
    setAddresses({});

    try {
      const response = await hsmApi.getAddresses({
        key_id: keyId,
        chains: selectedChains,
      });
      if (response.data) {
        setAddresses(response.data.addresses);
      } else if (response.error) {
        setError(response.error.message);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = async (address: string, chainName: string) => {
    await copyToClipboard(address);
    success("Copied", `${chainName} address copied to clipboard`);
  };

  return (
    <>
      <Header
        title="Multi-Chain Addresses"
        description="Generate blockchain addresses from keys"
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
              <CardTitle>Settings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <KeySelector
                value={keyId}
                onChange={setKeyId}
                filterType="signing"
                label="Key"
              />

              <div className="space-y-2">
                <p className="text-sm font-medium">Chains</p>
                <div className="flex flex-wrap gap-2">
                  {chains.map((chain) => (
                    <Badge
                      key={chain.id}
                      variant={selectedChains.includes(chain.id) ? "default" : "outline"}
                      className="cursor-pointer"
                      onClick={() => toggleChain(chain.id)}
                    >
                      {chain.name}
                    </Badge>
                  ))}
                </div>
              </div>

              <Button
                variant="primary"
                className="w-full"
                onClick={handleGetAddresses}
                disabled={!keyId || selectedChains.length === 0}
                loading={isLoading}
              >
                Get Addresses
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Addresses</CardTitle>
            </CardHeader>
            <CardContent>
              {error ? (
                <p className="text-sm text-destructive">{error}</p>
              ) : Object.keys(addresses).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Select a key and chains to generate addresses
                </p>
              ) : (
                <div className="space-y-4">
                  {Object.entries(addresses).map(([chainId, address]) => {
                    const chain = chains.find((c) => c.id === chainId);
                    return (
                      <div key={chainId} className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline">{chain?.name || chainId}</Badge>
                          <span className="text-xs text-muted-foreground">
                            {chain?.symbol}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <code className="flex-1 text-sm font-mono break-all bg-muted p-2 rounded">
                            {address}
                          </code>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleCopy(address, chain?.name || chainId)}
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
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
