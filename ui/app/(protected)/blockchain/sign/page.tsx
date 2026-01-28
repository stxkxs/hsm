"use client";

import { useState } from "react";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeySelector } from "@/components/operations/key-selector";
import { OperationResult } from "@/components/operations/operation-result";
import { hsmApi } from "@/lib/api";

const exampleTypedData = `{
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" }
    ],
    "Message": [
      { "name": "content", "type": "string" }
    ]
  },
  "primaryType": "Message",
  "domain": {
    "name": "Example App",
    "version": "1",
    "chainId": 1
  },
  "message": {
    "content": "Hello, World!"
  }
}`;

export default function BlockchainSignPage() {
  const [keyId, setKeyId] = useState("");
  const [message, setMessage] = useState("");
  const [typedData, setTypedData] = useState(exampleTypedData);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{
    signature?: string;
    r?: string;
    s?: string;
    v?: number;
    error?: string;
  } | null>(null);

  const handleSignEip191 = async () => {
    if (!keyId || !message) return;

    setIsLoading(true);
    setResult(null);

    try {
      const response = await hsmApi.signEip191({ key_id: keyId, message });
      if (response.data) {
        setResult({
          signature: response.data.signature,
          r: response.data.r,
          s: response.data.s,
          v: response.data.v,
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

  const handleSignEip712 = async () => {
    if (!keyId || !typedData) return;

    setIsLoading(true);
    setResult(null);

    try {
      const parsed = JSON.parse(typedData);
      const response = await hsmApi.signEip712({ key_id: keyId, typed_data: parsed });
      if (response.data) {
        setResult({
          signature: response.data.signature,
          r: response.data.r,
          s: response.data.s,
          v: response.data.v,
        });
      } else if (response.error) {
        setResult({ error: response.error.message });
      }
    } catch (err) {
      if (err instanceof SyntaxError) {
        setResult({ error: "Invalid JSON in typed data" });
      } else {
        setResult({ error: err instanceof Error ? err.message : "Unknown error" });
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <Header
        title="Blockchain Signing"
        description="Sign messages with EIP-191 or typed data with EIP-712"
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
              <CardTitle>Sign</CardTitle>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="eip191">
                <TabsList className="mb-4">
                  <TabsTrigger value="eip191">EIP-191 Personal</TabsTrigger>
                  <TabsTrigger value="eip712">EIP-712 Typed Data</TabsTrigger>
                </TabsList>

                <div className="mb-4">
                  <KeySelector
                    value={keyId}
                    onChange={setKeyId}
                    filterType="signing"
                    label="Signing Key"
                  />
                </div>

                <TabsContent value="eip191" className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="message">Message</Label>
                    <Textarea
                      id="message"
                      placeholder="Enter the message to sign..."
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                      className="min-h-[150px]"
                    />
                    <p className="text-xs text-muted-foreground">
                      Message will be prefixed with &quot;\x19Ethereum Signed Message:\n&quot;
                    </p>
                  </div>

                  <Button
                    variant="primary"
                    className="w-full"
                    onClick={handleSignEip191}
                    disabled={!keyId || !message}
                    loading={isLoading}
                  >
                    Sign Message
                  </Button>
                </TabsContent>

                <TabsContent value="eip712" className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="typedData">Typed Data (JSON)</Label>
                    <Textarea
                      id="typedData"
                      placeholder="Enter EIP-712 typed data..."
                      value={typedData}
                      onChange={(e) => setTypedData(e.target.value)}
                      className="min-h-[250px] font-mono text-xs"
                    />
                  </div>

                  <Button
                    variant="primary"
                    className="w-full"
                    onClick={handleSignEip712}
                    disabled={!keyId || !typedData}
                    loading={isLoading}
                  >
                    Sign Typed Data
                  </Button>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          <div>
            {result && (
              <OperationResult
                title="Signature"
                data={
                  result.error
                    ? undefined
                    : {
                        signature: result.signature!,
                        r: result.r!,
                        s: result.s!,
                        v: result.v!,
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
