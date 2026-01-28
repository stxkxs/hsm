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
import { KeySelector } from "@/components/operations/key-selector";
import { OperationResult } from "@/components/operations/operation-result";
import { hsmApi } from "@/lib/api";

export default function SignPage() {
  const [keyId, setKeyId] = useState("");
  const [data, setData] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{
    signature?: string;
    key_id?: string;
    algorithm?: string;
    error?: string;
  } | null>(null);

  const handleSign = async () => {
    if (!keyId || !data) return;

    setIsLoading(true);
    setResult(null);

    try {
      const response = await hsmApi.sign(keyId, { data: btoa(data) });
      if (response.data) {
        setResult({
          signature: response.data.signature,
          key_id: keyId,  // Use the selected key_id since backend doesn't return it
          algorithm: response.data.algorithm,
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
      <Header title="Sign Data" description="Create a digital signature" />
      <PageContainer>
        <div className="mb-4">
          <Link href="/operations">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Operations
            </Button>
          </Link>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Input</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <KeySelector
                value={keyId}
                onChange={setKeyId}
                filterType="signing"
                label="Signing Key"
              />

              <div className="space-y-2">
                <Label htmlFor="data">Data to Sign</Label>
                <Textarea
                  id="data"
                  placeholder="Enter the data you want to sign..."
                  value={data}
                  onChange={(e) => setData(e.target.value)}
                  className="min-h-[200px] font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  Data will be base64 encoded before signing
                </p>
              </div>

              <Button
                variant="primary"
                className="w-full"
                onClick={handleSign}
                disabled={!keyId || !data}
                loading={isLoading}
              >
                Sign Data
              </Button>
            </CardContent>
          </Card>

          <div>
            {result && (
              <OperationResult
                title="Signature Result"
                data={
                  result.error
                    ? undefined
                    : {
                        signature: result.signature!,
                        key_id: result.key_id!,
                        algorithm: result.algorithm!,
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
