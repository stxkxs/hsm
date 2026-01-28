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

export default function VerifyPage() {
  const [keyId, setKeyId] = useState("");
  const [data, setData] = useState("");
  const [signature, setSignature] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{
    valid?: boolean;
    key_id?: string;
    error?: string;
  } | null>(null);

  const handleVerify = async () => {
    if (!keyId || !data || !signature) return;

    setIsLoading(true);
    setResult(null);

    try {
      const response = await hsmApi.verify(keyId, {
        data: btoa(data),
        signature,
      });
      if (response.data) {
        setResult({
          valid: response.data.valid,
          key_id: keyId,  // Use the selected key_id since backend doesn't return it
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
      <Header title="Verify Signature" description="Verify a digital signature" />
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
                label="Verification Key"
              />

              <div className="space-y-2">
                <Label htmlFor="data">Original Data</Label>
                <Textarea
                  id="data"
                  placeholder="Enter the original data..."
                  value={data}
                  onChange={(e) => setData(e.target.value)}
                  className="min-h-[120px] font-mono"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="signature">Signature</Label>
                <Textarea
                  id="signature"
                  placeholder="Enter the signature (base64)..."
                  value={signature}
                  onChange={(e) => setSignature(e.target.value)}
                  className="min-h-[120px] font-mono"
                />
              </div>

              <Button
                variant="primary"
                className="w-full"
                onClick={handleVerify}
                disabled={!keyId || !data || !signature}
                loading={isLoading}
              >
                Verify Signature
              </Button>
            </CardContent>
          </Card>

          <div>
            {result && (
              <OperationResult
                title="Verification Result"
                data={
                  result.error
                    ? undefined
                    : {
                        valid: result.valid!,
                        key_id: result.key_id!,
                      }
                }
                success={result.valid}
                error={result.error}
              />
            )}
          </div>
        </div>
      </PageContainer>
    </>
  );
}
