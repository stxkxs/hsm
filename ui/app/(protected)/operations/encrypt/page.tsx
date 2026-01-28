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

export default function EncryptPage() {
  const [keyId, setKeyId] = useState("");
  const [plaintext, setPlaintext] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{
    ciphertext?: string;
    nonce?: string;
    key_id?: string;
    error?: string;
  } | null>(null);

  const handleEncrypt = async () => {
    if (!keyId || !plaintext) return;

    setIsLoading(true);
    setResult(null);

    try {
      const response = await hsmApi.encrypt(keyId, { plaintext: btoa(plaintext) });
      if (response.data) {
        setResult({
          ciphertext: response.data.ciphertext,
          nonce: response.data.nonce,
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
      <Header title="Encrypt Data" description="Encrypt data using a key" />
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
                filterType="encryption"
                label="Encryption Key"
              />

              <div className="space-y-2">
                <Label htmlFor="plaintext">Plaintext</Label>
                <Textarea
                  id="plaintext"
                  placeholder="Enter the data you want to encrypt..."
                  value={plaintext}
                  onChange={(e) => setPlaintext(e.target.value)}
                  className="min-h-[200px] font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  Data will be base64 encoded before encryption
                </p>
              </div>

              <Button
                variant="primary"
                className="w-full"
                onClick={handleEncrypt}
                disabled={!keyId || !plaintext}
                loading={isLoading}
              >
                Encrypt Data
              </Button>
            </CardContent>
          </Card>

          <div>
            {result && (
              <OperationResult
                title="Encryption Result"
                data={
                  result.error
                    ? undefined
                    : {
                        ciphertext: result.ciphertext!,
                        nonce: result.nonce!,
                        key_id: result.key_id!,
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
