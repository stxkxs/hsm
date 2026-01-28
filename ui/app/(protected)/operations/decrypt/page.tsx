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
import { Input } from "@/components/ui/input";
import { KeySelector } from "@/components/operations/key-selector";
import { OperationResult } from "@/components/operations/operation-result";
import { hsmApi } from "@/lib/api";

export default function DecryptPage() {
  const [keyId, setKeyId] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [nonce, setNonce] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{
    plaintext?: string;
    key_id?: string;
    error?: string;
  } | null>(null);

  const handleDecrypt = async () => {
    if (!keyId || !ciphertext || !nonce) return;

    setIsLoading(true);
    setResult(null);

    try {
      const response = await hsmApi.decrypt(keyId, { ciphertext, nonce });
      if (response.data) {
        // Decode base64 plaintext
        let decodedPlaintext = response.data.plaintext;
        try {
          decodedPlaintext = atob(response.data.plaintext);
        } catch {
          // Keep as-is if not base64
        }
        setResult({
          plaintext: decodedPlaintext,
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
      <Header title="Decrypt Data" description="Decrypt ciphertext using a key" />
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
                label="Decryption Key"
              />

              <div className="space-y-2">
                <Label htmlFor="ciphertext">Ciphertext</Label>
                <Textarea
                  id="ciphertext"
                  placeholder="Enter the ciphertext (base64)..."
                  value={ciphertext}
                  onChange={(e) => setCiphertext(e.target.value)}
                  className="min-h-[150px] font-mono"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="nonce">Nonce</Label>
                <Input
                  id="nonce"
                  placeholder="Enter the nonce (base64)..."
                  value={nonce}
                  onChange={(e) => setNonce(e.target.value)}
                  className="font-mono"
                />
              </div>

              <Button
                variant="primary"
                className="w-full"
                onClick={handleDecrypt}
                disabled={!keyId || !ciphertext || !nonce}
                loading={isLoading}
              >
                Decrypt Data
              </Button>
            </CardContent>
          </Card>

          <div>
            {result && (
              <OperationResult
                title="Decryption Result"
                data={
                  result.error
                    ? undefined
                    : {
                        plaintext: result.plaintext!,
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
