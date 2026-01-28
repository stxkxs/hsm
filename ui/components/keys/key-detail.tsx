"use client";

import { Copy } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/context/toast-context";
import { algorithmDisplayName, formatDate, copyToClipboard } from "@/lib/utils";
import type { Key } from "@/lib/types";

interface KeyDetailProps {
  keyData: Key;
}

export function KeyDetail({ keyData }: KeyDetailProps) {
  const { success } = useToast();

  const handleCopy = async (text: string, label: string) => {
    await copyToClipboard(text);
    success("Copied", `${label} copied to clipboard`);
  };

  const getStatusBadge = (active: boolean) => {
    return active
      ? <Badge variant="success">Active</Badge>
      : <Badge variant="secondary">Inactive</Badge>;
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Key Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <p className="text-sm text-muted-foreground">Key ID</p>
              <div className="flex items-center gap-2">
                <code className="text-sm font-mono break-all">{keyData.key_id}</code>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 shrink-0"
                  onClick={() => handleCopy(keyData.key_id, "Key ID")}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Status</p>
              <div className="mt-1">{getStatusBadge(keyData.active)}</div>
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Algorithm</p>
              <p className="font-medium">
                {algorithmDisplayName(keyData.algorithm)}
              </p>
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Namespace</p>
              <Badge variant="outline">{keyData.namespace}</Badge>
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Purpose</p>
              <p className="font-medium">{keyData.purpose}</p>
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Created</p>
              <p className="font-medium">{formatDate(keyData.created_at)}</p>
            </div>

            {keyData.last_used && (
              <div>
                <p className="text-sm text-muted-foreground">Last Used</p>
                <p className="font-medium">{formatDate(keyData.last_used)}</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {keyData.public_key && (
        <Card>
          <CardHeader>
            <CardTitle>Public Key</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="relative">
              <pre className="rounded-lg bg-muted p-4 text-sm font-mono overflow-x-auto break-all whitespace-pre-wrap">
                {keyData.public_key}
              </pre>
              <Button
                variant="ghost"
                size="icon"
                className="absolute right-2 top-2"
                onClick={() => handleCopy(keyData.public_key!, "Public key")}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {Object.keys(keyData.labels).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Labels</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {Object.entries(keyData.labels).map(([key, value]) => (
                <Badge key={key} variant="outline">
                  {key}: {value}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
