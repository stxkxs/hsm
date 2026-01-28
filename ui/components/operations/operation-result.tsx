"use client";

import { Copy, Check, X } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/context/toast-context";
import { copyToClipboard } from "@/lib/utils";

interface OperationResultProps {
  title: string;
  data?: Record<string, string | boolean | number>;
  success?: boolean;
  error?: string;
}

export function OperationResult({
  title,
  data,
  success,
  error,
}: OperationResultProps) {
  const { success: showSuccess } = useToast();

  const handleCopy = async (value: string, label: string) => {
    await copyToClipboard(value);
    showSuccess("Copied", `${label} copied to clipboard`);
  };

  if (error) {
    return (
      <Card className="border-destructive">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <X className="h-5 w-5" />
            {title} Failed
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-destructive">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!data) return null;

  return (
    <Card className={success === false ? "border-destructive" : "border-success"}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {success !== false ? (
            <Check className="h-5 w-5 text-success" />
          ) : (
            <X className="h-5 w-5 text-destructive" />
          )}
          {title}
          {typeof success === "boolean" && (
            <Badge variant={success ? "success" : "destructive"}>
              {success ? "Valid" : "Invalid"}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {Object.entries(data).map(([key, value]) => (
          <div key={key}>
            <p className="text-sm text-muted-foreground capitalize mb-1">
              {key.replace(/_/g, " ")}
            </p>
            {typeof value === "boolean" ? (
              <Badge variant={value ? "success" : "destructive"}>
                {value ? "True" : "False"}
              </Badge>
            ) : typeof value === "string" && value.length > 50 ? (
              <div className="relative">
                <pre className="rounded-lg bg-muted p-3 text-sm font-mono overflow-x-auto break-all whitespace-pre-wrap">
                  {value}
                </pre>
                <Button
                  variant="ghost"
                  size="icon"
                  className="absolute right-2 top-2"
                  onClick={() => handleCopy(value, key)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <code className="text-sm font-mono">{String(value)}</code>
                {typeof value === "string" && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6"
                    onClick={() => handleCopy(value, key)}
                  >
                    <Copy className="h-3 w-3" />
                  </Button>
                )}
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
