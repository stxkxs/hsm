"use client";

import { motion } from "framer-motion";
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

// Spring tuned to feel responsive without bouncing — signals resolution, not playfulness.
const resultSpring = { type: "spring" as const, stiffness: 380, damping: 30 };
const iconSpring = { type: "spring" as const, stiffness: 600, damping: 22 };

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
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={resultSpring}
      >
        <Card className="border-destructive" role="status" aria-live="polite">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <motion.span
                initial={{ scale: 0.6, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={iconSpring}
                className="inline-flex"
              >
                <X className="h-5 w-5" />
              </motion.span>
              {title} Failed
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-destructive">{error}</p>
          </CardContent>
        </Card>
      </motion.div>
    );
  }

  if (!data) return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={resultSpring}
    >
      <Card
        className={success === false ? "border-destructive" : "border-success"}
        role="status"
        aria-live="polite"
      >
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <motion.span
            initial={{ scale: 0.6, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={iconSpring}
            className="inline-flex"
          >
            {success !== false ? (
              <Check className="h-5 w-5 text-success" />
            ) : (
              <X className="h-5 w-5 text-destructive" />
            )}
          </motion.span>
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
    </motion.div>
  );
}
