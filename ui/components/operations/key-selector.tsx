"use client";

import { useEffect, useState } from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { hsmApi } from "@/lib/api";
import { algorithmDisplayName, truncateMiddle } from "@/lib/utils";
import type { Key } from "@/lib/types";

interface KeySelectorProps {
  value: string;
  onChange: (value: string) => void;
  filterType?: "signing" | "encryption" | "all";
  label?: string;
}

const signingAlgorithms = ["ED25519", "ECDSA_P256", "ECDSA_P384", "RSA2048", "RSA3072", "RSA4096"];
const encryptionAlgorithms = ["AES128", "AES256"];

export function KeySelector({
  value,
  onChange,
  filterType = "all",
  label = "Select Key",
}: KeySelectorProps) {
  const [keys, setKeys] = useState<Key[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchKeys = async () => {
      setIsLoading(true);
      try {
        const response = await hsmApi.listKeys();
        if (response.data) {
          let filteredKeys = response.data.keys.filter((k) => k.active);

          if (filterType === "signing") {
            filteredKeys = filteredKeys.filter((k) =>
              signingAlgorithms.includes(k.algorithm)
            );
          } else if (filterType === "encryption") {
            filteredKeys = filteredKeys.filter((k) =>
              encryptionAlgorithms.includes(k.algorithm)
            );
          }

          setKeys(filteredKeys);
        }
      } catch (error) {
        console.error("Failed to fetch keys:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchKeys();
  }, [filterType]);

  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <Select value={value} onValueChange={onChange} disabled={isLoading}>
        <SelectTrigger>
          <SelectValue placeholder={isLoading ? "Loading keys..." : "Select a key"} />
        </SelectTrigger>
        <SelectContent>
          {keys.length === 0 ? (
            <div className="p-2 text-sm text-muted-foreground">
              No {filterType !== "all" ? filterType : ""} keys available
            </div>
          ) : (
            keys.map((key) => (
              <SelectItem key={key.key_id} value={key.key_id}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs">
                    {truncateMiddle(key.key_id, 16)}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    ({algorithmDisplayName(key.algorithm)})
                  </span>
                </div>
              </SelectItem>
            ))
          )}
        </SelectContent>
      </Select>
    </div>
  );
}
