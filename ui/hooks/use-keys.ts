"use client";

import { useState, useEffect, useCallback } from "react";
import { hsmApi } from "@/lib/api";
import type { Key } from "@/lib/types";

export function useKeys(namespace?: string) {
  const [keys, setKeys] = useState<Key[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchKeys = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await hsmApi.listKeys(namespace);
      if (response.data) {
        setKeys(response.data.keys);
      } else if (response.error) {
        setError(response.error.message);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch keys");
    } finally {
      setIsLoading(false);
    }
  }, [namespace]);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  return { keys, isLoading, error, refetch: fetchKeys };
}

export function useKey(keyId: string) {
  const [key, setKey] = useState<Key | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchKey = useCallback(async () => {
    if (!keyId) return;
    setIsLoading(true);
    setError(null);
    try {
      const response = await hsmApi.getKey(keyId);
      if (response.data) {
        setKey(response.data);
      } else if (response.error) {
        setError(response.error.message);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch key");
    } finally {
      setIsLoading(false);
    }
  }, [keyId]);

  useEffect(() => {
    fetchKey();
  }, [fetchKey]);

  return { key, isLoading, error, refetch: fetchKey };
}
