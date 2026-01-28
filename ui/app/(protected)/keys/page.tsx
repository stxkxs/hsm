"use client";

import { useState } from "react";
import { Plus, RefreshCw } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { KeyList } from "@/components/keys/key-list";
import { CreateKeyDialog } from "@/components/keys/create-key-dialog";
import { DeleteKeyDialog } from "@/components/keys/delete-key-dialog";
import { useKeys } from "@/hooks/use-keys";
import { useToast } from "@/context/toast-context";
import { hsmApi } from "@/lib/api";

export default function KeysPage() {
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [deleteKeyId, setDeleteKeyId] = useState<string | null>(null);
  const { keys, isLoading, refetch } = useKeys();
  const { success, error } = useToast();

  const filteredKeys = keys.filter(
    (key) =>
      key.key_id.toLowerCase().includes(search.toLowerCase()) ||
      key.namespace.toLowerCase().includes(search.toLowerCase()) ||
      key.algorithm.toLowerCase().includes(search.toLowerCase())
  );

  const handleRotate = async (keyId: string) => {
    try {
      const response = await hsmApi.rotateKey(keyId);
      if (response.data) {
        success("Key Rotated", `New key ${response.data.key_id} created`);
        refetch();
      } else if (response.error) {
        error("Failed to rotate key", response.error.message);
      }
    } catch (err) {
      error("Failed to rotate key", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <>
      <Header
        title="Keys"
        description="Manage cryptographic keys"
        action={
          <Button
            variant="primary"
            icon={<Plus className="h-4 w-4" />}
            onClick={() => setCreateOpen(true)}
          >
            Create Key
          </Button>
        }
      />
      <PageContainer>
        <Card>
          <div className="flex items-center justify-between gap-4 p-4 border-b">
            <Input
              placeholder="Search keys..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="max-w-sm"
            />
            <Button
              variant="ghost"
              size="icon"
              onClick={refetch}
              disabled={isLoading}
            >
              <RefreshCw
                className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
              />
            </Button>
          </div>

          {isLoading ? (
            <div className="p-8 text-center">
              <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : (
            <KeyList
              keys={filteredKeys}
              onDelete={setDeleteKeyId}
              onRotate={handleRotate}
            />
          )}
        </Card>
      </PageContainer>

      <CreateKeyDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onSuccess={refetch}
      />

      <DeleteKeyDialog
        keyId={deleteKeyId}
        open={!!deleteKeyId}
        onOpenChange={(open) => !open && setDeleteKeyId(null)}
        onSuccess={refetch}
      />
    </>
  );
}
