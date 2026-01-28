"use client";

import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/context/toast-context";
import { hsmApi } from "@/lib/api";

interface DeleteKeyDialogProps {
  keyId: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

export function DeleteKeyDialog({
  keyId,
  open,
  onOpenChange,
  onSuccess,
}: DeleteKeyDialogProps) {
  const [confirmation, setConfirmation] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { success, error } = useToast();

  const handleDelete = async () => {
    if (!keyId || confirmation !== "DELETE") return;

    setIsLoading(true);
    try {
      const response = await hsmApi.deleteKey(keyId);
      if (response.error) {
        error("Failed to delete key", response.error.message);
      } else {
        success("Key Deleted", `Key ${keyId} has been deleted`);
        setConfirmation("");
        onOpenChange(false);
        onSuccess?.();
      }
    } catch (err) {
      error("Failed to delete key", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-destructive">Delete Key</DialogTitle>
          <DialogDescription>
            This action cannot be undone. This will permanently delete the key
            and all associated data.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="rounded-lg bg-destructive/10 p-3">
            <p className="text-sm font-mono break-all">{keyId}</p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirmation">
              Type <span className="font-mono font-bold">DELETE</span> to
              confirm
            </Label>
            <Input
              id="confirmation"
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              placeholder="DELETE"
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={handleDelete}
            disabled={confirmation !== "DELETE"}
            loading={isLoading}
          >
            Delete Key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
