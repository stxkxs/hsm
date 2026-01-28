"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/context/toast-context";
import { hsmApi } from "@/lib/api";
import { algorithms } from "@/config/site";

const createKeySchema = z.object({
  algorithm: z.string().min(1, "Algorithm is required"),
  purpose: z.string().min(1, "Purpose is required"),
  namespace: z.string().optional(),
});

type CreateKeyFormData = z.infer<typeof createKeySchema>;

interface CreateKeyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

export function CreateKeyDialog({
  open,
  onOpenChange,
  onSuccess,
}: CreateKeyDialogProps) {
  const [isLoading, setIsLoading] = useState(false);
  const { success, error } = useToast();

  const {
    register,
    handleSubmit,
    setValue,
    reset,
    formState: { errors },
  } = useForm<CreateKeyFormData>({
    resolver: zodResolver(createKeySchema),
    defaultValues: {
      algorithm: "",
      purpose: "SIGN",
      namespace: "default",
    },
  });

  const onSubmit = async (data: CreateKeyFormData) => {
    setIsLoading(true);
    try {
      const response = await hsmApi.createKey({
        algorithm: data.algorithm,
        purpose: data.purpose,
        namespace: data.namespace || "default",
      });

      if (response.data) {
        success("Key Created", `Key ${response.data.key_id} created successfully`);
        reset();
        onOpenChange(false);
        onSuccess?.();
      } else if (response.error) {
        error("Failed to create key", response.error.message);
      }
    } catch (err) {
      error("Failed to create key", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create New Key</DialogTitle>
          <DialogDescription>
            Generate a new cryptographic key in the HSM
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="algorithm">Algorithm</Label>
            <Select
              onValueChange={(value) => setValue("algorithm", value)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select an algorithm" />
              </SelectTrigger>
              <SelectContent>
                {algorithms.map((alg) => (
                  <SelectItem key={alg.value} value={alg.value}>
                    <div className="flex items-center gap-2">
                      <span>{alg.label}</span>
                      <span className="text-xs text-muted-foreground">
                        ({alg.type})
                      </span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.algorithm && (
              <p className="text-xs text-destructive">
                {errors.algorithm.message}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="purpose">Purpose</Label>
            <Select
              defaultValue="SIGN"
              onValueChange={(value) => setValue("purpose", value)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select purpose" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="SIGN">Sign (signatures)</SelectItem>
                <SelectItem value="ENCRYPT">Encrypt (encryption)</SelectItem>
                <SelectItem value="GENERAL">General (both)</SelectItem>
              </SelectContent>
            </Select>
            {errors.purpose && (
              <p className="text-xs text-destructive">
                {errors.purpose.message}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="namespace">Namespace</Label>
            <Input
              id="namespace"
              placeholder="default"
              {...register("namespace")}
            />
            <p className="text-xs text-muted-foreground">
              Optional. Defaults to &quot;default&quot; namespace.
            </p>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={isLoading}>
              Create Key
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
