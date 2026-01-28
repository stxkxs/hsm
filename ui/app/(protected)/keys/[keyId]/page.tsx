"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, Trash2 } from "lucide-react";
import Link from "next/link";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Button } from "@/components/ui/button";
import { KeyDetail } from "@/components/keys/key-detail";
import { DeleteKeyDialog } from "@/components/keys/delete-key-dialog";
import { useKey } from "@/hooks/use-keys";

export default function KeyDetailPage() {
  const params = useParams();
  const router = useRouter();
  const keyId = params.keyId as string;
  const { key, isLoading, error } = useKey(keyId);
  const [deleteOpen, setDeleteOpen] = useState(false);

  if (isLoading) {
    return (
      <>
        <Header title="Loading..." />
        <PageContainer>
          <div className="flex items-center justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          </div>
        </PageContainer>
      </>
    );
  }

  if (error || !key) {
    return (
      <>
        <Header title="Key Not Found" />
        <PageContainer>
          <div className="flex flex-col items-center justify-center py-12">
            <p className="text-muted-foreground mb-4">
              {error || "Key not found"}
            </p>
            <Link href="/keys">
              <Button variant="ghost">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to Keys
              </Button>
            </Link>
          </div>
        </PageContainer>
      </>
    );
  }

  return (
    <>
      <Header
        title="Key Details"
        description={keyId}
        action={
          <Button
            variant="destructive"
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        }
      />
      <PageContainer>
        <div className="mb-4">
          <Link href="/keys">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Keys
            </Button>
          </Link>
        </div>
        <KeyDetail keyData={key} />
      </PageContainer>

      <DeleteKeyDialog
        keyId={keyId}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        onSuccess={() => router.push("/keys")}
      />
    </>
  );
}
