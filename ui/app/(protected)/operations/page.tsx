"use client";

import Link from "next/link";
import { PenTool, CheckCircle, Lock, Unlock, ArrowRight } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const operations = [
  {
    title: "Sign",
    description: "Create a digital signature using a private key",
    href: "/operations/sign",
    icon: PenTool,
  },
  {
    title: "Verify",
    description: "Verify a signature against data and public key",
    href: "/operations/verify",
    icon: CheckCircle,
  },
  {
    title: "Encrypt",
    description: "Encrypt data using a symmetric or public key",
    href: "/operations/encrypt",
    icon: Lock,
  },
  {
    title: "Decrypt",
    description: "Decrypt ciphertext using the corresponding key",
    href: "/operations/decrypt",
    icon: Unlock,
  },
];

export default function OperationsPage() {
  return (
    <>
      <Header
        title="Cryptographic Operations"
        description="Perform signing, verification, encryption, and decryption"
      />
      <PageContainer>
        <div className="grid gap-3 md:grid-cols-2 animate-fade-in-up">
          {operations.map((op) => (
            <Link key={op.href} href={op.href}>
              <Card className="h-full card-hover-glow transition-all duration-200 hover:translate-y-[-1px] cursor-pointer group">
                <CardContent className="flex items-center gap-4 py-5 px-5">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <op.icon className="h-5 w-5 text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{op.title}</p>
                    <p className="text-xs text-muted-foreground">{op.description}</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </PageContainer>
    </>
  );
}
