"use client";

import Link from "next/link";
import { PenTool, CheckCircle, Lock, Unlock } from "lucide-react";
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
        <div className="grid gap-4 md:grid-cols-2">
          {operations.map((op) => (
            <Link key={op.href} href={op.href}>
              <Card className="h-full hover:border-primary/50 transition-colors cursor-pointer">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                      <op.icon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="text-lg">{op.title}</CardTitle>
                      <CardDescription>{op.description}</CardDescription>
                    </div>
                  </div>
                </CardHeader>
              </Card>
            </Link>
          ))}
        </div>
      </PageContainer>
    </>
  );
}
