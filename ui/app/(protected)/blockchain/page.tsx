"use client";

import Link from "next/link";
import { Wallet, Key, PenTool, MapPin } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const features = [
  {
    title: "Wallets",
    description: "Create and manage HD wallets from BIP-39 mnemonics",
    href: "/blockchain/wallets",
    icon: Wallet,
  },
  {
    title: "Derive Keys",
    description: "Derive child keys using BIP-32/44 paths",
    href: "/blockchain/derive",
    icon: Key,
  },
  {
    title: "Sign",
    description: "Sign messages with EIP-191 or typed data with EIP-712",
    href: "/blockchain/sign",
    icon: PenTool,
  },
  {
    title: "Addresses",
    description: "Generate multi-chain addresses from keys",
    href: "/blockchain/addresses",
    icon: MapPin,
  },
];

export default function BlockchainPage() {
  return (
    <>
      <Header
        title="Blockchain"
        description="HD wallets, key derivation, and Web3 signing"
      />
      <PageContainer>
        <div className="grid gap-4 md:grid-cols-2">
          {features.map((feature) => (
            <Link key={feature.href} href={feature.href}>
              <Card className="h-full hover:border-primary/50 transition-colors cursor-pointer">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                      <feature.icon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="text-lg">{feature.title}</CardTitle>
                      <CardDescription>{feature.description}</CardDescription>
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
