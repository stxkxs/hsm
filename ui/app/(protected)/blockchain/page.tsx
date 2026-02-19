"use client";

import Link from "next/link";
import { Wallet, Key, PenTool, MapPin, ArrowRight } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent } from "@/components/ui/card";

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
        <div className="grid gap-3 md:grid-cols-2 animate-fade-in-up">
          {features.map((feature) => (
            <Link key={feature.href} href={feature.href}>
              <Card className="h-full card-hover-glow transition-all duration-200 hover:translate-y-[-1px] cursor-pointer group">
                <CardContent className="flex items-center gap-4 py-5 px-5">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <feature.icon className="h-5 w-5 text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{feature.title}</p>
                    <p className="text-xs text-muted-foreground">{feature.description}</p>
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
