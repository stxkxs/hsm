import {
  Key,
  Shield,
  FileText,
  Webhook,
  FileCode,
  FolderKey,
  Settings,
  LayoutDashboard,
  Wallet,
} from "lucide-react";

export interface NavItem {
  title: string;
  href: string;
  icon: typeof Key;
  description?: string;
  children?: NavItem[];
}

export const navigation: NavItem[] = [
  {
    title: "Dashboard",
    href: "/",
    icon: LayoutDashboard,
    description: "Overview and quick actions",
  },
  {
    title: "Keys",
    href: "/keys",
    icon: Key,
    description: "Manage cryptographic keys",
  },
  {
    title: "Operations",
    href: "/operations",
    icon: Shield,
    description: "Sign, verify, encrypt, decrypt",
  },
  {
    title: "Blockchain",
    href: "/blockchain",
    icon: Wallet,
    description: "HD wallets and Web3 signing",
  },
  {
    title: "Audit Log",
    href: "/audit",
    icon: FileText,
    description: "View security audit trail",
  },
  {
    title: "Webhooks",
    href: "/webhooks",
    icon: Webhook,
    description: "Manage event notifications",
  },
  {
    title: "Policies",
    href: "/policies",
    icon: FileCode,
    description: "WASM transaction policies",
  },
  {
    title: "Namespaces",
    href: "/namespaces",
    icon: FolderKey,
    description: "Organize keys by namespace",
  },
  {
    title: "Settings",
    href: "/settings",
    icon: Settings,
    description: "Application settings",
  },
];

export const operationsSubNav: NavItem[] = [
  {
    title: "Sign",
    href: "/operations/sign",
    icon: Shield,
    description: "Sign data with a key",
  },
  {
    title: "Verify",
    href: "/operations/verify",
    icon: Shield,
    description: "Verify a signature",
  },
  {
    title: "Encrypt",
    href: "/operations/encrypt",
    icon: Shield,
    description: "Encrypt data",
  },
  {
    title: "Decrypt",
    href: "/operations/decrypt",
    icon: Shield,
    description: "Decrypt data",
  },
];

export const blockchainSubNav: NavItem[] = [
  {
    title: "Wallets",
    href: "/blockchain/wallets",
    icon: Wallet,
    description: "HD wallet management",
  },
  {
    title: "Derive Keys",
    href: "/blockchain/derive",
    icon: Key,
    description: "BIP-32/44 key derivation",
  },
  {
    title: "Sign",
    href: "/blockchain/sign",
    icon: Shield,
    description: "EIP-191/712 signing",
  },
  {
    title: "Addresses",
    href: "/blockchain/addresses",
    icon: FolderKey,
    description: "Multi-chain addresses",
  },
];
