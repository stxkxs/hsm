import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: Date | string): string {
  const d = typeof date === "string" ? new Date(date) : date;
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function truncateMiddle(str: string, maxLength: number = 16): string {
  if (str.length <= maxLength) return str;
  const start = Math.ceil((maxLength - 3) / 2);
  const end = Math.floor((maxLength - 3) / 2);
  return `${str.slice(0, start)}...${str.slice(-end)}`;
}

export function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function algorithmDisplayName(algorithm: string): string {
  const names: Record<string, string> = {
    ED25519: "Ed25519",
    ECDSA_P256: "ECDSA P-256",
    ECDSA_P384: "ECDSA P-384",
    RSA2048: "RSA 2048",
    RSA3072: "RSA 3072",
    RSA4096: "RSA 4096",
    AES128: "AES-128",
    AES256: "AES-256",
  };
  return names[algorithm] || algorithm;
}

export function keyStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "active":
      return "text-success";
    case "inactive":
    case "deactivated":
      return "text-muted-foreground";
    case "destroyed":
      return "text-destructive";
    default:
      return "text-foreground";
  }
}
