"use client";

import Link from "next/link";
import { MoreHorizontal, Copy, Trash2, RotateCcw, Eye, KeyRound } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/context/toast-context";
import { algorithmDisplayName, formatDate, truncateMiddle, copyToClipboard } from "@/lib/utils";
import type { Key } from "@/lib/types";

interface KeyListProps {
  keys: Key[];
  onDelete?: (keyId: string) => void;
  onRotate?: (keyId: string) => void;
}

export function KeyList({ keys, onDelete, onRotate }: KeyListProps) {
  const { success } = useToast();

  const handleCopyId = async (keyId: string) => {
    await copyToClipboard(keyId);
    success("Copied", "Key ID copied to clipboard");
  };

  const getStatusBadge = (active: boolean) => {
    return active
      ? <Badge variant="success">Active</Badge>
      : <Badge variant="secondary">Inactive</Badge>;
  };

  if (keys.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted mb-4">
          <KeyRound className="h-6 w-6 text-muted-foreground" />
        </div>
        <p className="text-sm font-medium text-foreground">No keys found</p>
        <p className="text-xs text-muted-foreground mt-1">
          Create a new cryptographic key to get started
        </p>
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Key ID</TableHead>
          <TableHead>Algorithm</TableHead>
          <TableHead>Namespace</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Created</TableHead>
          <TableHead className="w-[50px]"></TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {keys.map((key) => (
          <TableRow key={key.key_id} className="table-row-hover">
            <TableCell>
              <div className="flex items-center gap-2">
                <code className="text-sm font-mono">
                  {truncateMiddle(key.key_id, 20)}
                </code>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6"
                  onClick={() => handleCopyId(key.key_id)}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            </TableCell>
            <TableCell>{algorithmDisplayName(key.algorithm)}</TableCell>
            <TableCell>
              <Badge variant="outline">{key.namespace}</Badge>
            </TableCell>
            <TableCell>{getStatusBadge(key.active)}</TableCell>
            <TableCell className="text-muted-foreground">
              {formatDate(key.created_at)}
            </TableCell>
            <TableCell>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8">
                    <MoreHorizontal className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem asChild>
                    <Link href={`/keys/${key.key_id}`}>
                      <Eye className="mr-2 h-4 w-4" />
                      View Details
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => handleCopyId(key.key_id)}>
                    <Copy className="mr-2 h-4 w-4" />
                    Copy ID
                  </DropdownMenuItem>
                  {key.active && onRotate && (
                    <DropdownMenuItem onClick={() => onRotate(key.key_id)}>
                      <RotateCcw className="mr-2 h-4 w-4" />
                      Rotate Key
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuSeparator />
                  {onDelete && (
                    <DropdownMenuItem
                      onClick={() => onDelete(key.key_id)}
                      className="text-destructive focus:text-destructive"
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Delete
                    </DropdownMenuItem>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
