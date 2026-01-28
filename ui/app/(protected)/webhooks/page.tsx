"use client";

import { useState, useEffect } from "react";
import { Plus, RefreshCw, MoreHorizontal, Trash2, Play, ExternalLink } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/context/toast-context";
import { hsmApi } from "@/lib/api";
import { formatDate, truncateMiddle } from "@/lib/utils";
import { webhookEvents } from "@/config/site";
import type { Webhook } from "@/lib/types";

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [selectedEvents, setSelectedEvents] = useState<string[]>([]);
  const [isCreating, setIsCreating] = useState(false);
  const { success, error } = useToast();

  const fetchWebhooks = async () => {
    setIsLoading(true);
    try {
      const response = await hsmApi.listWebhooks();
      if (response.data) {
        setWebhooks(response.data);
      }
    } catch (err) {
      console.error("Failed to fetch webhooks:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchWebhooks();
  }, []);

  const handleCreate = async () => {
    if (!url || !secret || selectedEvents.length === 0) return;

    setIsCreating(true);
    try {
      const response = await hsmApi.createWebhook({
        url,
        secret,
        events: selectedEvents,
      });
      if (response.data) {
        success("Webhook Created", "Webhook has been created successfully");
        setUrl("");
        setSecret("");
        setSelectedEvents([]);
        setCreateOpen(false);
        fetchWebhooks();
      } else if (response.error) {
        error("Failed to create webhook", response.error.message);
      }
    } catch (err) {
      error("Failed to create webhook", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsCreating(false);
    }
  };

  const handleDelete = async (webhookId: string) => {
    try {
      const response = await hsmApi.deleteWebhook(webhookId);
      if (response.error) {
        error("Failed to delete webhook", response.error.message);
      } else {
        success("Webhook Deleted", "Webhook has been deleted");
        fetchWebhooks();
      }
    } catch (err) {
      error("Failed to delete webhook", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleTest = async (webhookId: string) => {
    try {
      const response = await hsmApi.testWebhook(webhookId);
      if (response.data?.success) {
        success("Test Successful", "Webhook received the test event");
      } else {
        error("Test Failed", "Webhook did not respond successfully");
      }
    } catch (err) {
      error("Test Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const toggleEvent = (event: string) => {
    setSelectedEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    );
  };

  return (
    <>
      <Header
        title="Webhooks"
        description="Manage event notifications"
        action={
          <Button
            variant="primary"
            icon={<Plus className="h-4 w-4" />}
            onClick={() => setCreateOpen(true)}
          >
            Create Webhook
          </Button>
        }
      />
      <PageContainer>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Webhooks</CardTitle>
            <Button
              variant="ghost"
              size="icon"
              onClick={fetchWebhooks}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
            </Button>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="py-8 text-center">
                <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              </div>
            ) : webhooks.length === 0 ? (
              <div className="py-8 text-center text-muted-foreground">
                <p>No webhooks configured</p>
                <p className="text-sm">Create a webhook to receive event notifications</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>URL</TableHead>
                    <TableHead>Events</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Triggered</TableHead>
                    <TableHead className="w-[50px]"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {webhooks.map((webhook) => (
                    <TableRow key={webhook.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <code className="text-sm font-mono">
                            {truncateMiddle(webhook.url, 40)}
                          </code>
                          <a
                            href={webhook.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-muted-foreground hover:text-foreground"
                          >
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {webhook.events.slice(0, 3).map((event) => (
                            <Badge key={event} variant="outline" className="text-xs">
                              {event}
                            </Badge>
                          ))}
                          {webhook.events.length > 3 && (
                            <Badge variant="secondary" className="text-xs">
                              +{webhook.events.length - 3}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={webhook.status === "active" ? "success" : "secondary"}>
                          {webhook.status}
                        </Badge>
                        {webhook.failure_count > 0 && (
                          <Badge variant="destructive" className="ml-1">
                            {webhook.failure_count} failures
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {webhook.last_triggered ? formatDate(webhook.last_triggered) : "-"}
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleTest(webhook.id)}>
                              <Play className="mr-2 h-4 w-4" />
                              Test Webhook
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              onClick={() => handleDelete(webhook.id)}
                              className="text-destructive focus:text-destructive"
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </PageContainer>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Webhook</DialogTitle>
            <DialogDescription>
              Configure a webhook endpoint to receive event notifications
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="url">Endpoint URL</Label>
              <Input
                id="url"
                type="url"
                placeholder="https://example.com/webhook"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="secret">Secret</Label>
              <Input
                id="secret"
                type="password"
                placeholder="HMAC signing secret"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Used to sign webhook payloads for verification
              </p>
            </div>

            <div className="space-y-2">
              <Label>Events</Label>
              <div className="flex flex-wrap gap-2 max-h-48 overflow-y-auto p-2 border rounded-md">
                {webhookEvents.map((event) => (
                  <Badge
                    key={event.value}
                    variant={selectedEvents.includes(event.value) ? "default" : "outline"}
                    className="cursor-pointer"
                    onClick={() => toggleEvent(event.value)}
                  >
                    {event.label}
                  </Badge>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleCreate}
              disabled={!url || !secret || selectedEvents.length === 0}
              loading={isCreating}
            >
              Create Webhook
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
