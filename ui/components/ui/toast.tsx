"use client";

import * as React from "react";
import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

export interface Toast {
  id: string;
  title?: string;
  description?: string;
  variant?: "default" | "destructive" | "success";
  duration?: number;
}

interface ToastProps extends Toast {
  onClose: (id: string) => void;
}

// Spring that settles fast — toasts are background ack, not the main event.
const toastSpring = { type: "spring" as const, stiffness: 420, damping: 32 };

const ToastItem = ({
  id,
  title,
  description,
  variant = "default",
  onClose,
}: ToastProps) => {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 24, scale: 0.96 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 24, scale: 0.96, transition: { duration: 0.15 } }}
      transition={toastSpring}
      role={variant === "destructive" ? "alert" : "status"}
      aria-live={variant === "destructive" ? "assertive" : "polite"}
      className={cn(
        "pointer-events-auto relative flex w-full items-center justify-between space-x-4 overflow-hidden rounded-lg border p-4 shadow-lg",
        {
          "bg-background text-foreground border-border": variant === "default",
          "bg-destructive text-destructive-foreground border-destructive":
            variant === "destructive",
          "bg-success text-success-foreground border-success":
            variant === "success",
        }
      )}
    >
      <div className="flex flex-col gap-1">
        {title && <p className="text-sm font-semibold">{title}</p>}
        {description && (
          <p className="text-sm opacity-90">{description}</p>
        )}
      </div>
      <button
        onClick={() => onClose(id)}
        className="absolute right-2 top-2 rounded-md p-1 opacity-70 hover:opacity-100 transition-opacity"
        aria-label="Dismiss notification"
      >
        <X className="h-4 w-4" />
        <span className="sr-only">Close</span>
      </button>
    </motion.div>
  );
};

interface ToasterProps {
  toasts: Toast[];
  onClose: (id: string) => void;
}

export function Toaster({ toasts, onClose }: ToasterProps) {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-full max-w-sm pointer-events-none">
      <AnimatePresence initial={false}>
        {toasts.map((toast) => (
          <ToastItem key={toast.id} {...toast} onClose={onClose} />
        ))}
      </AnimatePresence>
    </div>
  );
}

export { ToastItem };
