import React from "react";
import { X, CheckCircle, XCircle, AlertTriangle, Info, Loader2 } from "lucide-react";
import { cn } from "../lib/utils";

const StatusMessage = ({
  type = "info",
  message,
  onDismiss,
  persistent = false,
  className = "",
}) => {
  if (!message) return null;

  const getIcon = () => {
    switch (type) {
      case "success":
        return <CheckCircle className="h-5 w-5" />;
      case "error":
        return <XCircle className="h-5 w-5" />;
      case "warning":
        return <AlertTriangle className="h-5 w-5" />;
      case "loading":
        return <Loader2 className="h-5 w-5 animate-spin" />;
      case "info":
      default:
        return <Info className="h-5 w-5" />;
    }
  };

  const getVariantClasses = () => {
    switch (type) {
      case "success":
        return "bg-green-500/10 text-green-500 border-green-500/20";
      case "error":
        return "bg-red-500/10 text-red-500 border-red-500/20";
      case "warning":
        return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
      case "loading":
        return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      case "info":
      default:
        return "bg-blue-500/10 text-blue-500 border-blue-500/20";
    }
  };

  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3 rounded-lg border p-4",
        getVariantClasses(),
        className
      )}
    >
      <div className="flex items-center gap-3">
        {getIcon()}
        <span className="text-sm font-medium">{message}</span>
      </div>
      {!persistent && onDismiss && (
        <button
          onClick={onDismiss}
          className="rounded-md p-1 hover:bg-background/10 transition-colors"
          aria-label="Dismiss"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  );
};

export default StatusMessage;