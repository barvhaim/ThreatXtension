import React from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";


const CacheConfirmationModal = ({
  isOpen,
  onClose,
  onViewCached,
  onReScan,
  cachedData,
  extensionId,
}) => {
  if (!cachedData) return null;

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const formatAge = (timestamp) => {
    const age = Date.now() - timestamp;
    const hours = Math.floor(age / (1000 * 60 * 60));
    const minutes = Math.floor((age % (1000 * 60 * 60)) / (1000 * 60));

    if (hours > 0) {
      return `${hours}h ${minutes}m ago`;
    }
    return `${minutes}m ago`;
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Extension Previously Scanned</DialogTitle>
          <DialogDescription>
            This extension has been scanned before
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Extension ID:</span>
              <span className="font-medium">{extensionId}</span>
            </div>

            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Last Scanned:</span>
              <span className="font-medium">
                {formatTimestamp(cachedData.timestamp)}
              </span>
            </div>

            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Age:</span>
              <span className="font-medium">{formatAge(cachedData.timestamp)}</span>
            </div>

            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Times Scanned:</span>
              <span className="font-medium">{cachedData.scanCount}</span>
            </div>
          </div>

          {cachedData.data && (
            <div className="space-y-3 border-t pt-4">
              <h4 className="font-semibold">Previous Scan Summary:</h4>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <span className="text-sm text-muted-foreground">Security Score:</span>
                  <div className={`text-lg font-bold ${cachedData.data.securityScore < 50 ? "text-red-500" :
                      cachedData.data.securityScore < 80 ? "text-yellow-500" : "text-green-500"
                    }`}>
                    {cachedData.data.securityScore || "N/A"}/100
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-sm text-muted-foreground">Total Files:</span>
                  <div className="text-lg font-bold">
                    {cachedData.data.totalFiles || "N/A"}
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-sm text-muted-foreground">Security Findings:</span>
                  <div className="text-lg font-bold">
                    {cachedData.data.totalFindings || "N/A"}
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-sm text-muted-foreground">Risk Level:</span>
                  <Badge variant={
                    cachedData.data.riskLevel === "HIGH" ? "destructive" :
                      cachedData.data.riskLevel === "MEDIUM" ? "secondary" : "default"
                  }>
                    {cachedData.data.riskLevel || "N/A"}
                  </Badge>
                </div>
              </div>
            </div>
          )}

          <div className="bg-muted p-3 rounded-md text-sm">
            <p>
              <strong>Note:</strong> Cached results are stored locally and expire
              after 24 hours. Re-scanning will download and analyze the latest
              version of the extension.
            </p>
          </div>
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={onViewCached}>
            View Cached Results
          </Button>
          <Button variant="destructive" onClick={onReScan}>
            Re-scan Extension
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default CacheConfirmationModal;