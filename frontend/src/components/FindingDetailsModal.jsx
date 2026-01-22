import React, { useState, useEffect } from "react";
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
import { Loader2, Copy, AlertTriangle } from "lucide-react";

const FindingDetailsModal = ({
  isOpen,
  onClose,
  finding,
  extensionId,
  onGetFileContent,
}) => {
  const [fileContent, setFileContent] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen && finding && extensionId) {
      loadFileContent();
    }
  }, [isOpen, finding, extensionId]);

  const loadFileContent = async () => {
    if (!finding || !extensionId) {
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const content = await onGetFileContent(extensionId, finding.file);
      setFileContent(content);
    } catch (err) {
      setError(err.message || "Failed to load file content");
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(fileContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const renderCodeWithHighlight = () => {
    if (!fileContent) return null;

    const lines = fileContent.split('\n');
    const targetLine = finding.line_number || finding.line || 1;
    
    // Show context: 5 lines before and after
    const contextStart = Math.max(0, targetLine - 6);
    const contextEnd = Math.min(lines.length, targetLine + 5);
    const contextLines = lines.slice(contextStart, contextEnd);

    return (
      <div className="bg-muted rounded-lg overflow-hidden border">
        <div className="bg-background/50 px-4 py-2 border-b flex items-center justify-between">
          <span className="text-sm font-medium">Code Context</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
          >
            <Copy className="h-4 w-4 mr-2" />
            {copied ? "Copied!" : "Copy All"}
          </Button>
        </div>
        <div className="overflow-x-auto">
          <pre className="p-4 text-xs font-mono">
            {contextLines.map((line, idx) => {
              const lineNumber = contextStart + idx + 1;
              const isTargetLine = lineNumber === targetLine;
              
              return (
                <div
                  key={idx}
                  className={`flex ${
                    isTargetLine
                      ? 'bg-red-500/20 border-l-4 border-l-red-500'
                      : 'hover:bg-muted/50'
                  }`}
                >
                  <span
                    className={`inline-block w-12 text-right pr-4 select-none ${
                      isTargetLine
                        ? 'text-red-500 font-bold'
                        : 'text-muted-foreground'
                    }`}
                  >
                    {lineNumber}
                  </span>
                  <span className={`flex-1 ${isTargetLine ? 'font-semibold' : ''}`}>
                    {line || ' '}
                  </span>
                </div>
              );
            })}
          </pre>
        </div>
      </div>
    );
  };

  if (!finding) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[900px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-start gap-3">
            <AlertTriangle className={`h-6 w-6 mt-1 ${
              finding.severity === 'HIGH' || finding.severity === 'CRITICAL' || finding.severity === 'ERROR'
                ? 'text-red-500'
                : finding.severity === 'MEDIUM' || finding.severity === 'WARNING'
                ? 'text-yellow-500'
                : 'text-blue-500'
            }`} />
            <div className="flex-1">
              <DialogTitle className="text-xl">{finding.title || finding.pattern_name || 'Security Finding'}</DialogTitle>
              <DialogDescription className="mt-2">
                <div className="flex flex-wrap gap-2 items-center">
                  <Badge variant={
                    finding.severity === 'HIGH' || finding.severity === 'CRITICAL' || finding.severity === 'ERROR'
                      ? 'destructive'
                      : finding.severity === 'MEDIUM' || finding.severity === 'WARNING'
                      ? 'secondary'
                      : 'default'
                  }>
                    {finding.severity}
                  </Badge>
                  <span className="text-sm">•</span>
                  <span className="text-sm">{finding.file}</span>
                  <span className="text-sm">•</span>
                  <span className="text-sm">Line {finding.line_number || finding.line}</span>
                </div>
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-4">
          {/* Description */}
          <div className="bg-muted/50 rounded-lg p-4">
            <h4 className="font-semibold mb-2">Description</h4>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap">
              {finding.description || 'No description available'}
            </p>
          </div>

          {/* Additional Details */}
          {(finding.message || finding.check_id || finding.cwe || finding.owasp) && (
            <div className="bg-muted/50 rounded-lg p-4">
              <h4 className="font-semibold mb-2">Additional Details</h4>
              <div className="space-y-2 text-sm">
                {finding.message && (
                  <div>
                    <span className="text-muted-foreground">Message: </span>
                    <span>{finding.message}</span>
                  </div>
                )}
                {finding.check_id && (
                  <div>
                    <span className="text-muted-foreground">Check ID: </span>
                    <code className="bg-background px-2 py-1 rounded text-xs">{finding.check_id}</code>
                  </div>
                )}
                {finding.cwe && (
                  <div>
                    <span className="text-muted-foreground">CWE: </span>
                    <span>{Array.isArray(finding.cwe) ? finding.cwe.join(', ') : finding.cwe}</span>
                  </div>
                )}
                {finding.owasp && (
                  <div>
                    <span className="text-muted-foreground">OWASP: </span>
                    <span>{Array.isArray(finding.owasp) ? finding.owasp.join(', ') : finding.owasp}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Code Display */}
          {isLoading && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="ml-2">Loading file content...</span>
            </div>
          )}

          {error && (
            <div className="flex flex-col items-center justify-center py-8 space-y-3">
              <p className="text-destructive">❌ {error}</p>
              <Button onClick={loadFileContent} size="sm">
                🔄 Retry
              </Button>
            </div>
          )}

          {!isLoading && !error && fileContent && renderCodeWithHighlight()}

          {copied && (
            <div className="text-sm text-green-500 flex items-center gap-2">
              ✅ Content copied to clipboard!
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default FindingDetailsModal;

// Made with Bob
