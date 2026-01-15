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
import { Textarea } from "./ui/textarea";
import { X, Download, Copy, Loader2 } from "lucide-react";


const FileViewerModal = ({
  isOpen,
  onClose,
  file,
  extensionId,
  onGetFileContent,
}) => {
  const [fileContent, setFileContent] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen && file && extensionId) {
      loadFileContent();
    }
  }, [isOpen, file, extensionId]);

  const loadFileContent = async () => {
    if (!file || !extensionId) {
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const content = await onGetFileContent(extensionId, file.path);
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

  const handleDownload = () => {
    const blob = new Blob([fileContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getFileIcon = (filename) => {
    const ext = filename.split(".").pop()?.toLowerCase();
    switch (ext) {
      case "js": return "📄";
      case "json": return "⚙️";
      case "html": return "🌐";
      case "css": return "🎨";
      case "png":
      case "jpg":
      case "jpeg":
      case "gif": return "🖼️";
      case "xml": return "📋";
      case "txt": return "📝";
      default: return "📁";
    }
  };

  const getFileType = (filename) => {
    const ext = filename.split(".").pop()?.toLowerCase();
    switch (ext) {
      case "js": return "JavaScript";
      case "json": return "JSON";
      case "html": return "HTML";
      case "css": return "CSS";
      case "png":
      case "jpg":
      case "jpeg":
      case "gif": return "Image";
      case "xml": return "XML";
      case "txt": return "Text";
      default: return "File";
    }
  };

  if (!file) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[700px] max-h-[80vh]">
        <DialogHeader>
          <div className="flex items-start gap-3">
            <span className="text-2xl">{getFileIcon(file.name)}</span>
            <div className="flex-1">
              <DialogTitle>{file.name}</DialogTitle>
              <DialogDescription>
                {getFileType(file.name)} • {file.size ? `${(file.size / 1024).toFixed(1)} KB` : "Unknown size"}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-4">
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

          {!isLoading && !error && fileContent && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">File Content</span>
                <div className="flex gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleCopy}
                  >
                    <Copy className="h-4 w-4 mr-2" />
                    {copied ? "Copied!" : "Copy"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleDownload}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Download
                  </Button>
                </div>
              </div>

              <Textarea
                value={fileContent}
                readOnly
                className="font-mono text-xs min-h-[400px]"
                placeholder="File content will appear here..."
              />

              {copied && (
                <div className="text-sm text-green-500">
                  ✅ Content copied to clipboard!
                </div>
              )}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          {fileContent && (
            <Button onClick={handleDownload}>
              <Download className="h-4 w-4 mr-2" />
              Download File
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default FileViewerModal;