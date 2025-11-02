import React, { useState, useEffect } from "react";
import {
  Modal,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Button,
  TextArea,
  Loading,
  Copy,
} from "@carbon/react";
import { Close, Download, Copy as CopyIcon } from "@carbon/icons-react";
import "./FileViewerModal.scss";

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
      console.log("Missing file or extensionId:", { file, extensionId });
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      console.log("Loading file content for:", {
        extensionId,
        filePath: file.path,
      });
      const content = await onGetFileContent(extensionId, file.path);
      console.log("File content loaded successfully, length:", content?.length);
      setFileContent(content);
    } catch (err) {
      console.error("Error loading file content:", err);
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
      case "js":
        return "📄";
      case "json":
        return "⚙️";
      case "html":
        return "🌐";
      case "css":
        return "🎨";
      case "png":
      case "jpg":
      case "jpeg":
      case "gif":
        return "🖼️";
      case "xml":
        return "📋";
      case "txt":
        return "📝";
      default:
        return "📁";
    }
  };

  const getFileType = (filename) => {
    const ext = filename.split(".").pop()?.toLowerCase();
    switch (ext) {
      case "js":
        return "JavaScript";
      case "json":
        return "JSON";
      case "html":
        return "HTML";
      case "css":
        return "CSS";
      case "png":
      case "jpg":
      case "jpeg":
      case "gif":
        return "Image";
      case "xml":
        return "XML";
      case "txt":
        return "Text";
      default:
        return "File";
    }
  };

  if (!file) return null;

  return (
    <Modal
      open={isOpen}
      onRequestClose={onClose}
      size="lg"
      className="file-viewer-modal"
      modalHeading=""
      primaryButtonText=""
      secondaryButtonText=""
      hasScrollingContent
    >
      <ModalHeader>
        <div className="file-header">
          <div className="file-info">
            <span className="file-icon">{getFileIcon(file.name)}</span>
            <div className="file-details">
              <h3 className="file-name">{file.name}</h3>
              <p className="file-meta">
                {getFileType(file.name)} •{" "}
                {file.size
                  ? `${(file.size / 1024).toFixed(1)} KB`
                  : "Unknown size"}
              </p>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={onClose}
            className="close-button"
            hasIconOnly
            iconDescription="Close"
          >
            <Close size={16} />
          </Button>
        </div>
      </ModalHeader>

      <ModalBody>
        {isLoading && (
          <div className="loading-container">
            <Loading description="Loading file content..." />
          </div>
        )}

        {error && (
          <div className="error-container">
            <p className="error-message">❌ {error}</p>
            <Button onClick={loadFileContent} size="sm">
              🔄 Retry
            </Button>
          </div>
        )}

        {!isLoading && !error && fileContent && (
          <div className="file-content-container">
            <div className="content-header">
              <span className="content-label">File Content</span>
              <div className="content-actions">
                <Button
                  kind="ghost"
                  size="sm"
                  onClick={handleCopy}
                  className={copied ? "copied" : ""}
                  hasIconOnly
                  iconDescription={copied ? "Copied!" : "Copy content"}
                >
                  <CopyIcon size={16} />
                </Button>
                <Button
                  kind="ghost"
                  size="sm"
                  onClick={handleDownload}
                  hasIconOnly
                  iconDescription="Download file"
                >
                  <Download size={16} />
                </Button>
              </div>
            </div>

            <div className="content-wrapper">
              <TextArea
                value={fileContent}
                readOnly
                className="file-content-textarea"
                rows={20}
                placeholder="File content will appear here..."
              />
            </div>

            {copied && (
              <div className="copy-notification">
                ✅ Content copied to clipboard!
              </div>
            )}
          </div>
        )}
      </ModalBody>

      <ModalFooter>
        <Button kind="secondary" onClick={onClose}>
          Close
        </Button>
        {fileContent && <Button onClick={handleDownload}>Download File</Button>}
      </ModalFooter>
    </Modal>
  );
};

export default FileViewerModal;
