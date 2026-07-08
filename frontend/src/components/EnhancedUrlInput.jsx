import React, { useRef } from "react";
import { Button } from "./ui/button";
import { Search, Upload, ChevronRight } from "lucide-react";
import "./EnhancedUrlInput.scss";

/**
 * Terminal-style target acquisition input with file upload support.
 */
const EnhancedUrlInput = ({
  value,
  onChange,
  onScan,
  onFileUpload,
  isScanning = false,
  className = "",
  ...props
}) => {
  const fileInputRef = useRef(null);

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && value.trim() && !isScanning) {
      onScan();
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file && onFileUpload) {
      onFileUpload(file);
    }
  };

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className={`enhanced-url-input ${className}`} {...props}>
      <label htmlFor="extension-url" className="url-label">
        <span className="url-label__key">target</span>
        <span className="url-label__eq">=</span>
        <span className="url-label__hint">store URL · extension ID · .crx / .zip</span>
      </label>

      <div className="url-input-row">
        <div className="url-input-wrapper">
          <ChevronRight className="url-prompt" size={16} strokeWidth={2.5} />
          <input
            id="extension-url"
            className="url-input-field"
            placeholder="paste a Chrome Web Store URL or 32-char extension ID…"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyPress={handleKeyPress}
            autoComplete="off"
            spellCheck="false"
          />
        </div>

        <Button
          onClick={onScan}
          disabled={isScanning || !value.trim()}
          className="scan-button"
        >
          {isScanning ? (
            <>
              <span className="scan-button__spinner" />
              Scanning
            </>
          ) : (
            <>
              <Search size={16} strokeWidth={2.25} />
              Run scan
            </>
          )}
        </Button>
      </div>

      {onFileUpload && (
        <div className="file-upload-section">
          <div className="upload-divider">
            <span className="upload-divider__line" />
            <span className="upload-divider__text">or load a local package</span>
            <span className="upload-divider__line" />
          </div>

          <input
            ref={fileInputRef}
            type="file"
            accept=".crx,.zip"
            onChange={handleFileChange}
            className="hidden"
            disabled={isScanning}
          />

          <button
            type="button"
            onClick={handleUploadClick}
            disabled={isScanning}
            className="upload-button"
          >
            <Upload size={16} strokeWidth={2.25} />
            Upload .crx / .zip
          </button>
        </div>
      )}
    </div>
  );
};

export default EnhancedUrlInput;
