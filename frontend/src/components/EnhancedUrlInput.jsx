import React, { useRef } from "react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Search, Upload } from "lucide-react";
import "./EnhancedUrlInput.scss";

/**
 * Enhanced URL Input Component with File Upload Support
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
    <div className={`enhanced-url-input ${className}`}>
      <div className="input-container">
        <div className="url-field-container">
          <div className="space-y-2">
            <label htmlFor="extension-url" className="text-sm font-medium url-label">
              Chrome Web Store URL
            </label>
            <div className="url-input-wrapper">
              <style>
                {`
                  #extension-url::placeholder {
                    color: #6b7280 !important;
                    opacity: 1 !important;
                    font-weight: 300 !important;
                  }
                  #extension-url::-webkit-input-placeholder {
                    color: #6b7280 !important;
                    opacity: 1 !important;
                    font-weight: 300 !important;
                  }
                  #extension-url::-moz-placeholder {
                    color: #6b7280 !important;
                    opacity: 1 !important;
                    font-weight: 300 !important;
                  }
                  #extension-url:-ms-input-placeholder {
                    color: #6b7280 !important;
                    opacity: 1 !important;
                    font-weight: 300 !important;
                  }
                `}
              </style>
              <Input
                id="extension-url"
                placeholder="https://chromewebstore.google.com/detail/extension-name/extension-id"
                value={value}
                onChange={(e) => onChange(e.target.value)}
                onKeyPress={handleKeyPress}
                className="url-input-field"
                style={{
                  height: '56px',
                  background: 'rgba(255, 255, 255, 0.08)',
                  border: '2px solid rgba(59, 130, 246, 0.4)',
                  borderRadius: '0.75rem',
                  color: '#ffffff',
                  fontSize: '0.9375rem',
                  fontWeight: '500',
                  padding: '0 3.5rem 0 1.25rem',
                  boxShadow: '0 4px 16px rgba(0, 0, 0, 0.3), 0 0 20px rgba(59, 130, 246, 0.15), inset 0 1px 0 rgba(255, 255, 255, 0.1)'
                }}
              />
            </div>
          </div>


        </div>

        {/* File Upload Section */}
        {onFileUpload && (
          <div className="file-upload-section mt-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="flex-1 h-px bg-gray-600"></div>
              <span className="text-sm text-gray-400">OR</span>
              <div className="flex-1 h-px bg-gray-600"></div>
            </div>
            
            <input
              ref={fileInputRef}
              type="file"
              accept=".crx,.zip"
              onChange={handleFileChange}
              className="hidden"
              disabled={isScanning}
            />
            
            <Button
              onClick={handleUploadClick}
              disabled={isScanning}
              variant="outline"
              className="w-full"
              size="lg"
              style={{
                height: '56px',
                background: 'rgba(255, 255, 255, 0.05)',
                border: '2px solid rgba(139, 92, 246, 0.4)',
                borderRadius: '0.75rem',
                color: '#ffffff',
                fontSize: '0.9375rem',
                fontWeight: '500',
              }}
            >
              <Upload className="mr-2 h-4 w-4" />
              Upload CRX/ZIP File
            </Button>
          </div>
        )}

        <div className="action-buttons flex gap-2 mt-4">
          <Button
            onClick={onScan}
            disabled={isScanning || !value.trim()}
            className="scan-button"
            size="lg"
          >
            {isScanning ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Scanning...
              </>
            ) : (
              <>
                <Search className="mr-2 h-4 w-4" />
                Scan & Analyze
              </>
            )}
          </Button>

        </div>
      </div>



      <p className="input-help-text text-sm text-muted-foreground mt-2">
        {onFileUpload
          ? "Enter a Chrome Web Store URL or upload a .crx/.zip file to analyze the extension's security posture"
          : "Enter a Chrome Web Store URL to automatically scan and analyze the extension's security posture"
        }
      </p>
    </div>
  );
};

export default EnhancedUrlInput;