import React, { useState, useRef, useEffect } from "react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Search, Code, ChevronDown } from "lucide-react";
import "./EnhancedUrlInput.scss";

/**
 * Enhanced URL Input Component with recent URLs dropdown and sample extension button
 */
const EnhancedUrlInput = ({
  value,
  onChange,
  onScan,
  isScanning = false,
  recentUrls = [],
  onSelectRecent,
  onScanSample,
  className = "",
  ...props
}) => {
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsDropdownOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  const formatUrlForDisplay = (url) => {
    try {
      const match = url.match(/\/detail\/([^\/]+)\/([^\/\?]+)/);
      if (match && match[1]) {
        return `${match[1]} (${match[2]})`;
      }
      return url.length > 40 ? url.substring(0, 37) + "..." : url;
    } catch (e) {
      return url;
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && value.trim() && !isScanning) {
      onScan();
    }
  };

  // Sample extensions removed per user feedback

  return (
    <div className={`enhanced-url-input ${className}`}>
      <div className="input-container">
        <div className="url-field-container">
          <div className="space-y-2">
            <label htmlFor="extension-url" className="text-sm font-medium url-label">
              Chrome Web Store URL
            </label>
            <div className="url-input-wrapper">
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

          {recentUrls.length > 0 && (
            <div className="recent-urls-dropdown" ref={dropdownRef}>
              <button
                className="dropdown-toggle"
                onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                aria-label="Show recent URLs"
              >
                <ChevronDown size={16} />
              </button>

              {isDropdownOpen && (
                <div className="dropdown-menu">
                  <div className="dropdown-header">Recent Extensions</div>
                  {recentUrls.map((url, index) => (
                    <button
                      key={index}
                      className="dropdown-item"
                      onClick={() => {
                        onSelectRecent(url);
                        setIsDropdownOpen(false);
                      }}
                    >
                      {formatUrlForDisplay(url)}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="action-buttons flex gap-2">
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



      <p className="input-help-text text-sm text-muted-foreground">
        Enter a Chrome Web Store URL to automatically scan and analyze the
        extension's security posture
      </p>
    </div>
  );
};

export default EnhancedUrlInput;