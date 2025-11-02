import React, { useState, useRef, useEffect } from "react";
import { TextInput, Button, InlineLoading, Dropdown } from "@carbon/react";
import { Search, Code, ChevronDown } from "@carbon/icons-react";
import "./EnhancedUrlInput.scss";

/**
 * Enhanced URL Input Component with recent URLs dropdown and sample extension button
 *
 * @param {Object} props
 * @param {string} props.value - Current URL value
 * @param {function} props.onChange - Function to call when URL changes
 * @param {function} props.onScan - Function to call when scan button is clicked
 * @param {boolean} props.isScanning - Whether a scan is in progress
 * @param {Array} props.recentUrls - Array of recently scanned URLs
 * @param {function} props.onSelectRecent - Function to call when a recent URL is selected
 * @param {function} props.onScanSample - Function to call when scan sample button is clicked
 * @param {string} props.className - Additional CSS classes
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

  // Handle click outside to close dropdown
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

  // Format URLs for display in dropdown
  const formatUrlForDisplay = (url) => {
    try {
      // Extract extension ID and name if possible
      const match = url.match(/\/detail\/([^\/]+)\/([^\/\?]+)/);
      if (match && match[1]) {
        return `${match[1]} (${match[2]})`;
      }

      // Fallback to just showing the URL with truncation
      return url.length > 40 ? url.substring(0, 37) + "..." : url;
    } catch (e) {
      return url;
    }
  };

  // Handle key press (Enter to submit)
  const handleKeyPress = (e) => {
    if (e.key === "Enter" && value.trim() && !isScanning) {
      onScan();
    }
  };

  // Sample extension URLs
  const sampleExtensions = [
    {
      name: "AdBlock",
      url: "https://chromewebstore.google.com/detail/adblock/gighmmpiobklfepjocnamgkkbiglidom",
    },
    {
      name: "Grammarly",
      url: "https://chromewebstore.google.com/detail/grammarly/kbfnbcaeplbcioakkpcpgfkobkghlhen",
    },
    {
      name: "LastPass",
      url: "https://chromewebstore.google.com/detail/lastpass/hdokiejnpimakedhajhdlcegeplioahd",
    },
  ];

  return (
    <div className={`enhanced-url-input ${className}`}>
      <div className="input-container">
        <div className="url-field-container">
          <TextInput
            id="extension-url"
            labelText="Chrome Web Store URL"
            placeholder="https://chromewebstore.google.com/detail/extension-name/extension-id"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyPress={handleKeyPress}
            className="url-input-field"
            size="lg"
          />

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

        <div className="action-buttons">
          <Button
            onClick={onScan}
            disabled={isScanning || !value.trim()}
            className="scan-button"
            size="lg"
            renderIcon={Search}
          >
            {isScanning ? (
              <InlineLoading description="Scanning..." />
            ) : (
              "Scan & Analyze"
            )}
          </Button>

          <Button
            onClick={onScanSample}
            disabled={isScanning}
            className="sample-button"
            kind="tertiary"
            size="lg"
            renderIcon={Code}
          >
            Sample
          </Button>
        </div>
      </div>

      {/* Sample extensions quick access */}
      <div className="sample-extensions">
        <span className="sample-label">Try:</span>
        {sampleExtensions.map((ext, index) => (
          <button
            key={index}
            className="sample-extension-link"
            onClick={() => onChange(ext.url)}
          >
            {ext.name}
          </button>
        ))}
      </div>

      <p className="input-help-text">
        Enter a Chrome Web Store URL to automatically scan and analyze the
        extension's security posture
      </p>
    </div>
  );
};

export default EnhancedUrlInput;

// Made with Bob
