import React, { useState } from "react";
import {
  TextInput,
  Button,
  Tile,
  ProgressBar,
  InlineLoading,
  Tag,
  Accordion,
  AccordionItem,
  CodeSnippet,
  Grid,
  Column,
} from "@carbon/react";
import {
  Search,
  Play,
  Stop,
  Download,
  Security,
  Document,
  Warning,
} from "@carbon/icons-react";
// import './LiveScanPage.scss';

const LiveScanPage = () => {
  const [scanUrl, setScanUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanLog, setScanLog] = useState([]);
  const [showResults, setShowResults] = useState(false);

  const handleScan = async () => {
    if (!scanUrl.trim()) return;

    setIsScanning(true);
    setScanProgress(0);
    setScanLog([]);
    setShowResults(false);

    // Simulate CLI scan process with realistic log messages
    const logMessages = [
      {
        type: "info",
        message: "🔍 ThreatXtension CLI - Starting Extension Analysis",
      },
      {
        type: "info",
        message: "📅 Scan initiated at: " + new Date().toLocaleString(),
      },
      { type: "info", message: "🎯 Target: " + scanUrl },
      { type: "info", message: "" },
      { type: "info", message: "📥 Phase 1: Extension Download" },
      { type: "info", message: "   🔍 Attempting to download extension..." },
      {
        type: "info",
        message: "   📋 Checking Chrome Web Store availability...",
      },
      {
        type: "warning",
        message: "   ⚠️  Direct download failed (status: 204)",
      },
      { type: "info", message: "   🔄 Trying alternative download methods..." },
      { type: "info", message: "   📥 Method 2: Chrome browser simulation" },
      {
        type: "info",
        message: "      🔗 Using clients2.google.com service...",
      },
      { type: "success", message: "      ✅ CRX file detected successfully!" },
      { type: "success", message: "   ✅ Download completed: 4.1 MB" },
      { type: "info", message: "" },
      { type: "info", message: "📁 Phase 2: File Extraction" },
      { type: "info", message: "   🔓 Extracting CRX file contents..." },
      { type: "info", message: "   📂 Creating extraction directory..." },
      { type: "info", message: "   📋 Extracting manifest.json..." },
      { type: "info", message: "   📄 Extracting JavaScript files..." },
      { type: "info", message: "   🎨 Extracting CSS and HTML files..." },
      { type: "success", message: "   ✅ Extraction completed: 34 files" },
      { type: "info", message: "" },
      { type: "info", message: "🔒 Phase 3: Security Analysis (SAST)" },
      { type: "info", message: "   📊 Analyzing manifest.json..." },
      { type: "warning", message: "   ⚠️  High-risk permissions detected" },
      {
        type: "info",
        message: "   📄 Scanning JavaScript files for vulnerabilities...",
      },
      {
        type: "error",
        message: "   🚨 eval() usage detected in background.js",
      },
      { type: "error", message: "   🚨 innerHTML assignment in popup.js" },
      { type: "warning", message: "   ⚠️  Suspicious URL patterns found" },
      { type: "info", message: "   📊 SAST analysis completed" },
      { type: "info", message: "" },
      { type: "info", message: "💾 Phase 4: Results & Logging" },
      { type: "info", message: "   📝 Generating security report..." },
      { type: "info", message: "   💾 Saving to CLI logs directory..." },
      {
        type: "success",
        message:
          "   ✅ Log saved: mdanidgdpmkimeiiojknlnekblgmpdll_20250818_141823.log",
      },
      { type: "success", message: "" },
      { type: "success", message: "🎉 SCAN COMPLETED SUCCESSFULLY!" },
      { type: "info", message: "📊 Final Security Score: 0.0/100 (HIGH RISK)" },
      { type: "info", message: "🔍 Total Findings: 20,249 security issues" },
    ];

    for (let i = 0; i < logMessages.length; i++) {
      await new Promise((resolve) => setTimeout(resolve, 600));
      setScanLog((prev) => [...prev, logMessages[i]]);
      setScanProgress(((i + 1) / logMessages.length) * 100);
    }

    // Show results after scan completes
    setTimeout(() => {
      setShowResults(true);
      setIsScanning(false);
    }, 1000);
  };

  const stopScan = () => {
    setIsScanning(false);
    setScanProgress(0);
  };

  const clearLog = () => {
    setScanLog([]);
    setShowResults(false);
    setScanProgress(0);
  };

  const getLogIcon = (type) => {
    switch (type) {
      case "info":
        return "ℹ️";
      case "success":
        return "✅";
      case "warning":
        return "⚠️";
      case "error":
        return "🚨";
      default:
        return "📝";
    }
  };

  const getLogColor = (type) => {
    switch (type) {
      case "info":
        return "blue";
      case "success":
        return "green";
      case "warning":
        return "orange";
      case "error":
        return "red";
      default:
        return "gray";
    }
  };

  return (
    <div className="live-scan-page">
      <div className="page-header">
        <h1>🔴 Live Extension Security Scan</h1>
        <p>Real-time monitoring and analysis of Chrome extension security</p>
      </div>

      <Grid className="scan-controls">
        <Column lg={8} md={4} sm={4}>
          <Tile className="scan-input-tile">
            <div className="scan-input-section">
              <TextInput
                id="scan-url"
                labelText="Chrome Web Store URL"
                placeholder="https://chromewebstore.google.com/detail/extension-name/extension-id"
                value={scanUrl}
                onChange={(e) => setScanUrl(e.target.value)}
                size="lg"
                className="url-input"
              />
              <div className="scan-actions">
                <Button
                  onClick={handleScan}
                  disabled={isScanning || !scanUrl.trim()}
                  className="scan-button"
                  size="lg"
                >
                  {isScanning ? (
                    <InlineLoading description="Scanning..." />
                  ) : (
                    <>
                      <Play size={20} />
                      Start Scan
                    </>
                  )}
                </Button>
                {isScanning && (
                  <Button
                    onClick={stopScan}
                    kind="danger"
                    size="lg"
                    className="stop-button"
                  >
                    <Stop size={20} />
                    Stop
                  </Button>
                )}
              </div>
            </div>
          </Tile>
        </Column>

        <Column lg={4} md={4} sm={4}>
          <Tile className="scan-status-tile">
            <div className="status-header">
              <Security size={24} />
              <h3>Scan Status</h3>
            </div>
            <div className="status-content">
              <div className="status-item">
                <span className="status-label">Progress:</span>
                <ProgressBar
                  value={scanProgress}
                  size="lg"
                  className="progress-bar"
                />
                <span className="progress-text">
                  {Math.round(scanProgress)}%
                </span>
              </div>
              <div className="status-item">
                <span className="status-label">Status:</span>
                <Tag type={isScanning ? "blue" : "green"} size="sm">
                  {isScanning ? "Scanning" : "Ready"}
                </Tag>
              </div>
              <div className="status-item">
                <span className="status-label">Log Entries:</span>
                <span className="log-count">{scanLog.length}</span>
              </div>
            </div>
          </Tile>
        </Column>
      </Grid>

      {/* Scan Progress and Logs */}
      {isScanning && (
        <Tile className="scan-progress-tile">
          <div className="progress-header">
            <h3>📊 Scan Progress</h3>
            <Button
              onClick={clearLog}
              kind="tertiary"
              size="sm"
              className="clear-log-btn"
            >
              Clear Log
            </Button>
          </div>
          <div className="progress-content">
            <div className="log-container">
              {scanLog.map((log, index) => (
                <div key={index} className={`log-entry log-${log.type}`}>
                  <span className="log-icon">{getLogIcon(log.type)}</span>
                  <span className="log-message">{log.message}</span>
                  <Tag type={getLogColor(log.type)} size="sm">
                    {log.type.toUpperCase()}
                  </Tag>
                </div>
              ))}
            </div>
          </div>
        </Tile>
      )}

      {/* Scan Results */}
      {showResults && (
        <Tile className="scan-results-tile">
          <div className="results-header">
            <h3>📋 Scan Results Summary</h3>
            <div className="results-meta">
              <span>Completed at: {new Date().toLocaleString()}</span>
              <span>Target: {scanUrl}</span>
            </div>
          </div>

          <Grid className="results-grid">
            <Column lg={3} md={4} sm={4}>
              <div className="result-card security-score">
                <h4>Security Score</h4>
                <div className="score-value">0.0/100</div>
                <Tag type="red" size="lg">
                  HIGH RISK
                </Tag>
              </div>
            </Column>

            <Column lg={3} md={4} sm={4}>
              <div className="result-card findings">
                <h4>Total Findings</h4>
                <div className="findings-value">20,249</div>
                <Tag type="red" size="lg">
                  CRITICAL
                </Tag>
              </div>
            </Column>

            <Column lg={3} md={4} sm={4}>
              <div className="result-card files">
                <h4>Files Analyzed</h4>
                <div className="files-value">34</div>
                <Tag type="blue" size="lg">
                  COMPLETE
                </Tag>
              </div>
            </Column>

            <Column lg={3} md={4} sm={4}>
              <div className="result-card download">
                <h4>Download Size</h4>
                <div className="download-value">4.1 MB</div>
                <Tag type="green" size="lg">
                  SUCCESS
                </Tag>
              </div>
            </Column>
          </Grid>

          <div className="results-actions">
            <Button kind="primary" size="lg" className="download-report-btn">
              <Download size={20} />
              Download Full Report
            </Button>
            <Button kind="tertiary" size="lg" className="view-details-btn">
              <Document size={20} />
              View Detailed Analysis
            </Button>
          </div>
        </Tile>
      )}

      {/* Quick Actions */}
      <Tile className="quick-actions-tile">
        <h3>⚡ Quick Actions</h3>
        <Grid className="actions-grid">
          <Column lg={4} md={4} sm={4}>
            <Button kind="tertiary" size="lg" className="action-btn">
              <Search size={20} />
              Recent Scans
            </Button>
          </Column>
          <Column lg={4} md={4} sm={4}>
            <Button kind="tertiary" size="lg" className="action-btn">
              <Warning size={20} />
              High Risk Extensions
            </Button>
          </Column>
          <Column lg={4} md={4} sm={4}>
            <Button kind="tertiary" size="lg" className="action-btn">
              <Document size={20} />
              Scan History
            </Button>
          </Column>
        </Grid>
      </Tile>
    </div>
  );
};

export default LiveScanPage;
