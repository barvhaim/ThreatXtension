import React, { useState, useEffect } from "react";
import {
  Button,
  Grid,
  Column,
  Tile,
  Tag,
  Loading,
  InlineLoading,
  Modal,
} from "@carbon/react";
import {
  ModernCard,
  ModernCardHeader,
  ModernCardBody,
} from "../components/ModernCard";
import EnhancedMetricCard from "../components/EnhancedMetricCard";
import EnhancedUrlInput from "../components/EnhancedUrlInput";
import TabbedResultsPanel from "../components/TabbedResultsPanel";
import StatusMessage from "../components/StatusMessage";
import realScanService from "../services/realScanService";
import cacheService from "../services/cacheService";
import CacheConfirmationModal from "../components/CacheConfirmationModal";
import FileViewerModal from "../components/FileViewerModal";
import "./DashboardPage.scss";
import "../components/ScanHistory.scss";

const DashboardPage = () => {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const [showCacheModal, setShowCacheModal] = useState(false);
  const [cachedData, setCachedData] = useState(null);
  const [extensionId, setExtensionId] = useState("");
  const [scanHistory, setScanHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [recentUrls, setRecentUrls] = useState([]);
  const [showSampleModal, setShowSampleModal] = useState(false);
  const [fileViewerModal, setFileViewerModal] = useState({
    isOpen: false,
    file: null,
  });

  // Load scan history on component mount
  useEffect(() => {
    loadScanHistory();
  }, []);

  // Load scan history from cache service
  const loadScanHistory = () => {
    const history = cacheService.getScanHistory();
    setScanHistory(history);

    // Extract recent URLs from history
    const urls = history.map((item) => item.url).filter(Boolean);
    setRecentUrls(urls.slice(0, 5)); // Keep only the 5 most recent URLs
  };

  // Extract extension ID from Chrome Web Store URL
  const extractExtensionId = (url) => {
    return realScanService.extractExtensionId(url);
  };

  // Check if URL has been scanned before
  const checkCache = (url) => {
    const extId = extractExtensionId(url);
    if (!extId) return false;

    const cached = cacheService.getCachedResult(extId);
    if (cached) {
      setCachedData(cached);
      setExtensionId(extId);
      setShowCacheModal(true);
      return true;
    }
    return false;
  };

  // Handle scan button click
  const handleScanClick = async () => {
    if (!url.trim()) {
      setError("Please enter a Chrome Web Store URL");
      return;
    }

    // Check cache first
    if (checkCache(url)) {
      return; // Cache modal will handle the rest
    }

    // Proceed with new scan
    await startScan();
  };

  // Handle selecting a recent URL from dropdown
  const handleSelectRecentUrl = (selectedUrl) => {
    setUrl(selectedUrl);
  };

  // Handle sample extension button click
  const handleSampleExtensionClick = () => {
    setShowSampleModal(true);
  };

  // Handle scanning a sample extension
  const handleScanSampleExtension = () => {
    // For demo purposes, we'll use a known extension URL
    const sampleUrl =
      "https://chromewebstore.google.com/detail/adblock/gighmmpiobklfepjocnamgkkbiglidom";
    setUrl(sampleUrl);
    setShowSampleModal(false);

    // Auto-trigger scan
    setTimeout(() => {
      handleScanClick();
    }, 500);
  };

  // Start the actual scan using CLI results
  const startScan = async () => {
    setIsScanning(true);
    setError(null);
    setScanResults(null);

    try {
      const extId = extractExtensionId(url);
      if (!extId) {
        throw new Error("Invalid Chrome Web Store URL format");
      }

      // First, check if the extension has already been scanned
      const status = await realScanService.checkScanStatus(extId);

      if (!status.scanned) {
        // Extension not scanned yet, trigger a scan
        setError(
          "🔄 Starting security scan... This may take a few minutes for large extensions.",
        );
        const scanTrigger = await realScanService.triggerScan(url);

        if (!scanTrigger.success) {
          throw new Error(scanTrigger.error || "Failed to start scan");
        }

        if (scanTrigger.already_scanned) {
          setError("✅ Extension already scanned! Loading results...");
        } else {
          // Wait for scan to complete (poll for results)
          await waitForScanCompletion(extId);
        }
      }

      // Get scan results
      const results = await realScanService.getRealScanResults(extId);

      // Cache the results
      cacheService.cacheScanResult(extId, results);

      setScanResults(results);
      setError(""); // Clear any scanning messages

      // Reload scan history
      loadScanHistory();
    } catch (err) {
      setError(err.message || "Failed to scan extension.");
    } finally {
      setIsScanning(false);
    }
  };

  // Wait for scan completion by polling
  const waitForScanCompletion = async (extensionId, maxAttempts = 120) => {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10000)); // Wait 10 seconds

      const status = await realScanService.checkScanStatus(extensionId);
      if (status.scanned) {
        setError("✅ Scan completed! Loading results...");
        return;
      }

      const minutes = Math.floor(((attempt + 1) * 10) / 60);
      const seconds = ((attempt + 1) * 10) % 60;
      setError(
        `🔄 Scanning in progress... ${minutes}m ${seconds}s - Large extensions take time to analyze. You can close this and check back later.`,
      );
    }

    throw new Error(
      "Scan timeout - extension analysis took too long (20 minutes limit)",
    );
  };

  // Handle cache modal actions
  const handleViewCached = () => {
    setShowCacheModal(false);
    setScanResults(cachedData.data);
  };

  const handleReScan = () => {
    setShowCacheModal(false);
    startScan();
  };

  const handleCloseCacheModal = () => {
    setShowCacheModal(false);
    setCachedData(null);
    setExtensionId("");
  };

  // Load scan from history
  const loadScanFromHistory = async (extId) => {
    try {
      const results = await realScanService.getRealScanResults(extId);
      setScanResults(results);
      setError("");
    } catch (err) {
      setError("Failed to load scan results from history.");
    }
  };

  // File content viewer
  const handleViewFile = async (file) => {
    console.log("Opening file viewer for:", file);
    setFileViewerModal({
      isOpen: true,
      file: file,
    });
  };

  // Wrapper function to maintain service context
  const getFileContent = async (extensionId, filePath) => {
    return await realScanService.getFileContent(extensionId, filePath);
  };

  // AI analysis handler
  const handleAnalyzeWithAI = async (file) => {
    try {
      // For now, show a placeholder. In a real app, you'd call the AI service
      alert(
        `🤖 AI Analysis for ${file.name}\n\nThis would analyze the file content using GPT-OSS for security insights.`,
      );
    } catch (error) {
      alert(`Error starting AI analysis: ${error.message}`);
    }
  };

  // Finding details viewer
  const handleViewFindingDetails = (finding) => {
    const details = `
🚨 Security Finding Details

File: ${finding.file}
Line: ${finding.line}
Severity: ${finding.severity}
Title: ${finding.title}
Description: ${finding.description}
${finding.context ? `Context: ${finding.context}` : ""}
    `;
    alert(details);
  };

  // View all findings
  const handleViewAllFindings = () => {
    alert(
      `Viewing all ${scanResults.totalFindings} findings. In a real app, this would open a comprehensive findings view.`,
    );
  };

  return (
    <div className="dashboard-page">
      {/* Header Section */}
      <div className="dashboard-header">
        <h1 className="fade-in">🚀 Quick Extension Security Scan</h1>
        <p className="fade-in">
          Enter a Chrome Web Store URL to automatically scan and analyze
          security posture
        </p>
      </div>

      {/* Enhanced URL Input Section with Recent URLs and Sample Button */}
      <div className="scan-section">
        <EnhancedUrlInput
          value={url}
          onChange={setUrl}
          onScan={handleScanClick}
          isScanning={isScanning}
          recentUrls={recentUrls}
          onSelectRecent={handleSelectRecentUrl}
          onScanSample={handleSampleExtensionClick}
        />
      </div>

      {/* Sample Extension Modal */}
      <Modal
        open={showSampleModal}
        onRequestClose={() => setShowSampleModal(false)}
        modalHeading="Scan Sample Extension"
        primaryButtonText="Scan AdBlock Extension"
        secondaryButtonText="Cancel"
        onRequestSubmit={handleScanSampleExtension}
        size="sm"
      >
        <p className="sample-modal-text">
          This will scan the popular AdBlock extension as a demonstration of
          ThreatXtension's capabilities. The scan will analyze the extension's
          code for potential security issues.
        </p>
      </Modal>

      {/* Dashboard Overview Section - Below Input */}
      <div className="dashboard-overview">
        <div className="overview-header">
          <h2 className="section-title fade-in">
            📊 Security Dashboard Overview
          </h2>
          <Button
            kind="tertiary"
            size="sm"
            onClick={() => setShowHistory(!showHistory)}
            className="history-toggle-btn"
          >
            {showHistory ? "📊 Hide History" : "📋 View Scan History"}
          </Button>
        </div>

        {/* Scan History Section */}
        {showHistory && scanHistory.length > 0 && (
          <div className="scan-history-section">
            <h3>📋 Recent Scans</h3>
            <div className="history-grid">
              {scanHistory.slice(0, 6).map((scan, index) => (
                <Tile
                  key={index}
                  className="history-tile"
                  onClick={() => loadScanFromHistory(scan.extensionId)}
                >
                  <div className="history-content">
                    <div className="history-icon">🔍</div>
                    <div className="history-info">
                      <h4>{scan.extensionName || scan.extensionId}</h4>
                      <p>
                        Scanned: {new Date(scan.timestamp).toLocaleDateString()}
                      </p>
                      <p>Score: {scan.securityScore || "N/A"}/100</p>
                    </div>
                    <Tag
                      type={
                        scan.riskLevel === "HIGH"
                          ? "red"
                          : scan.riskLevel === "MEDIUM"
                            ? "warm-gray"
                            : "green"
                      }
                      size="sm"
                    >
                      {scan.riskLevel || "UNKNOWN"}
                    </Tag>
                  </div>
                </Tile>
              ))}
            </div>
          </div>
        )}

        {/* Enhanced Stats Grid with Trend Indicators and Sparklines */}
        <div className="stats-grid">
          <EnhancedMetricCard
            icon="🔍"
            title="Total Scans"
            subtitle="Extensions analyzed"
            value={scanHistory.length}
            label={
              scanHistory.length === 1
                ? "Extension scanned"
                : "Extensions scanned"
            }
            variant="primary"
            trend={scanHistory.length > 0 ? 5 : 0} // Example trend: 5% increase
            sparklineData={[4, 6, 8, 7, 9, 11, scanHistory.length]} // Example historical data
            helpText="Total number of Chrome extensions that have been scanned and analyzed for security issues."
            className="fade-in"
          />

          <EnhancedMetricCard
            icon="⚠️"
            title="High Risk"
            subtitle="Critical extensions"
            value={scanHistory.filter((s) => s.riskLevel === "HIGH").length}
            label="High-risk extensions"
            variant="danger"
            trend={-10} // Example trend: 10% decrease (improvement)
            sparklineData={[
              8,
              7,
              9,
              6,
              5,
              4,
              scanHistory.filter((s) => s.riskLevel === "HIGH").length,
            ]} // Example historical data
            helpText="Extensions with critical security vulnerabilities that require immediate attention."
            className="fade-in"
          />

          <EnhancedMetricCard
            icon="📁"
            title="Files Analyzed"
            subtitle="Total files processed"
            value={scanHistory.reduce((sum, s) => sum + (s.totalFiles || 0), 0)}
            label="Files processed"
            variant="success"
            trend={15} // Example trend: 15% increase
            sparklineData={[
              120,
              150,
              180,
              210,
              190,
              230,
              scanHistory.reduce((sum, s) => sum + (s.totalFiles || 0), 0),
            ]} // Example historical data
            helpText="Total number of files that have been analyzed across all scanned extensions."
            className="fade-in"
          />

          <EnhancedMetricCard
            icon="🚨"
            title="Security Findings"
            subtitle="Issues discovered"
            value={scanHistory.reduce(
              (sum, s) => sum + (s.totalFindings || 0),
              0,
            )}
            label="Security issues found"
            variant="warning"
            trend={8} // Example trend: 8% increase
            sparklineData={[
              45,
              52,
              48,
              60,
              55,
              65,
              scanHistory.reduce((sum, s) => sum + (s.totalFindings || 0), 0),
            ]} // Example historical data
            helpText="Total number of security vulnerabilities and issues discovered across all scanned extensions."
            className="fade-in"
          />
        </div>
      </div>

      {/* Status Messages */}
      {error && (
        <StatusMessage
          type={
            error.includes("✅")
              ? "success"
              : error.includes("🔄")
                ? "loading"
                : "error"
          }
          message={error}
          onDismiss={() => setError("")}
          className="fade-in"
        />
      )}

      {/* Clean Loading State */}
      {isScanning && (
        <div className="scanning-section fade-in">
          <div className="scanning-content">
            <div className="simple-loader">
              <div className="spinner"></div>
            </div>
            <h3 className="scanning-title">🔍 Analyzing Extension Security</h3>
            <p className="scanning-text">
              Performing comprehensive security analysis...
            </p>
            <div className="scanning-steps">
              <span className="step active">📥 Downloading</span>
              <span className="step">📦 Extracting</span>
              <span className="step">🔍 Analyzing</span>
              <span className="step">📊 Reporting</span>
            </div>
          </div>
        </div>
      )}

      {/* Enhanced Tabbed Results Section */}
      {scanResults && (
        <TabbedResultsPanel
          scanResults={scanResults}
          onViewFile={handleViewFile}
          onAnalyzeWithAI={handleAnalyzeWithAI}
          onViewFindingDetails={handleViewFindingDetails}
          onViewAllFindings={handleViewAllFindings}
        />
      )}

      {/* File Viewer Modal */}
      <FileViewerModal
        isOpen={fileViewerModal.isOpen}
        onClose={() => setFileViewerModal({ isOpen: false, file: null })}
        file={fileViewerModal.file}
        extensionId={scanResults?.extensionId}
        onGetFileContent={getFileContent}
      />

      {/* Cache Confirmation Modal */}
      <CacheConfirmationModal
        isOpen={showCacheModal}
        onClose={handleCloseCacheModal}
        onViewCached={handleViewCached}
        onReScan={handleReScan}
        cachedData={cachedData}
        extensionId={extensionId}
      />
    </div>
  );
};

export default DashboardPage;
