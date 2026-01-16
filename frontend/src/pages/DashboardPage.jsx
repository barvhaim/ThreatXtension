import React, { useState, useEffect } from "react";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Badge } from "../components/ui/badge";
import EnhancedMetricCard from "../components/EnhancedMetricCard";
import EnhancedUrlInput from "../components/EnhancedUrlInput";
import TabbedResultsPanel from "../components/TabbedResultsPanel";
import StatusMessage from "../components/StatusMessage";
import realScanService from "../services/realScanService";
import databaseService from "../services/databaseService";
import FileViewerModal from "../components/FileViewerModal";
import "./DashboardPage.scss";

const DashboardPage = () => {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  // const [showSampleModal, setShowSampleModal] = useState(false);
  const [fileViewerModal, setFileViewerModal] = useState({
    isOpen: false,
    file: null,
  });

  useEffect(() => {
    loadScanHistory();
    loadDashboardStats();
  }, []);

  const loadScanHistory = async () => {
    try {
      const history = await databaseService.getScanHistory(50);
      setScanHistory(history);
      
      // Initially show history if there is any
      if (history.length > 0) {
        setShowHistory(true);
      }
    } catch (error) {
      console.error("Error loading scan history:", error);
      setScanHistory([]);
    }
  };

  const [dashboardStats, setDashboardStats] = useState({
    totalScans: { value: 0, sparkline: [0] },
    highRisk: { value: 0, sparkline: [0] },
    totalFiles: { value: 0, sparkline: [0] },
    totalVulnerabilities: { value: 0, sparkline: [0] }
  });

  const loadDashboardStats = async () => {
    try {
      const metrics = await databaseService.getDashboardMetrics();
      setDashboardStats(metrics);
    } catch (error) {
      console.error("Error loading dashboard stats:", error);
    }
  };

  const extractExtensionId = (url) => {
    return realScanService.extractExtensionId(url);
  };

  const handleScanClick = async () => {
    if (!url.trim()) {
      setError("Please enter a Chrome Web Store URL");
      return;
    }
    await startScan();
  };



  // const handleScanSampleExtension = () => {
  //   const sampleUrl = "https://chromewebstore.google.com/detail/adblock/gighmmpiobklfepjocnamgkkbiglidom";
  //   setUrl(sampleUrl);
  //   setShowSampleModal(false);
  //   setTimeout(() => {
  //     handleScanClick();
  //   }, 500);
  // };

  const startScan = async () => {
    setIsScanning(true);
    setError(null);
    setScanResults(null);

    try {
      const extId = extractExtensionId(url);
      if (!extId) {
        throw new Error("Invalid Chrome Web Store URL format");
      }

      const status = await realScanService.checkScanStatus(extId);

      if (!status.scanned) {
        setError("🔄 Starting security scan... This may take a few minutes for large extensions.");
        const scanTrigger = await realScanService.triggerScan(url);

        // Check for success based on running status available in the response
        if (scanTrigger.status !== "running") {
          throw new Error(scanTrigger.error || "Failed to start scan");
        }

        if (scanTrigger.already_scanned) {
          setError("✅ Extension already scanned! Loading results...");
        } else {
          await waitForScanCompletion(extId);
        }
      }

      const results = await realScanService.getRealScanResults(extId);
      setScanResults(results);
      setError("");
      await loadScanHistory();
      await loadDashboardStats();
    } catch (err) {
      setError(err.message || "Failed to scan extension.");
    } finally {
      setIsScanning(false);
    }
  };

  const waitForScanCompletion = async (extensionId, maxAttempts = 120) => {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 5000));
      const status = await realScanService.checkScanStatus(extensionId);

      if (status.scanned) {
        setError("✅ Scan completed! Loading results...");
        return;
      }

      if (status.status === "failed") {
        throw new Error(status.error || "Scan failed on the server.");
      }

      const minutes = Math.floor(((attempt + 1) * 5) / 60);
      const seconds = ((attempt + 1) * 5) % 60;
      setError(`🔄 Scanning in progress... ${minutes}m ${seconds}s - Large extensions take time to analyze.`);
    }
    throw new Error("Scan timeout - extension analysis took too long (10 minutes limit)");
  };

  const loadScanFromHistory = async (extId) => {
    try {
      // Try database first
      let results = await databaseService.getScanResult(extId);
      
      // Fallback to API if not in database
      if (!results) {
        results = await realScanService.getRealScanResults(extId);
      }
      
      // Format the results if they're raw from database
      if (results && !results.files) {
        results = realScanService.formatRealResults(results);
      }
      
      setScanResults(results);
      setError("");
    } catch (err) {
      console.error(err);
      setError("Failed to load scan results from history.");
    }
  };

  const handleViewFile = async (file) => {
    setFileViewerModal({ isOpen: true, file: file });
  };

  const getFileContent = async (extensionId, filePath) => {
    return await realScanService.getFileContent(extensionId, filePath);
  };

  const handleAnalyzeWithAI = async (file) => {
    alert(`🤖 AI Analysis for ${file.name}\n\nThis would analyze the file content using GPT-OSS for security insights.`);
  };

  const handleViewFindingDetails = (finding) => {
    const details = `🚨 Security Finding Details\n\nFile: ${finding.file}\nLine: ${finding.line}\nSeverity: ${finding.severity}\nTitle: ${finding.title}\nDescription: ${finding.description}`;
    alert(details);
  };

  const handleViewAllFindings = () => {
    alert(`Viewing all ${scanResults.totalFindings} findings.`);
  };

  return (
    <div className="dashboard-page">
      {/* Premium Hero Section */}
      <section className="dashboard-hero">
        <div className="hero-content">
          <h1 className="hero-title">
            <span className="text-gradient">Secure Your Browser</span>
          </h1>
          <p className="hero-subtitle">
            Advanced security analysis for Chrome Extensions.
            <br className="hidden md:block" />
            Detect vulnerabilities, malware, and privacy risks in seconds.
          </p>
        </div>

        {/* Search/Scan Input */}
        <div className="scan-highlight-box">
          <EnhancedUrlInput
            value={url}
            onChange={setUrl}
            onScan={handleScanClick}
            isScanning={isScanning}
          />
        </div>
      </section>

      {/* Stats Overview */}
      <div className="dashboard-content-wrapper">
        <div className="section-header-row">
          <h2 className="section-title">
            <span className="icon">📊</span> Security Overview
          </h2>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowHistory(!showHistory)}
            className="history-toggle-btn"
          >
            {showHistory ? "Hide History" : "Show History"}
          </Button>
        </div>

        <div className="stats-grid">
          <EnhancedMetricCard
            icon="🔍"
            title="Total Scans"
            subtitle="Analyzed Extensions"
            value={dashboardStats.totalScans.value}
            label={dashboardStats.totalScans.value === 1 ? "Scan completed" : "Scans completed"}
            variant="primary"
            trend={null}
            sparklineData={dashboardStats.totalScans.sparkline}
            helpText="Total number of unique Chrome extensions analyzed."
          />
          <EnhancedMetricCard
            icon="🛡️"
            title="High Risk"
            subtitle="Critical Threats"
            value={dashboardStats.highRisk.value}
            label="Critical issues found"
            variant="danger"
            trend={null}
            sparklineData={dashboardStats.highRisk.sparkline}
            helpText="Extensions identified with critical security vulnerabilities."
          />
          <EnhancedMetricCard
            icon="📁"
            title="Code Analysis"
            subtitle="Files Processed"
            value={dashboardStats.totalFiles.value}
            label="Source files analyzed"
            variant="success"
            trend={null}
            sparklineData={dashboardStats.totalFiles.sparkline}
            helpText="Total file count processed across all scans."
          />
          <EnhancedMetricCard
            icon="🚨"
            title="Vulnerabilities"
            subtitle="Issues Detected"
            value={dashboardStats.totalVulnerabilities.value}
            label="Security alerts"
            variant="warning"
            trend={null}
            sparklineData={dashboardStats.totalVulnerabilities.sparkline}
            helpText="Aggregated count of security findings and potential risks."
          />
        </div>
      </div>

      {/* Recent Activity / History */}
      {showHistory && scanHistory.length > 0 && (
        <div className="dashboard-content-wrapper mt-8">
          <h3 className="section-title mb-4">
            <span className="icon">🕒</span> Recent Activity
          </h3>
          <div className="history-grid">
            {scanHistory.slice(0, 8).map((scan, index) => (
              <div
                key={index}
                className="history-tile"
                onClick={() => loadScanFromHistory(scan.extension_id || scan.extensionId)}
              >
                <div className="history-content">
                  <div className="history-icon-wrapper">
                    <span className="history-icon">📦</span>
                  </div>
                  <div className="history-info">
                    <h4>{scan.extension_name || scan.extensionName || scan.extension_id || scan.extensionId}</h4>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground mt-1">
                      <span>{new Date(scan.timestamp).toLocaleDateString()}</span>
                      <span className="w-1 h-1 rounded-full bg-border"></span>
                      <span>Score: {scan.security_score || scan.securityScore || "N/A"}</span>
                    </div>
                    <div className="mt-2">
                      <Badge
                        variant={
                          (scan.risk_level || scan.riskLevel || "").toUpperCase() === "HIGH" ? "destructive" :
                            (scan.risk_level || scan.riskLevel || "").toUpperCase() === "MEDIUM" ? "secondary" :
                              "outline"
                        }
                        className="text-[10px] h-5 px-2"
                      >
                        {(scan.risk_level || scan.riskLevel || "UNKNOWN").toUpperCase()}
                      </Badge>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Status & Loading */}
      {error && (
        <StatusMessage
          type={error.includes("✅") ? "success" : error.includes("🔄") ? "loading" : "error"}
          message={error}
          onDismiss={() => setError("")}
        />
      )}

      {isScanning && (
        <div className="scanning-section">
          <div className="scanning-content">
            <div className="simple-loader">
              <div className="spinner"></div>
            </div>
            <h3 className="scanning-title">Performing Deep Scan</h3>
            <p className="scanning-text">Analyzing extension package structure, permissions, and code patterns...</p>
            <div className="scanning-steps">
              <span className="step active">📥 Fetching</span>
              <span className="step">📦 Unpacking</span>
              <span className="step">🔍 Static Analysis</span>
              <span className="step">🛡️ Threat Check</span>
            </div>
          </div>
        </div>
      )}

      {/* Results Panel */}
      {scanResults && (
        <div className="mt-8">
          <TabbedResultsPanel
            scanResults={scanResults}
            onViewFile={handleViewFile}
            onAnalyzeWithAI={handleAnalyzeWithAI}
            onViewFindingDetails={handleViewFindingDetails}
            onViewAllFindings={handleViewAllFindings}
          />
        </div>
      )}

      {/* Modals */}
      <FileViewerModal
        isOpen={fileViewerModal.isOpen}
        onClose={() => setFileViewerModal({ isOpen: false, file: null })}
        file={fileViewerModal.file}
        extensionId={scanResults?.extensionId}
        onGetFileContent={getFileContent}
      />
    </div>
  );
};

export default DashboardPage;
