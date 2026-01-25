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
import gptOssService from "../services/gptOssService";
import FileViewerModal from "../components/FileViewerModal";
import FindingDetailsModal from "../components/FindingDetailsModal";
import AllFindingsModal from "../components/AllFindingsModal";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "../components/ui/dialog";
import { Loader2 } from "lucide-react";
import "./DashboardPage.scss";

const DashboardPage = () => {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [forceRescan, setForceRescan] = useState(false);
  // const [showSampleModal, setShowSampleModal] = useState(false);
  const [fileViewerModal, setFileViewerModal] = useState({
    isOpen: false,
    file: null,
  });
  const [findingDetailsModal, setFindingDetailsModal] = useState({
    isOpen: false,
    finding: null,
  });
  const [allFindingsModal, setAllFindingsModal] = useState({
    isOpen: false,
  });
  const [aiAnalysisModal, setAiAnalysisModal] = useState({
    isOpen: false,
    file: null,
    isAnalyzing: false,
    result: null,
    error: null,
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

  const handleFileUpload = async (file) => {
    setIsScanning(true);
    setError(null);
    setScanResults(null);

    try {
      setError("📤 Uploading file... This may take a moment.");
      
      // Upload the file
      const uploadResult = await realScanService.uploadAndScan(file);
      
      if (!uploadResult || !uploadResult.extension_id) {
        throw new Error("Failed to upload file");
      }

      const extensionId = uploadResult.extension_id;
      setError(`🔄 File uploaded successfully! Starting analysis...`);

      // Wait for scan completion
      await waitForScanCompletion(extensionId);

      // Get results
      const results = await realScanService.getRealScanResults(extensionId);
      setScanResults(results);
      setError("");
      
      // Refresh history and stats
      await loadScanHistory();
      await loadDashboardStats();
    } catch (err) {
      setError(err.message || "Failed to upload and scan file.");
    } finally {
      setIsScanning(false);
    }
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
      // Check if input is already an extension ID (32 lowercase letters a-p)
      const isExtensionId = /^[a-p]{32}$/.test(url.trim().toLowerCase());
      
      let extId;
      if (isExtensionId) {
        // Input is already an extension ID
        extId = url.trim().toLowerCase();
      } else {
        // Try to extract ID from URL
        extId = extractExtensionId(url);
        if (!extId) {
          throw new Error("Invalid input. Please enter a Chrome Web Store URL or extension ID (32-character string)");
        }
      }

      const status = await realScanService.checkScanStatus(extId);

      if (!status.scanned || forceRescan) {
        setError(forceRescan ? "🔄 Force re-scanning extension..." : "🔄 Starting security scan... This may take a few minutes for large extensions.");
        const scanTrigger = await realScanService.triggerScan(url, forceRescan);

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
    // Open modal and start analysis
    setAiAnalysisModal({
      isOpen: true,
      file: file,
      isAnalyzing: true,
      result: null,
      error: null,
    });

    try {
      // Get file content
      const fileContent = await realScanService.getFileContent(
        scanResults.extensionId,
        file.path
      );

      // Determine file type
      const fileType = file.type || file.name.split('.').pop() || 'unknown';

      // Analyze with GPT-OSS
      const analysisResult = await gptOssService.analyzeFileContent(
        fileContent,
        file.name,
        fileType,
        'auto' // Use auto provider selection
      );

      if (analysisResult.success) {
        setAiAnalysisModal(prev => ({
          ...prev,
          isAnalyzing: false,
          result: analysisResult.data,
        }));
      } else {
        throw new Error(analysisResult.error || 'Analysis failed');
      }
    } catch (err) {
      console.error('AI analysis error:', err);
      setAiAnalysisModal(prev => ({
        ...prev,
        isAnalyzing: false,
        error: err.message || 'Failed to analyze file with AI',
      }));
    }
  };

  const closeAiAnalysisModal = () => {
    setAiAnalysisModal({
      isOpen: false,
      file: null,
      isAnalyzing: false,
      result: null,
      error: null,
    });
  };

  const handleViewFindingDetails = (finding) => {
    setFindingDetailsModal({
      isOpen: true,
      finding: finding,
    });
  };

  const handleViewAllFindings = () => {
    setAllFindingsModal({
      isOpen: true,
    });
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
            onFileUpload={handleFileUpload}
            isScanning={isScanning}
          />
          
          {/* Force Re-scan Checkbox */}
          <div style={{
            marginTop: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '14px',
            color: '#64748b'
          }}>
            <input
              type="checkbox"
              id="force-rescan"
              checked={forceRescan}
              onChange={(e) => setForceRescan(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            <label
              htmlFor="force-rescan"
              style={{ cursor: 'pointer', userSelect: 'none' }}
            >
              Force re-scan (ignore cached results)
            </label>
          </div>
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

      <FindingDetailsModal
        isOpen={findingDetailsModal.isOpen}
        onClose={() => setFindingDetailsModal({ isOpen: false, finding: null })}
        finding={findingDetailsModal.finding}
        extensionId={scanResults?.extensionId}
        onGetFileContent={getFileContent}
      />

      <AllFindingsModal
        isOpen={allFindingsModal.isOpen}
        onClose={() => setAllFindingsModal({ isOpen: false })}
        findings={scanResults?.sastResults || []}
        onViewFindingDetails={handleViewFindingDetails}
      />

      {/* AI Analysis Modal */}
      <Dialog open={aiAnalysisModal.isOpen} onOpenChange={closeAiAnalysisModal}>
        <DialogContent className="sm:max-w-[800px] max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              🤖 AI Security Analysis
              {aiAnalysisModal.file && ` - ${aiAnalysisModal.file.name}`}
            </DialogTitle>
            <DialogDescription>
              Advanced AI-powered security analysis using GPT-OSS
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {aiAnalysisModal.isAnalyzing && (
              <div className="flex flex-col items-center justify-center py-12 space-y-4">
                <Loader2 className="h-12 w-12 animate-spin text-primary" />
                <div className="text-center">
                  <p className="font-medium">Analyzing file with AI...</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    This may take a few moments depending on file size
                  </p>
                </div>
              </div>
            )}

            {aiAnalysisModal.error && (
              <div className="p-4 bg-destructive/10 border border-destructive rounded-lg">
                <div className="flex items-start gap-3">
                  <span className="text-2xl">❌</span>
                  <div className="flex-1">
                    <h4 className="font-semibold text-destructive mb-1">Analysis Failed</h4>
                    <p className="text-sm">{aiAnalysisModal.error}</p>
                    <p className="text-xs text-muted-foreground mt-2">
                      Make sure the backend API is running and LLM providers are configured.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {aiAnalysisModal.result && !aiAnalysisModal.isAnalyzing && (
              <div className="space-y-4">
                {/* Analysis Summary */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Analysis Summary</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <div className="text-sm text-muted-foreground">Risk Score</div>
                        <div className="flex items-center gap-2">
                          <span className={`text-2xl font-bold ${
                            aiAnalysisModal.result.riskScore >= 8 ? 'text-red-500' :
                            aiAnalysisModal.result.riskScore >= 5 ? 'text-yellow-500' :
                            'text-green-500'
                          }`}>
                            {aiAnalysisModal.result.riskScore || 'N/A'}
                          </span>
                          <span className="text-muted-foreground">/10</span>
                        </div>
                      </div>
                      <div>
                        <div className="text-sm text-muted-foreground">Severity</div>
                        <Badge variant={
                          aiAnalysisModal.result.severity === 'High' ? 'destructive' :
                          aiAnalysisModal.result.severity === 'Medium' ? 'secondary' :
                          'default'
                        } className="mt-1">
                          {aiAnalysisModal.result.severity || 'Unknown'}
                        </Badge>
                      </div>
                    </div>
                    {aiAnalysisModal.result.confidence && (
                      <div>
                        <div className="text-sm text-muted-foreground">Confidence</div>
                        <div className="font-medium">{aiAnalysisModal.result.confidence}</div>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Detailed Analysis */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Detailed Analysis</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="prose prose-sm max-w-none dark:prose-invert">
                      <pre className="whitespace-pre-wrap text-sm bg-muted p-4 rounded-lg">
                        {aiAnalysisModal.result.analysis}
                      </pre>
                    </div>
                  </CardContent>
                </Card>

                {/* Findings */}
                {aiAnalysisModal.result.findings && aiAnalysisModal.result.findings.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Key Findings</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ul className="space-y-2">
                        {aiAnalysisModal.result.findings.map((finding, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="text-primary mt-1">•</span>
                            <span className="text-sm">{finding}</span>
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                )}

                {/* Recommendations */}
                {aiAnalysisModal.result.recommendations && aiAnalysisModal.result.recommendations.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Recommendations</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ul className="space-y-2">
                        {aiAnalysisModal.result.recommendations.map((rec, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="text-green-500 mt-1">✓</span>
                            <span className="text-sm">{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                )}

                {/* Metadata */}
                {aiAnalysisModal.result.metadata && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Analysis Metadata</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-2 gap-3 text-sm">
                        {aiAnalysisModal.result.metadata.model && (
                          <div>
                            <div className="text-muted-foreground">Model</div>
                            <div className="font-medium">{aiAnalysisModal.result.metadata.model}</div>
                          </div>
                        )}
                        {aiAnalysisModal.result.metadata.deployment && (
                          <div>
                            <div className="text-muted-foreground">Deployment</div>
                            <div className="font-medium">{aiAnalysisModal.result.metadata.deployment}</div>
                          </div>
                        )}
                        {aiAnalysisModal.result.metadata.tokens_used && (
                          <div>
                            <div className="text-muted-foreground">Tokens Used</div>
                            <div className="font-medium">{aiAnalysisModal.result.metadata.tokens_used}</div>
                          </div>
                        )}
                        {aiAnalysisModal.result.metadata.analysis_duration && (
                          <div>
                            <div className="text-muted-foreground">Duration</div>
                            <div className="font-medium">{aiAnalysisModal.result.metadata.analysis_duration}</div>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 mt-4">
            <Button variant="outline" onClick={closeAiAnalysisModal}>
              Close
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default DashboardPage;
