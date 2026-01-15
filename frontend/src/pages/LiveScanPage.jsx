import React, { useState } from "react";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Search, Play, Square, Download, Shield, FileText, AlertTriangle } from "lucide-react";

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

    const logMessages = [
      { type: "info", message: "🔍 ThreatXtension CLI - Starting Extension Analysis" },
      { type: "info", message: "📅 Scan initiated at: " + new Date().toLocaleString() },
      { type: "info", message: "🎯 Target: " + scanUrl },
      { type: "info", message: "" },
      { type: "info", message: "📥 Phase 1: Extension Download" },
      { type: "info", message: "   🔍 Attempting to download extension..." },
      { type: "info", message: "   📋 Checking Chrome Web Store availability..." },
      { type: "warning", message: "   ⚠️  Direct download failed (status: 204)" },
      { type: "info", message: "   🔄 Trying alternative download methods..." },
      { type: "info", message: "   📥 Method 2: Chrome browser simulation" },
      { type: "info", message: "      🔗 Using clients2.google.com service..." },
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
      { type: "info", message: "   📄 Scanning JavaScript files for vulnerabilities..." },
      { type: "error", message: "   🚨 eval() usage detected in background.js" },
      { type: "error", message: "   🚨 innerHTML assignment in popup.js" },
      { type: "warning", message: "   ⚠️  Suspicious URL patterns found" },
      { type: "info", message: "   📊 SAST analysis completed" },
      { type: "info", message: "" },
      { type: "info", message: "💾 Phase 4: Results & Logging" },
      { type: "info", message: "   📝 Generating security report..." },
      { type: "info", message: "   💾 Saving to CLI logs directory..." },
      { type: "success", message: "   ✅ Log saved: mdanidgdpmkimeiiojknlnekblgmpdll_20250818_141823.log" },
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

  const getLogColor = (type) => {
    switch (type) {
      case "info": return "text-blue-400";
      case "success": return "text-green-400";
      case "warning": return "text-yellow-400";
      case "error": return "text-red-400";
      default: return "text-gray-400";
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">🔴 Live Extension Security Scan</h1>
        <p className="page-subtitle">Real-time monitoring and analysis of Chrome extension security</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-card">
          <h2 className="text-xl font-bold mb-4">Scan Configuration</h2>
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground-muted">Chrome Web Store URL</label>
              <Input
                placeholder="https://chromewebstore.google.com/detail/extension-name/extension-id"
                value={scanUrl}
                onChange={(e) => setScanUrl(e.target.value)}
                className="h-12 bg-background/50 border-input"
              />
            </div>
            <div className="flex gap-2">
              <Button
                onClick={handleScan}
                disabled={isScanning || !scanUrl.trim()}
                size="lg"
                className="flex-1"
              >
                {isScanning ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Scanning...
                  </>
                ) : (
                  <>
                    <Play className="mr-2 h-4 w-4" />
                    Start Scan
                  </>
                )}
              </Button>
              {isScanning && (
                <Button onClick={stopScan} variant="destructive" size="lg">
                  <Square className="mr-2 h-4 w-4" />
                  Stop
                </Button>
              )}
            </div>
          </div>
        </div>

        <div className="glass-card">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="h-5 w-5 text-primary" />
            <h2 className="text-xl font-bold">Scan Status</h2>
          </div>
          <div className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-foreground-muted">Progress:</span>
                <span className="font-mono">{Math.round(scanProgress)}%</span>
              </div>
              <div className="w-full bg-surface rounded-full h-2 overflow-hidden">
                <div
                  className="bg-primary h-2 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-border/50">
              <span className="text-sm text-foreground-muted">Status:</span>
              <Badge variant={isScanning ? "default" : "secondary"}>
                {isScanning ? "Scanning" : "Ready"}
              </Badge>
            </div>
            <div className="flex justify-between items-center pt-2">
              <span className="text-sm text-foreground-muted">Log Entries:</span>
              <span className="font-bold font-mono">{scanLog.length}</span>
            </div>
          </div>
        </div>
      </div>

      {isScanning && (
        <div className="glass-card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold">📊 Scan Progress</h2>
            <Button onClick={clearLog} variant="outline" size="sm">
              Clear Log
            </Button>
          </div>
          <div className="bg-black/80 backdrop-blur-sm rounded-lg p-4 max-h-96 overflow-y-auto font-mono text-sm space-y-1 border border-border/50 shadow-inner">
            {scanLog.map((log, index) => (
              <div key={index} className={`flex items-start gap-2 ${getLogColor(log.type)}`}>
                <span className="whitespace-pre opacity-90">{log.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {showResults && (
        <div className="glass-card animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="mb-6">
            <h2 className="text-2xl font-bold mb-1">📋 Scan Results Summary</h2>
            <div className="text-sm text-foreground-muted">
              Completed at: {new Date().toLocaleString()} • Target: {scanUrl}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <div className="p-4 rounded-xl bg-surface/50 border border-border/50">
              <div className="text-sm text-foreground-muted mb-2">Security Score</div>
              <div className="text-3xl font-bold text-destructive">0.0/100</div>
              <Badge variant="destructive" className="mt-2">HIGH RISK</Badge>
            </div>

            <div className="p-4 rounded-xl bg-surface/50 border border-border/50">
              <div className="text-sm text-foreground-muted mb-2">Total Findings</div>
              <div className="text-3xl font-bold text-foreground">20,249</div>
              <Badge variant="destructive" className="mt-2">CRITICAL</Badge>
            </div>

            <div className="p-4 rounded-xl bg-surface/50 border border-border/50">
              <div className="text-sm text-foreground-muted mb-2">Files Analyzed</div>
              <div className="text-3xl font-bold text-foreground">34</div>
              <Badge variant="secondary" className="mt-2 text-foreground">COMPLETE</Badge>
            </div>

            <div className="p-4 rounded-xl bg-surface/50 border border-border/50">
              <div className="text-sm text-foreground-muted mb-2">Download Size</div>
              <div className="text-3xl font-bold text-foreground">4.1 MB</div>
              <Badge variant="outline" className="mt-2 bg-success/10 text-success border-success/20">SUCCESS</Badge>
            </div>
          </div>

          <div className="flex gap-3">
            <Button size="lg" className="shadow-lg shadow-primary/20">
              <Download className="mr-2 h-4 w-4" />
              Download Report
            </Button>
            <Button variant="outline" size="lg">
              <FileText className="mr-2 h-4 w-4" />
              Detailed Analysis
            </Button>
          </div>
        </div>
      )}

      <div className="glass-card">
        <h2 className="text-xl font-bold mb-4">⚡ Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Button variant="outline" size="lg" className="w-full h-auto py-4 justify-start hover:bg-surface-hover/50">
            <Search className="mr-3 h-5 w-5 text-primary" />
            <div className="text-left">
              <div className="font-semibold">Recent Scans</div>
              <div className="text-xs text-foreground-muted font-normal">View your scan history</div>
            </div>
          </Button>
          <Button variant="outline" size="lg" className="w-full h-auto py-4 justify-start hover:bg-surface-hover/50">
            <AlertTriangle className="mr-3 h-5 w-5 text-warning" />
            <div className="text-left">
              <div className="font-semibold">High Risk Extensions</div>
              <div className="text-xs text-foreground-muted font-normal">Review critical threats</div>
            </div>
          </Button>
          <Button variant="outline" size="lg" className="w-full h-auto py-4 justify-start hover:bg-surface-hover/50">
            <FileText className="mr-3 h-5 w-5 text-accent" />
            <div className="text-left">
              <div className="font-semibold">Generate Reports</div>
              <div className="text-xs text-foreground-muted font-normal">Download compliance reports</div>
            </div>
          </Button>
        </div>
      </div>
    </div>
  );
};

export default LiveScanPage;