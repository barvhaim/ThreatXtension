import React, { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import databaseService from "../services/databaseService";
import realScanService from "../services/realScanService";
import TabbedResultsPanel from "../components/TabbedResultsPanel";
import { Search } from "lucide-react";
import { Button } from "../components/ui/button";

const AnalysisPage = () => {
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const loadData = async () => {
      // 1. Try to get ID from URL query params
      const params = new URLSearchParams(location.search);
      let scanId = params.get("id");

      // 2. Fallback: Get most recent scan from history if no ID provided
      if (!scanId) {
        const history = await databaseService.getScanHistory(1);
        if (history.length > 0) {
          scanId = history[0].extension_id;
          // Update URL with the ID so refresh works correctly
          navigate(`/analysis?id=${scanId}`, { replace: true });
        }
      }

      // 3. Load scan results if we have an ID
      if (scanId) {
        const dbResult = await databaseService.getScanResult(scanId);
        if (dbResult) {
          // Format raw database results for TabbedResultsPanel
          const formattedResults = realScanService.formatRealResults(dbResult);
          setScanResults(formattedResults);
        }
      }
      setLoading(false);
    };

    loadData();
  }, [location.search, navigate]);

  // Mock handlers since AnalysisPage is read-only view of past results mainly
  const handleViewFile = (file) => alert(`View file: ${file.name}`);
  const handleAnalyzeWithAI = (file) => alert(`AI analysis for ${file.name}`);
  const handleViewFindingDetails = (finding) => alert(finding.title);
  const handleViewAllFindings = () => alert("All findings view");

  if (loading) {
    return (
      <div className="page-container flex items-center justify-center min-h-[50vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!scanResults) {
    return (
      <div className="page-container">
        <div className="page-header">
          <h1 className="page-title">🔬 Analysis Center</h1>
          <p className="page-subtitle">Detailed security reports and code insights</p>
        </div>
        <div className="glass-card flex flex-col items-center justify-center py-20 text-center">
          <div className="bg-surface-elevated/50 p-6 rounded-full mb-6">
            <Search className="h-12 w-12 text-muted-foreground opacity-50" />
          </div>
          <h2 className="text-2xl font-bold mb-2">No Analysis Data Available</h2>
          <p className="text-muted-foreground max-w-md mb-8">
            Run a new scan from the Dashboard or select a previous scan from History to view detailed analysis.
          </p>
          <Button onClick={() => navigate("/")}>Go to Dashboard</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">🔬 Analysis Report: {scanResults.name || scanResults.extensionId}</h1>
        <p className="page-subtitle">
          Detailed security analysis and SAST findings
        </p>
      </div>

      <div className="glass-card">
        <TabbedResultsPanel
          scanResults={scanResults}
          onViewFile={handleViewFile}
          onAnalyzeWithAI={handleAnalyzeWithAI}
          onViewFindingDetails={handleViewFindingDetails}
          onViewAllFindings={handleViewAllFindings}
        />
      </div>
    </div>
  );
};

export default AnalysisPage;