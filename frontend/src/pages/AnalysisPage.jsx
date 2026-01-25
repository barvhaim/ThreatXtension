import React, { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import databaseService from "../services/databaseService";
import realScanService from "../services/realScanService";
import gptOssService from "../services/gptOssService";
import TabbedResultsPanel from "../components/TabbedResultsPanel";
import FileViewerModal from "../components/FileViewerModal";
import FindingDetailsModal from "../components/FindingDetailsModal";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "../components/ui/dialog";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Search, Loader2 } from "lucide-react";
import { Button } from "../components/ui/button";

const AnalysisPage = () => {
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();
  const [fileViewerModal, setFileViewerModal] = useState({
    isOpen: false,
    file: null,
  });
  const [aiAnalysisModal, setAiAnalysisModal] = useState({
    isOpen: false,
    file: null,
    isAnalyzing: false,
    result: null,
    error: null,
  });
  const [findingDetailsModal, setFindingDetailsModal] = useState({
    isOpen: false,
    finding: null,
  });
  const [allFindingsModal, setAllFindingsModal] = useState({
    isOpen: false,
  });

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

      {/* Modals */}
      <FileViewerModal
        isOpen={fileViewerModal.isOpen}
        onClose={() => setFileViewerModal({ isOpen: false, file: null })}
        file={fileViewerModal.file}
        extensionId={scanResults?.extensionId}
        onGetFileContent={getFileContent}
      />

      {/* Finding Details Modal */}
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

export default AnalysisPage;