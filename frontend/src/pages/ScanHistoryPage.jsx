import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Download, Eye, Shield, FileText, AlertTriangle, CheckCircle, XCircle, Info } from "lucide-react";

import databaseService from "../services/databaseService";

/**
 * ScanHistoryPage Component
 * Displays viewing history of scanned extensions with a premium glassmorphism design.
 */
const ScanHistoryPage = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const loadHistory = async () => {
      try {
        const history = await databaseService.getScanHistory(100);
        const formattedHistory = history.map(item => ({
          ...item,
          name: item.extension_name || item.extensionId || item.extension_id,
          id: item.extension_id || item.extensionId,
          filesAnalyzed: item.total_files || 0,
          downloadSize: item.downloadSize || "N/A",
          version: item.version || "N/A",
          securityScore: item.security_score || 0,
          riskLevel: item.risk_level || "unknown",
          totalFindings: item.total_findings || 0
        }));
        setScans(formattedHistory);
      } catch (error) {
        console.error("Failed to load scan history:", error);
      } finally {
        setLoading(false);
      }
    };

    loadHistory();
  }, []);

  const getRiskBadgeVariant = (riskLevel) => {
    switch (riskLevel) {
      case "high": return "destructive";
      case "medium": return "secondary";
      case "low": return "default"; // Will rely on default success color in theme if mapped, otherwise primary
      default: return "outline";
    }
  };

  const getRiskIcon = (riskLevel) => {
    switch (riskLevel) {
      case "high": return <XCircle className="h-4 w-4" />;
      case "medium": return <AlertTriangle className="h-4 w-4" />;
      case "low": return <CheckCircle className="h-4 w-4" />;
      default: return <Info className="h-4 w-4" />;
    }
  };

  const filteredScans = scans.filter(scan =>
    scan.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    scan.id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleExport = () => {
    const dataToExport = filteredScans.map(scan => ({
      id: scan.id,
      name: scan.name,
      version: scan.version,
      timestamp: scan.timestamp,
      securityScore: scan.securityScore,
      riskLevel: scan.riskLevel,
      totalFindings: scan.totalFindings,
      filesAnalyzed: scan.filesAnalyzed
    }));

    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threatxtension-history-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">Scan Log</h1>
        <p className="page-subtitle">
          View and manage your extension security scan history
        </p>
      </div>

      <div className="glass-card mb-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 mb-6">
          <h2 className="text-xl font-bold flex items-center gap-2">
            <FileText className="text-primary" size={18} strokeWidth={2.25} /> Recent Scans
            <Badge variant="outline" className="ml-2">{scans.length}</Badge>
          </h2>
          <div className="flex gap-2 w-full md:w-auto">
            <Input
              placeholder="Search scans..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full md:w-64 bg-background/50"
            />
            <Button variant="outline" onClick={handleExport}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12 text-muted-foreground">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mr-3"></div>
            <span>Loading scan history...</span>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredScans.map((scan) => (
              <div
                key={scan.id}
                className="p-4 rounded-xl border border-border/50 bg-card/30 hover:bg-card/50 transition-all hover:border-primary/50 group"
              >
                <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                  <div className="flex-1 space-y-1">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                        <Shield className="h-5 w-5" />
                      </div>
                      <div>
                        <h3 className="font-bold text-lg leading-none">{scan.name}</h3>
                        <p className="text-sm text-muted-foreground mt-1">
                          Version {scan.version} • {scan.timestamp}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="flex-1 grid grid-cols-2 lg:grid-cols-4 gap-4 w-full lg:w-auto">
                    <div>
                      <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1" title="Higher is more dangerous (100 = critical)">Risk Score ↑</div>
                      <div className={`text-xl font-bold ${scan.securityScore >= 61 ? "text-destructive" :
                        scan.securityScore >= 36 ? "text-orange-500" :
                          scan.securityScore >= 16 ? "text-yellow-500" : "text-success"
                        }`}>
                        {scan.securityScore}<span className="text-xs font-medium text-muted-foreground">/100</span>
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Risk</div>
                      <Badge variant={getRiskBadgeVariant(scan.riskLevel)} className="h-7 px-3">
                        {getRiskIcon(scan.riskLevel)}
                        <span className="ml-2">{scan.riskLevel.toUpperCase()}</span>
                      </Badge>
                    </div>

                    <div>
                      <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Findings</div>
                      <div className="text-xl font-bold text-foreground">{scan.totalFindings.toLocaleString()}</div>
                    </div>

                    <div>
                      <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Files</div>
                      <div className="text-xl font-bold text-foreground">{scan.filesAnalyzed}</div>
                    </div>
                  </div>

                  <div className="flex gap-2 w-full lg:w-auto mt-2 lg:mt-0 pt-4 lg:pt-0 border-t border-border/20 lg:border-0">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => navigate(`/analysis?id=${scan.id}`)}
                      className="flex-1 lg:flex-none"
                    >
                      <Eye className="mr-2 h-4 w-4" />
                      View
                    </Button>
                  </div>
                </div>
              </div>
            ))}

            {filteredScans.length === 0 && (
              <div className="text-center py-16 text-muted-foreground glass-card border-dashed">
                <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No scans found matching your search.</p>
              </div>
            )}
          </div>
        )}
      </div>

      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="glass-card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold">Scan Details</h2>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setSelectedScan(null)}
              >
                <XCircle className="h-6 w-6 opacity-70 hover:opacity-100" />
              </Button>
            </div>

            <div className="space-y-6">
              <div className="flex items-center gap-4 p-4 rounded-lg bg-surface-elevated/50 border border-border">
                <div className="w-16 h-16 rounded-lg bg-primary/15 border border-primary/40 flex items-center justify-center text-primary">
                  <Shield size={26} strokeWidth={2} />
                </div>
                <div>
                  <h3 className="text-xl font-bold">{selectedScan.name}</h3>
                  <p className="text-muted-foreground">{selectedScan.id}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 rounded-lg bg-surface/50 border border-border/50">
                  <div className="text-sm text-muted-foreground mb-1">Risk Score</div>
                  <div className={`text-2xl font-bold ${selectedScan.securityScore >= 61 ? "text-destructive" :
                    selectedScan.securityScore >= 36 ? "text-orange-500" :
                      selectedScan.securityScore >= 16 ? "text-yellow-500" : "text-success"
                    }`}>
                    {selectedScan.securityScore}<span className="text-sm font-medium text-muted-foreground">/100</span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">higher is riskier · 100 = critical</div>
                </div>
                <div className="p-4 rounded-lg bg-surface/50 border border-border/50">
                  <div className="text-sm text-muted-foreground mb-1">Download Size</div>
                  <div className="text-2xl font-bold text-foreground">{selectedScan.downloadSize}</div>
                </div>
              </div>

              <div className="flex justify-end pt-4">
                <Button onClick={() => setSelectedScan(null)}>
                  Close Details
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanHistoryPage;