import React, { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Info, Filter, ChevronDown, ChevronUp, Download, Shield, AlertTriangle, FileWarning } from "lucide-react";
import ChromeStatsTab from "./ChromeStatsTab";


/**
 * Tabbed Results Panel Component for organizing scan results
 */
const TabbedResultsPanel = ({
  scanResults,
  onViewFile,
  onAnalyzeWithAI,
  onViewFindingDetails,
  onViewAllFindings,
  onGenerateSASTSignature,
}) => {
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [collapsedSections, setCollapsedSections] = useState({});

  if (!scanResults) return null;

  const toggleSection = (sectionId) => {
    setCollapsedSections((prev) => ({
      ...prev,
      [sectionId]: !prev[sectionId],
    }));
  };

  const isSectionCollapsed = (sectionId) => {
    return !!collapsedSections[sectionId];
  };

  const filteredFindings =
    severityFilter === "ALL"
      ? scanResults.sastResults || []
      : (scanResults.sastResults || []).filter(
        (finding) => finding.severity === severityFilter,
      );

  return (
    <div className="space-y-6">
      <h2 className="text-3xl font-bold">🔒 Security Analysis Results</h2>

      {/* Key Metrics Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Security Score</CardTitle>
              <span className="text-2xl">🛡️</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-2">
              <span className={`text-4xl font-bold ${scanResults.securityScore < 40 ? "text-red-500" :
                scanResults.securityScore < 65 ? "text-orange-500" :
                  scanResults.securityScore < 85 ? "text-yellow-500" : "text-green-500"
                }`}>
                {scanResults.securityScore || 0}
              </span>
              <span className="text-muted-foreground">/100</span>
            </div>
            <p className="text-sm text-muted-foreground mt-2">
              {scanResults.securityScore < 40 ? "Critical Issues" :
                scanResults.securityScore < 65 ? "High Risk" :
                  scanResults.securityScore < 85 ? "Moderate" : "Secure"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Risk Level</CardTitle>
              <span className="text-2xl">⚠️</span>
            </div>
          </CardHeader>
          <CardContent>
            <Badge variant={
              scanResults.riskLevel === "CRITICAL" ? "destructive" :
                scanResults.riskLevel === "HIGH" ? "destructive" :
                  scanResults.riskLevel === "MEDIUM" ? "secondary" : "default"
            } className="text-lg px-4 py-1">
              {scanResults.riskLevel || "UNKNOWN"}
            </Badge>
            <p className="text-sm text-muted-foreground mt-2">
              {scanResults.riskLevel === "CRITICAL" ? "Critical — do not install" :
                scanResults.riskLevel === "HIGH" ? "Immediate attention" :
                  scanResults.riskLevel === "MEDIUM" ? "Review needed" : "Low risk"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Files Analyzed</CardTitle>
              <span className="text-2xl">📁</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-bold">{scanResults.totalFiles || 0}</span>
              <span className="text-muted-foreground">files</span>
            </div>
            <p className="text-sm text-muted-foreground mt-2">
              {scanResults.totalFiles > 100 ? "Large extension" :
                scanResults.totalFiles > 50 ? "Medium-sized" : "Small extension"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Security Findings</CardTitle>
              <span className="text-2xl">🚨</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-bold">{scanResults.totalFindings || 0}</span>
              <span className="text-muted-foreground">issues</span>
            </div>
            <p className="text-sm text-muted-foreground mt-2">
              {scanResults.totalFindings > 1000 ? "Critical concerns" :
                scanResults.totalFindings > 100 ? "Multiple issues" :
                  scanResults.totalFindings > 10 ? "Some concerns" : "Minimal issues"}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Export PDF Button */}
      <div className="flex justify-end mb-4">
        <Button
          variant="outline"
          onClick={() => {
            const extensionId = scanResults.extensionId;
            if (extensionId) {
              window.open(`http://localhost:8007/api/scan/report/${extensionId}`, '_blank');
            } else {
              alert('No extension ID available for report generation');
            }
          }}
        >
          <Download className="mr-2 h-4 w-4" />
          Export PDF Report
        </Button>
      </div>

      {/* Tabbed Interface */}
      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-7">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="threatintel">Threat Intel</TabsTrigger>
          <TabsTrigger value="obfuscation">Obfuscation</TabsTrigger>
          <TabsTrigger value="files">Files ({scanResults.files?.length || 0})</TabsTrigger>
          <TabsTrigger value="findings">SAST ({scanResults.sastResults?.length || 0})</TabsTrigger>
          <TabsTrigger value="chromestats">Chrome Stats</TabsTrigger>
          <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          {/* Executive Summary Card */}
          <Card className="border-l-4 border-l-primary">
            <CardHeader>
              <CardTitle>Executive Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm leading-relaxed whitespace-pre-line">
                {scanResults.executiveSummary || "No summary available."}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Extension Overview</CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => toggleSection("overview-extension")}
                >
                  {isSectionCollapsed("overview-extension") ? <ChevronDown /> : <ChevronUp />}
                </Button>
              </div>
            </CardHeader>
            {!isSectionCollapsed("overview-extension") && (
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm text-muted-foreground">Extension Name</div>
                    <div className="font-medium">{scanResults.name || "Unknown"}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Developer</div>
                    <div className="font-medium">{scanResults.developer || "Unknown"}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Version</div>
                    <div className="font-medium">{scanResults.version || "Unknown"}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Last Updated</div>
                    <div className="font-medium">{scanResults.lastUpdated || "Unknown"}</div>
                  </div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground mb-2">Description</div>
                  <div className="text-sm">{scanResults.description || "No description available"}</div>
                </div>
              </CardContent>
            )}
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Permissions Analysis</CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => toggleSection("overview-permissions")}
                >
                  {isSectionCollapsed("overview-permissions") ? <ChevronDown /> : <ChevronUp />}
                </Button>
              </div>
            </CardHeader>
            {!isSectionCollapsed("overview-permissions") && (
              <CardContent>
                <div className="space-y-3">
                  {(scanResults.permissions || []).length > 0 ? (
                    scanResults.permissions.map((permission, index) => (
                      <div key={index} className="flex items-start justify-between p-3 border rounded-lg">
                        <div className="flex-1">
                          <div className="font-medium">{permission.name}</div>
                          <div className="text-sm text-muted-foreground">{permission.description}</div>
                        </div>
                        <Badge variant={
                          permission.risk === "HIGH" ? "destructive" :
                            permission.risk === "MEDIUM" ? "secondary" : "default"
                        }>
                          {permission.risk}
                        </Badge>
                      </div>
                    ))
                  ) : (
                    <div className="text-center text-muted-foreground py-4">No permissions data available</div>
                  )}
                </div>
              </CardContent>
            )}
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Risk Summary</CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => toggleSection("overview-risk")}
                >
                  {isSectionCollapsed("overview-risk") ? <ChevronDown /> : <ChevronUp />}
                </Button>
              </div>
            </CardHeader>
            {!isSectionCollapsed("overview-risk") && (
              <CardContent>
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-500">
                      {(scanResults.sastResults || []).filter((f) => f.severity === "HIGH").length}
                    </div>
                    <div className="text-sm text-muted-foreground">High Risk</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-yellow-500">
                      {(scanResults.sastResults || []).filter((f) => f.severity === "MEDIUM").length}
                    </div>
                    <div className="text-sm text-muted-foreground">Medium Risk</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-500">
                      {(scanResults.sastResults || []).filter((f) => f.severity === "LOW").length}
                    </div>
                    <div className="text-sm text-muted-foreground">Low Risk</div>
                  </div>
                </div>
              </CardContent>
            )}
          </Card>
        </TabsContent>

        {/* Threat Intelligence Tab (VirusTotal) */}
        <TabsContent value="threatintel" className="space-y-4">
          <Card className="border-l-4 border-l-blue-500">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-blue-500" />
                <CardTitle>VirusTotal Threat Intelligence</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {scanResults.virustotalAnalysis ? (
                <div className="space-y-4">
                  {/* Summary Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="text-center p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold">{scanResults.virustotalAnalysis.files_analyzed || 0}</div>
                      <div className="text-sm text-muted-foreground">Files Scanned</div>
                    </div>
                    <div className="text-center p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold text-red-500">{scanResults.virustotalAnalysis.files_with_detections || 0}</div>
                      <div className="text-sm text-muted-foreground">With Detections</div>
                    </div>
                    <div className="text-center p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold text-orange-500">{scanResults.virustotalAnalysis.total_malicious || 0}</div>
                      <div className="text-sm text-muted-foreground">Malicious Flags</div>
                    </div>
                    <div className="text-center p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold text-yellow-500">{scanResults.virustotalAnalysis.total_suspicious || 0}</div>
                      <div className="text-sm text-muted-foreground">Suspicious Flags</div>
                    </div>
                  </div>

                  {/* Threat Level Badge */}
                  <div className="flex items-center gap-2">
                    <span className="font-medium">Threat Level:</span>
                    <Badge variant={
                      scanResults.virustotalAnalysis.summary?.threat_level === "malicious" ? "destructive" :
                      scanResults.virustotalAnalysis.summary?.threat_level === "suspicious" ? "secondary" : "default"
                    }>
                      {scanResults.virustotalAnalysis.summary?.threat_level?.toUpperCase() || "UNKNOWN"}
                    </Badge>
                  </div>

                  {/* Detected Malware Families */}
                  {scanResults.virustotalAnalysis.summary?.detected_families?.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Detected Malware Families:</h4>
                      <div className="flex flex-wrap gap-2">
                        {scanResults.virustotalAnalysis.summary.detected_families.map((family, idx) => (
                          <Badge key={idx} variant="destructive">{family}</Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* File Results */}
                  {scanResults.virustotalAnalysis.file_results?.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">File Hash Analysis:</h4>
                      <div className="space-y-2">
                        {scanResults.virustotalAnalysis.file_results.slice(0, 10).map((file, idx) => (
                          <div key={idx} className="flex items-center justify-between p-3 bg-muted rounded-lg">
                            <div>
                              <div className="font-medium">{file.file_name}</div>
                              <code className="text-xs text-muted-foreground">{file.hashes?.sha256?.substring(0, 32)}...</code>
                            </div>
                            <Badge variant={
                              file.virustotal?.found && file.virustotal?.detection_stats?.malicious > 0 ? "destructive" :
                              file.virustotal?.found ? "default" : "outline"
                            }>
                              {file.virustotal?.found
                                ? `${file.virustotal.detection_stats?.malicious || 0}/${file.virustotal.detection_stats?.total_engines || 0}`
                                : "Not in DB"}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommendation */}
                  <div className="p-4 bg-blue-50 dark:bg-blue-950 rounded-lg">
                    <p className="text-sm">{scanResults.virustotalAnalysis.summary?.recommendation || "No recommendation available."}</p>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>VirusTotal analysis not available.</p>
                  <p className="text-sm">Configure VIRUSTOTAL_API_KEY to enable threat intelligence.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Obfuscation Analysis Tab (Entropy) */}
        <TabsContent value="obfuscation" className="space-y-4">
          <Card className="border-l-4 border-l-purple-500">
            <CardHeader>
              <div className="flex items-center gap-2">
                <FileWarning className="h-5 w-5 text-purple-500" />
                <CardTitle>Obfuscation & Entropy Analysis</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {scanResults.entropyAnalysis ? (
                <div className="space-y-4">
                  {/* Summary Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="text-center p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold">{scanResults.entropyAnalysis.files_analyzed || 0}</div>
                      <div className="text-sm text-muted-foreground">Files Analyzed</div>
                    </div>
                    <div className="text-center p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold">{scanResults.entropyAnalysis.files_skipped || 0}</div>
                      <div className="text-sm text-muted-foreground">Libraries Skipped</div>
                    </div>
                    <div className="text-center p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold text-red-500">{scanResults.entropyAnalysis.obfuscated_files || 0}</div>
                      <div className="text-sm text-muted-foreground">Obfuscated</div>
                    </div>
                    <div className="text-center p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold text-yellow-500">{scanResults.entropyAnalysis.suspicious_files || 0}</div>
                      <div className="text-sm text-muted-foreground">Suspicious</div>
                    </div>
                  </div>

                  {/* Risk Level */}
                  <div className="flex items-center gap-2">
                    <span className="font-medium">Obfuscation Risk:</span>
                    <Badge variant={
                      scanResults.entropyAnalysis.summary?.overall_risk === "high" ? "destructive" :
                      scanResults.entropyAnalysis.summary?.overall_risk === "medium" ? "secondary" : "default"
                    }>
                      {scanResults.entropyAnalysis.summary?.overall_risk?.toUpperCase() || "NORMAL"}
                    </Badge>
                  </div>

                  {/* High Entropy Files */}
                  {scanResults.entropyAnalysis.summary?.high_entropy_files?.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2 flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-red-500" />
                        High Entropy Files (Potentially Obfuscated):
                      </h4>
                      <div className="space-y-2">
                        {scanResults.entropyAnalysis.summary.high_entropy_files.map((file, idx) => (
                          <div key={idx} className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-950 rounded-lg">
                            <div className="font-medium">{file.file}</div>
                            <div className="flex items-center gap-4">
                              <div className="text-sm">
                                <span className="text-muted-foreground">Entropy: </span>
                                <span className="font-bold text-red-500">{file.entropy?.toFixed(2)}</span>
                              </div>
                              <div className="text-sm">
                                <span className="text-muted-foreground">Patterns: </span>
                                <span className="font-bold">{file.patterns}</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Detected Patterns */}
                  {Object.keys(scanResults.entropyAnalysis.summary?.pattern_summary || {}).length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Detected Obfuscation Patterns:</h4>
                      <div className="space-y-2">
                        {Object.entries(scanResults.entropyAnalysis.summary.pattern_summary).map(([name, info], idx) => (
                          <div key={idx} className="flex items-center justify-between p-3 bg-muted rounded-lg">
                            <div>
                              <div className="font-medium">{info.description || name}</div>
                              <div className="text-sm text-muted-foreground">{info.files_affected} file(s) affected</div>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant={
                                info.risk === "high" ? "destructive" :
                                info.risk === "medium" ? "secondary" : "outline"
                              }>
                                {info.risk?.toUpperCase()}
                              </Badge>
                              <span className="text-sm font-bold">{info.total_occurrences}x</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommendation */}
                  <div className="p-4 bg-purple-50 dark:bg-purple-950 rounded-lg">
                    <p className="text-sm">{scanResults.entropyAnalysis.summary?.recommendation || "No recommendation available."}</p>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <FileWarning className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Entropy analysis not available.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Files Tab */}
        <TabsContent value="files" className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold">Analyzed Files ({scanResults.files?.length || 0})</h3>
            <Button variant="outline" size="sm">
              <Filter className="mr-2 h-4 w-4" />
              Filter
            </Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(scanResults.files || []).map((file, index) => (
              <Card key={index}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="text-base">{file.name}</CardTitle>
                      <div className="flex gap-2 mt-1">
                        <Badge variant="outline">{file.type}</Badge>
                        <span className="text-xs text-muted-foreground">{file.path}</span>
                      </div>
                    </div>
                    <Badge variant={
                      file.riskLevel === "HIGH" ? "destructive" :
                        file.riskLevel === "MEDIUM" ? "secondary" : "default"
                    }>
                      {file.riskLevel}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-2 flex-wrap">
                    <Button variant="outline" size="sm" onClick={() => onViewFile(file)}>
                      👁️ View
                    </Button>
                    <Button size="sm" onClick={() => onAnalyzeWithAI(file)}>
                      🤖 AI
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => onGenerateSASTSignature(file)}
                      className="gap-1"
                    >
                      ✨ SAST AI
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(scanResults.files || []).length === 0 && (
              <div className="col-span-2 text-center text-muted-foreground py-8">
                No files available for analysis
              </div>
            )}
          </div>
        </TabsContent>

        {/* SAST Findings Tab */}
        <TabsContent value="findings" className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold">
              Security Findings ({filteredFindings.length} of {scanResults.sastResults?.length || 0})
            </h3>
            <div className="flex gap-2">
              <Button
                variant={severityFilter === "ALL" ? "default" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("ALL")}
              >
                All
              </Button>
              <Button
                variant={severityFilter === "HIGH" ? "destructive" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("HIGH")}
              >
                High
              </Button>
              <Button
                variant={severityFilter === "MEDIUM" ? "secondary" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("MEDIUM")}
              >
                Medium
              </Button>
              <Button
                variant={severityFilter === "LOW" ? "default" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("LOW")}
              >
                Low
              </Button>
            </div>
          </div>

          <div className="space-y-3">
            {filteredFindings.slice(0, 15).map((finding, index) => (
              <Card key={index} className={`border-l-4 ${finding.severity === "HIGH" ? "border-l-red-500" :
                finding.severity === "MEDIUM" ? "border-l-yellow-500" : "border-l-green-500"
                }`}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex gap-2 text-sm text-muted-foreground mb-1">
                        <span>{finding.file}</span>
                        <span>Line {finding.line}</span>
                      </div>
                      <CardTitle className="text-base">{finding.title}</CardTitle>
                    </div>
                    <Badge variant={
                      finding.severity === "HIGH" ? "destructive" :
                        finding.severity === "MEDIUM" ? "secondary" : "default"
                    }>
                      {finding.severity}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground mb-3">{finding.description}</p>
                  <Button variant="outline" size="sm" onClick={() => onViewFindingDetails(finding)}>
                    📋 Details
                  </Button>
                </CardContent>
              </Card>
            ))}

            {filteredFindings.length > 15 && (
              <Card>
                <CardContent className="text-center py-6">
                  <p className="mb-3">... and {filteredFindings.length - 15} more findings</p>
                  <Button variant="outline" onClick={() => onViewAllFindings()}>
                    View All
                  </Button>
                </CardContent>
              </Card>
            )}

            {filteredFindings.length === 0 && (
              <div className="text-center text-muted-foreground py-8">
                No security findings match the current filter
              </div>
            )}
          </div>
        </TabsContent>

        {/* Chrome Stats Tab */}
        <TabsContent value="chromestats" className="space-y-4">
          <ChromeStatsTab
            metadata={scanResults.chromeStatsMetadata || scanResults.metadata}
            collapsedSections={collapsedSections}
            toggleSection={toggleSection}
            isSectionCollapsed={isSectionCollapsed}
          />
        </TabsContent>

        {/* Recommendations Tab */}
        <TabsContent value="recommendations" className="space-y-4">
          <h3 className="text-lg font-semibold">Security Recommendations</h3>
          {(scanResults.recommendations || []).length > 0 ? (
            <div className="space-y-3">
              {scanResults.recommendations.map((rec, index) => (
                <Card key={index}>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <CardTitle className="text-base">{rec.title}</CardTitle>
                      <Badge variant={
                        rec.priority === "HIGH" ? "destructive" :
                          rec.priority === "MEDIUM" ? "secondary" : "default"
                      }>
                        {rec.priority}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">{rec.description}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>🤖 AI-Generated Recommendations</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p>Based on the security scan results, here are some recommendations:</p>
                <ul className="list-disc list-inside space-y-2 text-sm">
                  <li>Review high-risk permissions that may expose sensitive data</li>
                  <li>Check for potential data leakage in network requests</li>
                  <li>Validate third-party libraries for known vulnerabilities</li>
                  <li>Implement Content Security Policy to prevent XSS attacks</li>
                  <li>Review code that handles user data for proper sanitization</li>
                </ul>
                <Button>Generate Detailed Report</Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default TabbedResultsPanel;