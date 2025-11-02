import React, { useState, useEffect } from "react";
import {
  DataTable,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Tile,
  Tag,
  Button,
  Search,
  Pagination,
  Grid,
  Column,
  Accordion,
  AccordionItem,
  CodeSnippet,
  SkeletonText,
} from "@carbon/react";
import {
  Download,
  View,
  Security,
  Document,
  Warning,
  Checkmark,
  Error,
  Information,
} from "@carbon/icons-react";
// import './ScanHistoryPage.scss';

const ScanHistoryPage = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);

  useEffect(() => {
    // Simulate loading scan history
    setTimeout(() => {
      setScans([
        {
          id: "mdanidgdpmkimeiiojknlnekblgmpdll",
          name: "Boomerang for Gmail",
          version: "1.8.8",
          timestamp: "2025-08-18 14:18:23",
          securityScore: 0.0,
          riskLevel: "high",
          totalFindings: 20249,
          fileCount: 34,
          downloadSize: "4.1 MB",
          status: "completed",
          logFile: "mdanidgdpmkimeiiojknlnekblgmpdll_20250818_141823.log",
          details: {
            manifest: {
              permissions: ["management", "activeTab"],
              threatLevel: "low",
              threatScore: 0,
            },
            sast: {
              overallScore: 0.0,
              riskDistribution: { high: 9, minimal: 1 },
              totalFindings: 20249,
            },
            files: {
              javascript: 11,
              html: 3,
              css: 13,
              other: 7,
            },
          },
        },
        {
          id: "cjpalhdlnbpafiamejdnhcphjbkeiagm",
          name: "uBlock Origin",
          version: "1.65.0",
          timestamp: "2025-08-18 14:25:31",
          securityScore: 27.5,
          riskLevel: "high",
          totalFindings: 15,
          fileCount: 653,
          downloadSize: "4.0 MB",
          status: "completed",
          logFile: "cjpalhdlnbpafiamejdnhcphjbkeiagm_20250818_142531.log",
          details: {
            manifest: {
              permissions: [
                "alarms",
                "contextMenus",
                "privacy",
                "storage",
                "tabs",
                "unlimitedStorage",
                "webNavigation",
                "webRequest",
                "webRequestBlocking",
                "<all_urls>",
              ],
              threatLevel: "medium",
              threatScore: 35,
            },
            sast: {
              overallScore: 27.5,
              riskDistribution: { high: 2, medium: 8, low: 5 },
              totalFindings: 15,
            },
            files: {
              javascript: 89,
              html: 12,
              css: 45,
              other: 507,
            },
          },
        },
      ]);
      setLoading(false);
    }, 2000);
  }, []);

  const handleScanSelect = (scan) => {
    setSelectedScan(selectedScan?.id === scan.id ? null : scan);
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case "high":
        return "red";
      case "medium":
        return "orange";
      case "low":
        return "green";
      default:
        return "gray";
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "completed":
        return <Checkmark size={16} />;
      case "failed":
        return <Error size={16} />;
      case "running":
        return <Information size={16} />;
      default:
        return <Information size={16} />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "completed":
        return "green";
      case "failed":
        return "red";
      case "running":
        return "blue";
      default:
        return "gray";
    }
  };

  if (loading) {
    return (
      <div className="scan-history-page">
        <div className="page-header">
          <h1>📋 Scan History</h1>
          <p>View and analyze previous extension security scans</p>
        </div>

        <Grid className="loading-grid">
          <Column lg={12} md={8} sm={4}>
            <Tile className="loading-tile">
              <SkeletonText paragraph lineCount={10} />
            </Tile>
          </Column>
        </Grid>
      </div>
    );
  }

  return (
    <div className="scan-history-page">
      <div className="page-header">
        <h1>📋 Scan History</h1>
        <p>View and analyze previous extension security scans</p>
      </div>

      <Grid className="history-content">
        <Column lg={8} md={8} sm={4}>
          <Tile className="scans-table-tile">
            <div className="table-header">
              <h3>🔍 Recent Scans ({scans.length})</h3>
              <Search size={20} className="search-icon" />
            </div>

            <div className="scans-table">
              {scans.map((scan) => (
                <div
                  key={scan.id}
                  className={`scan-row ${selectedScan?.id === scan.id ? "selected" : ""}`}
                  onClick={() => handleScanSelect(scan)}
                >
                  <div className="scan-info">
                    <div className="scan-name">
                      <h4>{scan.name}</h4>
                      <span className="scan-version">v{scan.version}</span>
                    </div>
                    <div className="scan-meta">
                      <span className="scan-time">{scan.timestamp}</span>
                      <span className="scan-id">{scan.id}</span>
                    </div>
                  </div>

                  <div className="scan-stats">
                    <div className="stat-item">
                      <span className="stat-label">Score:</span>
                      <span
                        className={`stat-value score-${scan.securityScore < 30 ? "low" : scan.securityScore < 70 ? "medium" : "high"}`}
                      >
                        {scan.securityScore}/100
                      </span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">Risk:</span>
                      <Tag type={getRiskColor(scan.riskLevel)} size="sm">
                        {scan.riskLevel.toUpperCase()}
                      </Tag>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">Findings:</span>
                      <span className="stat-value">{scan.totalFindings}</span>
                    </div>
                  </div>

                  <div className="scan-actions">
                    <Button kind="tertiary" size="sm" className="view-btn">
                      <View size={16} />
                      View
                    </Button>
                    <Button kind="tertiary" size="sm" className="download-btn">
                      <Download size={16} />
                      Log
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </Tile>
        </Column>

        <Column lg={4} md={8} sm={4}>
          <Tile className="summary-tile">
            <div className="summary-header">
              <Security size={24} />
              <h3>Scan Summary</h3>
            </div>

            <div className="summary-stats">
              <div className="summary-stat">
                <span className="stat-label">Total Scans:</span>
                <span className="stat-value">{scans.length}</span>
              </div>
              <div className="summary-stat">
                <span className="stat-label">High Risk:</span>
                <span className="stat-value">
                  {scans.filter((s) => s.riskLevel === "high").length}
                </span>
              </div>
              <div className="summary-stat">
                <span className="stat-label">Avg Score:</span>
                <span className="stat-value">
                  {(
                    scans.reduce((sum, s) => sum + s.securityScore, 0) /
                    scans.length
                  ).toFixed(1)}
                  /100
                </span>
              </div>
              <div className="summary-stat">
                <span className="stat-label">Total Files:</span>
                <span className="stat-value">
                  {scans.reduce((sum, s) => sum + s.fileCount, 0)}
                </span>
              </div>
            </div>
          </Tile>
        </Column>
      </Grid>

      {/* Selected Scan Details */}
      {selectedScan && (
        <Tile className="scan-details-tile">
          <div className="details-header">
            <h3>📊 Detailed Analysis: {selectedScan.name}</h3>
            <Button
              kind="tertiary"
              size="sm"
              onClick={() => setSelectedScan(null)}
              className="close-details-btn"
            >
              Close
            </Button>
          </div>

          <Grid className="details-grid">
            <Column lg={6} md={8} sm={4}>
              <div className="detail-section">
                <h4>📋 Extension Information</h4>
                <div className="detail-content">
                  <p>
                    <strong>Extension ID:</strong> {selectedScan.id}
                  </p>
                  <p>
                    <strong>Version:</strong> {selectedScan.version}
                  </p>
                  <p>
                    <strong>Scan Time:</strong> {selectedScan.timestamp}
                  </p>
                  <p>
                    <strong>File Count:</strong> {selectedScan.fileCount} files
                  </p>
                  <p>
                    <strong>Download Size:</strong> {selectedScan.downloadSize}
                  </p>
                  <p>
                    <strong>Log File:</strong> {selectedScan.logFile}
                  </p>
                </div>
              </div>

              <div className="detail-section">
                <h4>🔒 Security Assessment</h4>
                <div className="detail-content">
                  <div className="security-score-display">
                    <span className="score-label">Security Score:</span>
                    <span
                      className={`score-value score-${selectedScan.securityScore < 30 ? "low" : selectedScan.securityScore < 70 ? "medium" : "high"}`}
                    >
                      {selectedScan.securityScore}/100
                    </span>
                  </div>
                  <p>
                    <strong>Risk Level:</strong>
                    <Tag type={getRiskColor(selectedScan.riskLevel)} size="sm">
                      {selectedScan.riskLevel.toUpperCase()}
                    </Tag>
                  </p>
                  <p>
                    <strong>Total Findings:</strong>{" "}
                    {selectedScan.totalFindings}
                  </p>
                </div>
              </div>
            </Column>

            <Column lg={6} md={8} sm={4}>
              <div className="detail-section">
                <h4>📁 File Analysis</h4>
                <div className="detail-content">
                  <div className="file-breakdown">
                    <div className="file-type">
                      <span className="type-label">JavaScript:</span>
                      <span className="type-count">
                        {selectedScan.details.files.javascript} files
                      </span>
                    </div>
                    <div className="file-type">
                      <span className="type-label">HTML:</span>
                      <span className="type-count">
                        {selectedScan.details.files.html} files
                      </span>
                    </div>
                    <div className="file-type">
                      <span className="type-label">CSS:</span>
                      <span className="type-count">
                        {selectedScan.details.files.css} files
                      </span>
                    </div>
                    <div className="file-type">
                      <span className="type-label">Other:</span>
                      <span className="type-count">
                        {selectedScan.details.files.other} files
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="detail-section">
                <h4>🚨 SAST Results</h4>
                <div className="detail-content">
                  <div className="sast-breakdown">
                    <div className="sast-stat">
                      <span className="stat-label">Overall Score:</span>
                      <span className="stat-value">
                        {selectedScan.details.sast.overallScore}/100
                      </span>
                    </div>
                    <div className="sast-stat">
                      <span className="stat-label">High Risk:</span>
                      <span className="stat-value">
                        {selectedScan.details.sast.riskDistribution.high}
                      </span>
                    </div>
                    <div className="sast-stat">
                      <span className="stat-label">Medium Risk:</span>
                      <span className="stat-value">
                        {selectedScan.details.sast.riskDistribution.medium || 0}
                      </span>
                    </div>
                    <div className="sast-stat">
                      <span className="stat-label">Low Risk:</span>
                      <span className="stat-value">
                        {selectedScan.details.sast.riskDistribution.low || 0}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </Column>
          </Grid>

          <div className="details-actions">
            <Button kind="primary" size="lg" className="download-report-btn">
              <Download size={20} />
              Download Full Report
            </Button>
            <Button kind="tertiary" size="lg" className="view-log-btn">
              <Document size={20} />
              View Raw Log
            </Button>
          </div>
        </Tile>
      )}
    </div>
  );
};

export default ScanHistoryPage;
