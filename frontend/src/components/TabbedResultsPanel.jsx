import React, { useState } from "react";
import {
  Tabs,
  Tab,
  TabList,
  TabPanels,
  TabPanel,
  Button,
  Tag,
  Tile,
} from "@carbon/react";
import {
  Information,
  Filter,
  ChevronDown,
  ChevronUp,
} from "@carbon/icons-react";
import "./TabbedResultsPanel.scss";

/**
 * Tabbed Results Panel Component for organizing scan results
 *
 * @param {Object} props
 * @param {Object} props.scanResults - The scan results data
 * @param {Function} props.onViewFile - Function to call when viewing a file
 * @param {Function} props.onAnalyzeWithAI - Function to call when analyzing with AI
 * @param {Function} props.onViewFindingDetails - Function to call when viewing finding details
 * @param {Function} props.onViewAllFindings - Function to call when viewing all findings
 */
const TabbedResultsPanel = ({
  scanResults,
  onViewFile,
  onAnalyzeWithAI,
  onViewFindingDetails,
  onViewAllFindings,
}) => {
  const [selectedTab, setSelectedTab] = useState(0);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [collapsedSections, setCollapsedSections] = useState({});

  if (!scanResults) return null;

  // Toggle section collapse state
  const toggleSection = (sectionId) => {
    setCollapsedSections((prev) => ({
      ...prev,
      [sectionId]: !prev[sectionId],
    }));
  };

  // Check if a section is collapsed
  const isSectionCollapsed = (sectionId) => {
    return !!collapsedSections[sectionId];
  };

  // Filter findings by severity
  const filteredFindings =
    severityFilter === "ALL"
      ? scanResults.sastResults || []
      : (scanResults.sastResults || []).filter(
          (finding) => finding.severity === severityFilter,
        );

  return (
    <div className="tabbed-results-panel">
      <h2 className="results-title">🔒 Security Analysis Results</h2>

      {/* Key Metrics Summary */}
      <div className="results-summary">
        <div className="results-grid">
          <Tile className="result-tile security-score">
            <div className="tile-content">
              <div className="tile-header">
                <h3>Security Score</h3>
                <div className="tile-icon">🛡️</div>
              </div>
              <div className="score-display">
                <span
                  className={`score ${scanResults.securityScore < 30 ? "critical" : scanResults.securityScore < 50 ? "high" : scanResults.securityScore < 80 ? "medium" : "low"}`}
                >
                  {scanResults.securityScore || 0}
                </span>
                <span className="score-max">/100</span>
              </div>
              <p className="score-description">
                {scanResults.securityScore < 30
                  ? "Critical Issues"
                  : scanResults.securityScore < 50
                    ? "High Risk"
                    : scanResults.securityScore < 80
                      ? "Moderate"
                      : "Secure"}
              </p>
              <button className="what-does-this-mean-link">
                What does this mean? <Information size={16} />
              </button>
            </div>
          </Tile>

          <Tile className="result-tile risk-level">
            <div className="tile-content">
              <div className="tile-header">
                <h3>Risk Level</h3>
                <div className="tile-icon">⚠️</div>
              </div>
              <div className="risk-display">
                <Tag
                  type={
                    scanResults.riskLevel === "HIGH"
                      ? "red"
                      : scanResults.riskLevel === "MEDIUM"
                        ? "warm-gray"
                        : "green"
                  }
                  size="lg"
                >
                  {scanResults.riskLevel || "UNKNOWN"}
                </Tag>
              </div>
              <p className="risk-description">
                {scanResults.riskLevel === "HIGH"
                  ? "Immediate attention"
                  : scanResults.riskLevel === "MEDIUM"
                    ? "Review needed"
                    : "Low risk"}
              </p>
              <button className="what-does-this-mean-link">
                What does this mean? <Information size={16} />
              </button>
            </div>
          </Tile>

          <Tile className="result-tile files-analyzed">
            <div className="tile-content">
              <div className="tile-header">
                <h3>Files Analyzed</h3>
                <div className="tile-icon">📁</div>
              </div>
              <div className="files-display">
                <span className="files-count">
                  {scanResults.totalFiles || 0}
                </span>
                <span className="files-label">files</span>
              </div>
              <p className="files-description">
                {scanResults.totalFiles > 100
                  ? "Large extension"
                  : scanResults.totalFiles > 50
                    ? "Medium-sized"
                    : "Small extension"}
              </p>
            </div>
          </Tile>

          <Tile className="result-tile security-findings">
            <div className="tile-content">
              <div className="tile-header">
                <h3>Security Findings</h3>
                <div className="tile-icon">🚨</div>
              </div>
              <div className="findings-display">
                <span className="findings-count">
                  {scanResults.totalFindings || 0}
                </span>
                <span className="findings-label">issues</span>
              </div>
              <p className="findings-description">
                {scanResults.totalFindings > 1000
                  ? "Critical concerns"
                  : scanResults.totalFindings > 100
                    ? "Multiple issues"
                    : scanResults.totalFindings > 10
                      ? "Some concerns"
                      : "Minimal issues"}
              </p>
            </div>
          </Tile>
        </div>
      </div>

      {/* Tabbed Interface */}
      <div className="results-tabs-container">
        <Tabs
          selectedIndex={selectedTab}
          onChange={(index) => setSelectedTab(index)}
          className="results-tabs"
          type="container"
        >
          <TabList aria-label="Results Tabs" className="tab-list">
            <Tab>Overview</Tab>
            <Tab>Files ({scanResults.files?.length || 0})</Tab>
            <Tab>SAST Findings ({scanResults.sastResults?.length || 0})</Tab>
            <Tab>Recommendations</Tab>
          </TabList>

          <TabPanels className="tab-panels">
            {/* Overview Tab */}
            <TabPanel style={{ display: "block", visibility: "visible" }}>
              <div className="overview-tab">
                <div className="section-header">
                  <h3>Extension Overview</h3>
                  <button
                    className="section-toggle"
                    onClick={() => toggleSection("overview-extension")}
                    aria-label={
                      isSectionCollapsed("overview-extension")
                        ? "Expand section"
                        : "Collapse section"
                    }
                  >
                    {isSectionCollapsed("overview-extension") ? (
                      <ChevronDown size={16} />
                    ) : (
                      <ChevronUp size={16} />
                    )}
                  </button>
                </div>

                {!isSectionCollapsed("overview-extension") && (
                  <div className="overview-content">
                    <div className="overview-grid">
                      <div className="overview-item">
                        <div className="item-label">Extension Name</div>
                        <div className="item-value">
                          {scanResults.name || "Unknown"}
                        </div>
                      </div>
                      <div className="overview-item">
                        <div className="item-label">Developer</div>
                        <div className="item-value">
                          {scanResults.developer || "Unknown"}
                        </div>
                      </div>
                      <div className="overview-item">
                        <div className="item-label">Version</div>
                        <div className="item-value">
                          {scanResults.version || "Unknown"}
                        </div>
                      </div>
                      <div className="overview-item">
                        <div className="item-label">Last Updated</div>
                        <div className="item-value">
                          {scanResults.lastUpdated || "Unknown"}
                        </div>
                      </div>
                    </div>

                    <div className="overview-description">
                      <div className="item-label">Description</div>
                      <div className="item-value description">
                        {scanResults.description || "No description available"}
                      </div>
                    </div>
                  </div>
                )}

                <div className="section-header">
                  <h3>Permissions Analysis</h3>
                  <button
                    className="section-toggle"
                    onClick={() => toggleSection("overview-permissions")}
                    aria-label={
                      isSectionCollapsed("overview-permissions")
                        ? "Expand section"
                        : "Collapse section"
                    }
                  >
                    {isSectionCollapsed("overview-permissions") ? (
                      <ChevronDown size={16} />
                    ) : (
                      <ChevronUp size={16} />
                    )}
                  </button>
                </div>

                {!isSectionCollapsed("overview-permissions") && (
                  <div className="permissions-content">
                    <div className="permissions-list">
                      {(scanResults.permissions || []).length > 0 ? (
                        scanResults.permissions.map((permission, index) => (
                          <div
                            key={index}
                            className={`permission-item ${permission.risk}`}
                          >
                            <div className="permission-name">
                              {permission.name}
                            </div>
                            <div className="permission-risk">
                              <Tag
                                type={
                                  permission.risk === "HIGH"
                                    ? "red"
                                    : permission.risk === "MEDIUM"
                                      ? "warm-gray"
                                      : "green"
                                }
                                size="sm"
                              >
                                {permission.risk}
                              </Tag>
                            </div>
                            <div className="permission-description">
                              {permission.description}
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="no-data">
                          No permissions data available
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="section-header">
                  <h3>Risk Summary</h3>
                  <button
                    className="section-toggle"
                    onClick={() => toggleSection("overview-risk")}
                    aria-label={
                      isSectionCollapsed("overview-risk")
                        ? "Expand section"
                        : "Collapse section"
                    }
                  >
                    {isSectionCollapsed("overview-risk") ? (
                      <ChevronDown size={16} />
                    ) : (
                      <ChevronUp size={16} />
                    )}
                  </button>
                </div>

                {!isSectionCollapsed("overview-risk") && (
                  <div className="risk-content">
                    <div className="risk-summary">
                      <div className="risk-item">
                        <div className="risk-category">High Risk Findings</div>
                        <div className="risk-count high">
                          {
                            (scanResults.sastResults || []).filter(
                              (f) => f.severity === "HIGH",
                            ).length
                          }
                        </div>
                      </div>
                      <div className="risk-item">
                        <div className="risk-category">
                          Medium Risk Findings
                        </div>
                        <div className="risk-count medium">
                          {
                            (scanResults.sastResults || []).filter(
                              (f) => f.severity === "MEDIUM",
                            ).length
                          }
                        </div>
                      </div>
                      <div className="risk-item">
                        <div className="risk-category">Low Risk Findings</div>
                        <div className="risk-count low">
                          {
                            (scanResults.sastResults || []).filter(
                              (f) => f.severity === "LOW",
                            ).length
                          }
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </TabPanel>

            {/* Files Tab */}
            <TabPanel style={{ display: "block", visibility: "visible" }}>
              <div className="files-tab">
                <div className="section-header">
                  <h3>Analyzed Files ({scanResults.files?.length || 0})</h3>
                  <div className="section-actions">
                    <Button
                      kind="ghost"
                      size="sm"
                      renderIcon={Filter}
                      className="filter-button"
                    >
                      Filter
                    </Button>
                  </div>
                </div>

                <div className="files-grid">
                  {(scanResults.files || []).map((file, index) => (
                    <Tile key={index} className="file-analysis-tile">
                      <div className="file-header">
                        <div className="file-info">
                          <h4 className="file-name">{file.name}</h4>
                          <div className="file-meta">
                            <span className="file-type">{file.type}</span>
                            <span className="file-path">{file.path}</span>
                          </div>
                        </div>
                        <Tag
                          type={
                            file.riskLevel === "HIGH"
                              ? "red"
                              : file.riskLevel === "MEDIUM"
                                ? "warm-gray"
                                : "green"
                          }
                          size="sm"
                        >
                          {file.riskLevel}
                        </Tag>
                      </div>

                      <div className="file-actions">
                        <Button
                          kind="tertiary"
                          size="sm"
                          className="view-file-btn"
                          onClick={() => onViewFile(file)}
                        >
                          👁️ View
                        </Button>
                        <Button
                          kind="primary"
                          size="sm"
                          className="analyze-ai-btn"
                          onClick={() => onAnalyzeWithAI(file)}
                        >
                          🤖 AI
                        </Button>
                      </div>
                    </Tile>
                  ))}

                  {(scanResults.files || []).length === 0 && (
                    <div className="no-data">
                      No files available for analysis
                    </div>
                  )}
                </div>
              </div>
            </TabPanel>

            {/* SAST Findings Tab */}
            <TabPanel style={{ display: "block", visibility: "visible" }}>
              <div className="findings-tab">
                <div className="section-header">
                  <h3>
                    Security Findings ({filteredFindings.length} of{" "}
                    {scanResults.sastResults?.length || 0})
                  </h3>
                  <div className="section-actions">
                    <div className="severity-filter">
                      <span className="filter-label">Severity:</span>
                      <div className="filter-options">
                        <button
                          className={`filter-option ${severityFilter === "ALL" ? "active" : ""}`}
                          onClick={() => setSeverityFilter("ALL")}
                        >
                          All
                        </button>
                        <button
                          className={`filter-option high ${severityFilter === "HIGH" ? "active" : ""}`}
                          onClick={() => setSeverityFilter("HIGH")}
                        >
                          High
                        </button>
                        <button
                          className={`filter-option medium ${severityFilter === "MEDIUM" ? "active" : ""}`}
                          onClick={() => setSeverityFilter("MEDIUM")}
                        >
                          Medium
                        </button>
                        <button
                          className={`filter-option low ${severityFilter === "LOW" ? "active" : ""}`}
                          onClick={() => setSeverityFilter("LOW")}
                        >
                          Low
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="findings-grid">
                  {filteredFindings.slice(0, 15).map((finding, index) => (
                    <Tile
                      key={index}
                      className={`finding-tile severity-${finding.severity?.toLowerCase()}`}
                    >
                      <div className="finding-header">
                        <div className="finding-meta">
                          <span className="finding-file">{finding.file}</span>
                          <span className="finding-line">
                            Line {finding.line}
                          </span>
                        </div>
                        <Tag
                          type={
                            finding.severity === "HIGH"
                              ? "red"
                              : finding.severity === "MEDIUM"
                                ? "warm-gray"
                                : "green"
                          }
                          size="sm"
                        >
                          {finding.severity}
                        </Tag>
                      </div>

                      <div className="finding-content">
                        <h4 className="finding-title">{finding.title}</h4>
                        <p className="finding-description">
                          {finding.description}
                        </p>
                      </div>

                      <div className="finding-actions">
                        <Button
                          kind="tertiary"
                          size="sm"
                          className="view-details-btn"
                          onClick={() => onViewFindingDetails(finding)}
                        >
                          📋 Details
                        </Button>
                      </div>
                    </Tile>
                  ))}

                  {filteredFindings.length > 15 && (
                    <div className="more-findings">
                      <Tile className="more-findings-tile">
                        <p>
                          ... and {filteredFindings.length - 15} more findings
                        </p>
                        <Button
                          kind="tertiary"
                          size="sm"
                          onClick={() => onViewAllFindings()}
                        >
                          View All
                        </Button>
                      </Tile>
                    </div>
                  )}

                  {filteredFindings.length === 0 && (
                    <div className="no-data">
                      No security findings match the current filter
                    </div>
                  )}
                </div>
              </div>
            </TabPanel>

            {/* Recommendations Tab */}
            <TabPanel style={{ display: "block", visibility: "visible" }}>
              <div className="recommendations-tab">
                <div className="section-header">
                  <h3>Security Recommendations</h3>
                </div>

                <div className="recommendations-content">
                  {(scanResults.recommendations || []).length > 0 ? (
                    <div className="recommendations-list">
                      {scanResults.recommendations.map((rec, index) => (
                        <div key={index} className="recommendation-item">
                          <div className="recommendation-priority">
                            <Tag
                              type={
                                rec.priority === "HIGH"
                                  ? "red"
                                  : rec.priority === "MEDIUM"
                                    ? "warm-gray"
                                    : "green"
                              }
                              size="sm"
                            >
                              {rec.priority}
                            </Tag>
                          </div>
                          <div className="recommendation-content">
                            <h4 className="recommendation-title">
                              {rec.title}
                            </h4>
                            <p className="recommendation-description">
                              {rec.description}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="ai-recommendations">
                      <div className="ai-recommendation-header">
                        <h4>🤖 AI-Generated Recommendations</h4>
                      </div>
                      <div className="ai-recommendation-content">
                        <p>
                          Based on the security scan results, here are some
                          recommendations:
                        </p>
                        <ul className="recommendation-list">
                          <li>
                            Review high-risk permissions that may expose
                            sensitive data
                          </li>
                          <li>
                            Check for potential data leakage in network requests
                          </li>
                          <li>
                            Validate third-party libraries for known
                            vulnerabilities
                          </li>
                          <li>
                            Implement Content Security Policy to prevent XSS
                            attacks
                          </li>
                          <li>
                            Review code that handles user data for proper
                            sanitization
                          </li>
                        </ul>
                      </div>
                      <div className="ai-actions">
                        <Button kind="primary" size="sm">
                          Generate Detailed Report
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </TabPanel>
          </TabPanels>
        </Tabs>
      </div>
    </div>
  );
};

export default TabbedResultsPanel;

// Made with Bob
