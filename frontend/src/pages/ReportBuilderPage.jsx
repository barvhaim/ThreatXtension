import React, { useState, useEffect } from 'react';
import { Card } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Textarea } from '../components/ui/textarea';
import './ReportBuilderPage.scss';

const ReportBuilderPage = () => {
  const [scanHistory, setScanHistory] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [reportConfig, setReportConfig] = useState({
    title: 'Security Analysis Report',
    includeExecutiveSummary: true,
    includeFindings: true,
    includeSASTResults: true,
    includePermissions: true,
    includeRecommendations: true,
    customBranding: {
      logo: '',
      companyName: '',
      headerColor: '#1e40af',
      footerText: 'Confidential - Internal Use Only'
    }
  });
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportPreview, setReportPreview] = useState(null);

  useEffect(() => {
    fetchScanHistory();
  }, []);

  const fetchScanHistory = async () => {
    try {
      const response = await fetch('http://localhost:8007/api/history?limit=50');
      const data = await response.json();
      setScanHistory(data.scans || []);
    } catch (error) {
      console.error('Error fetching scan history:', error);
    }
  };

  const handleScanSelect = async (scanId) => {
    try {
      const response = await fetch(`http://localhost:8007/api/scan/results/${scanId}`);
      const data = await response.json();
      setSelectedScan(data);
    } catch (error) {
      console.error('Error fetching scan details:', error);
    }
  };

  const generateReport = async () => {
    if (!selectedScan) {
      alert('Please select a scan first');
      return;
    }

    setGeneratingReport(true);
    try {
      // Generate AI-powered report using the executive summary endpoint
      const response = await fetch('http://localhost:8007/api/analyze/executive-summary', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scan_id: selectedScan.scan_id,
          report_config: reportConfig
        })
      });

      const report = await response.json();
      setReportPreview(report);
    } catch (error) {
      console.error('Error generating report:', error);
      alert('Failed to generate report. Using fallback data.');
      // Fallback to existing data
      setReportPreview({
        title: reportConfig.title,
        scan_data: selectedScan,
        generated_at: new Date().toISOString()
      });
    } finally {
      setGeneratingReport(false);
    }
  };

  const exportReport = async (format) => {
    if (!reportPreview) {
      alert('Please generate a report first');
      return;
    }

    try {
      const response = await fetch(`http://localhost:8007/api/report/export/${format}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          report: reportPreview,
          config: reportConfig
        })
      });

      if (format === 'pdf' || format === 'docx') {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_report_${selectedScan.scan_id}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        const data = await response.json();
        const dataStr = JSON.stringify(data, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = window.URL.createObjectURL(dataBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_report_${selectedScan.scan_id}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (error) {
      console.error('Error exporting report:', error);
      alert('Failed to export report');
    }
  };

  const toggleSection = (section) => {
    setReportConfig(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  return (
    <div className="report-builder-page">
      <div className="page-header">
        <h1>Custom Report Builder</h1>
        <p>Create customized security reports with AI-generated insights</p>
      </div>

      <div className="report-builder-grid">
        {/* Left Panel - Configuration */}
        <div className="config-panel">
          <Card className="config-card">
            <h2>1. Select Scan</h2>
            <div className="scan-selector">
              <select
                value={selectedScan?.scan_id || ''}
                onChange={(e) => handleScanSelect(e.target.value)}
                className="scan-select"
              >
                <option value="">Choose a scan...</option>
                {scanHistory.map(scan => (
                  <option key={scan.scan_id} value={scan.scan_id}>
                    {scan.extension_name || scan.url || scan.scan_id} - {new Date(scan.timestamp).toLocaleDateString()}
                  </option>
                ))}
              </select>
            </div>
          </Card>

          <Card className="config-card">
            <h2>2. Report Configuration</h2>
            
            <div className="config-section">
              <label>Report Title</label>
              <Input
                value={reportConfig.title}
                onChange={(e) => setReportConfig(prev => ({ ...prev, title: e.target.value }))}
                placeholder="Enter report title"
              />
            </div>

            <div className="config-section">
              <h3>Include Sections</h3>
              <div className="section-toggles">
                <label className="toggle-item">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeExecutiveSummary}
                    onChange={() => toggleSection('includeExecutiveSummary')}
                  />
                  <span>Executive Summary</span>
                </label>
                <label className="toggle-item">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeFindings}
                    onChange={() => toggleSection('includeFindings')}
                  />
                  <span>Key Findings</span>
                </label>
                <label className="toggle-item">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeSASTResults}
                    onChange={() => toggleSection('includeSASTResults')}
                  />
                  <span>SAST Results</span>
                </label>
                <label className="toggle-item">
                  <input
                    type="checkbox"
                    checked={reportConfig.includePermissions}
                    onChange={() => toggleSection('includePermissions')}
                  />
                  <span>Permissions Analysis</span>
                </label>
                <label className="toggle-item">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeRecommendations}
                    onChange={() => toggleSection('includeRecommendations')}
                  />
                  <span>Recommendations</span>
                </label>
              </div>
            </div>

            <div className="config-section">
              <h3>Custom Branding</h3>
              <label>Company Name</label>
              <Input
                value={reportConfig.customBranding.companyName}
                onChange={(e) => setReportConfig(prev => ({
                  ...prev,
                  customBranding: { ...prev.customBranding, companyName: e.target.value }
                }))}
                placeholder="Your Company Name"
              />
              
              <label>Header Color</label>
              <Input
                type="color"
                value={reportConfig.customBranding.headerColor}
                onChange={(e) => setReportConfig(prev => ({
                  ...prev,
                  customBranding: { ...prev.customBranding, headerColor: e.target.value }
                }))}
              />
              
              <label>Footer Text</label>
              <Textarea
                value={reportConfig.customBranding.footerText}
                onChange={(e) => setReportConfig(prev => ({
                  ...prev,
                  customBranding: { ...prev.customBranding, footerText: e.target.value }
                }))}
                placeholder="Footer text..."
                rows={2}
              />
            </div>
          </Card>

          <Card className="config-card">
            <h2>3. Generate & Export</h2>
            <div className="action-buttons">
              <Button
                onClick={generateReport}
                disabled={!selectedScan || generatingReport}
                className="generate-btn"
              >
                {generatingReport ? 'Generating with AI...' : 'Generate Report'}
              </Button>
              
              {reportPreview && (
                <div className="export-buttons">
                  <Button onClick={() => exportReport('pdf')} variant="outline">
                    Export PDF
                  </Button>
                  <Button onClick={() => exportReport('docx')} variant="outline">
                    Export DOCX
                  </Button>
                  <Button onClick={() => exportReport('json')} variant="outline">
                    Export JSON
                  </Button>
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Right Panel - Preview */}
        <div className="preview-panel">
          <Card className="preview-card">
            <h2>Report Preview</h2>
            {!reportPreview ? (
              <div className="preview-placeholder">
                <p>Configure your report and click "Generate Report" to see a preview</p>
              </div>
            ) : (
              <div className="report-preview" style={{ '--header-color': reportConfig.customBranding.headerColor }}>
                <div className="report-header">
                  {reportConfig.customBranding.companyName && (
                    <div className="company-name">{reportConfig.customBranding.companyName}</div>
                  )}
                  <h1>{reportConfig.title}</h1>
                  <div className="report-meta">
                    <span>Generated: {new Date(reportPreview.generated_at || Date.now()).toLocaleString()}</span>
                    {selectedScan && (
                      <span>Extension: {selectedScan.extension_name || 'Unknown'}</span>
                    )}
                  </div>
                </div>

                {reportConfig.includeExecutiveSummary && selectedScan?.executive_summary && (
                  <div className="report-section">
                    <h2>Executive Summary</h2>
                    <div className="risk-badge" data-risk={selectedScan.executive_summary.overall_risk_level}>
                      Risk Level: {selectedScan.executive_summary.overall_risk_level?.toUpperCase()}
                    </div>
                    <p>{selectedScan.executive_summary.summary || selectedScan.executive_summary.executive_overview}</p>
                    
                    {selectedScan.executive_summary.business_impact && (
                      <div className="business-impact">
                        <h3>Business Impact</h3>
                        <ul>
                          <li><strong>Data Breach Risk:</strong> {selectedScan.executive_summary.business_impact.data_breach_risk}</li>
                          <li><strong>Financial Impact:</strong> {selectedScan.executive_summary.business_impact.financial_impact_range}</li>
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {reportConfig.includeFindings && selectedScan?.executive_summary?.key_findings && (
                  <div className="report-section">
                    <h2>Key Findings</h2>
                    <ul className="findings-list">
                      {selectedScan.executive_summary.key_findings.map((finding, idx) => (
                        <li key={idx}>
                          {typeof finding === 'string' ? finding : finding.finding}
                          {finding.priority && <span className="priority-badge">{finding.priority}</span>}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {reportConfig.includeSASTResults && selectedScan?.analysis_results?.javascript_analysis?.findings && (
                  <div className="report-section">
                    <h2>SAST Analysis Results</h2>
                    <p>Total Findings: {selectedScan.analysis_results.javascript_analysis.findings.length}</p>
                    <div className="findings-summary">
                      {selectedScan.analysis_results.javascript_analysis.findings.slice(0, 5).map((finding, idx) => (
                        <div key={idx} className="finding-item" data-severity={finding.severity}>
                          <strong>{finding.severity}:</strong> {finding.message}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {reportConfig.includeRecommendations && selectedScan?.executive_summary?.recommendations && (
                  <div className="report-section">
                    <h2>Recommendations</h2>
                    <ol className="recommendations-list">
                      {selectedScan.executive_summary.recommendations.map((rec, idx) => (
                        <li key={idx}>{rec}</li>
                      ))}
                    </ol>
                  </div>
                )}

                <div className="report-footer">
                  <p>{reportConfig.customBranding.footerText}</p>
                </div>
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};

export default ReportBuilderPage;

// Made with Bob
