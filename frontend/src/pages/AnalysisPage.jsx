import React from "react";


const AnalysisPage = () => {
  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">🔒 Security Analysis</h1>
        <p className="page-subtitle">
          Detailed security analysis and SAST findings for Chrome extensions
        </p>
      </div>

      <div className="glass-card">
        <div className="flex items-center gap-3 mb-6">
          <span className="text-2xl">🚨</span>
          <h2 className="text-xl font-bold">High-Risk Extensions Analysis</h2>
        </div>

        <div className="p-8 text-center text-foreground-muted border border-dashed border-border/50 rounded-xl bg-surface/30">
          <p className="mb-4">
            This module provides deep-dive SAST (Static Application Security Testing) analysis.
          </p>
          <p>
            Select a scan from the History or run a Live Scan to populate this data.
          </p>
        </div>
      </div>
    </div>
  );
};

export default AnalysisPage;