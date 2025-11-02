import React from "react";
import { Tile } from "@carbon/react";

const AnalysisPage = () => {
  return (
    <div>
      <h1>🔒 Security Analysis</h1>
      <p
        className="cds--type-productive-heading-01"
        style={{ color: "#525252", marginBottom: "2rem" }}
      >
        Detailed security analysis and SAST findings for Chrome extensions
      </p>

      <Tile>
        <h3>🚨 High-Risk Extensions Analysis</h3>
        <p>
          This page will show detailed security analysis of extensions with
          high-risk findings.
        </p>
      </Tile>
    </div>
  );
};

export default AnalysisPage;
