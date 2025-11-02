import React from "react";
import { Tile } from "@carbon/react";

const SettingsPage = () => {
  return (
    <div>
      <h1>⚙️ Settings</h1>
      <p
        className="cds--type-productive-heading-01"
        style={{ color: "#525252", marginBottom: "2rem" }}
      >
        Configure ThreatXtension system settings and preferences
      </p>

      <Tile>
        <h3>🔧 System Configuration</h3>
        <p>This page will contain system configuration options and settings.</p>
      </Tile>
    </div>
  );
};

export default SettingsPage;
