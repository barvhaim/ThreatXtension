import React, { useState, useEffect } from "react";
import { Settings, Shield, Save, RotateCcw } from "lucide-react";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";

const SettingsPage = () => {
  const [settings, setSettings] = useState({
    securityEngine: "standard", // standard, aggressive
    notifications: true,
  });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("threat_settings");
    if (stored) {
      setSettings(JSON.parse(stored));
    }
  }, []);

  const handleSave = () => {
    localStorage.setItem("threat_settings", JSON.stringify(settings));
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleChange = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">⚙️ Settings</h1>
        <p className="page-subtitle">
          Configure ThreatXtension system settings and preferences
        </p>
      </div>

      <div className="glass-card max-w-4xl mx-auto">
        <div className="flex items-center justify-between mb-6 border-b border-border/50 pb-4">
          <div className="flex items-center gap-3">
            <Settings className="w-6 h-6 text-primary" />
            <h2 className="text-xl font-bold">System Configuration</h2>
          </div>
          <Button onClick={handleSave} className="gap-2">
            {saved ? <span className="text-green-400">Saved!</span> : <><Save className="w-4 h-4" /> Save Changes</>}
          </Button>
        </div>

        <div className="space-y-6">
          <div className="p-6 rounded-lg bg-surface/50 border border-border/50">
            <div className="flex items-start gap-4">
              <Shield className="w-6 h-6 text-success mt-1" />
              <div className="flex-1">
                <div className="font-semibold text-lg">Security Engine Mode</div>
                <p className="text-sm text-foreground-muted mb-4">Set the sensitivity of the SAST analysis engine.</p>

                <div className="flex gap-4">
                  <label className={`flex-1 p-4 rounded-lg border cursor-pointer transition-all ${settings.securityEngine === 'standard' ? 'bg-primary/20 border-primary' : 'bg-background/50 border-border hover:border-border-strong'}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <input
                        type="radio"
                        name="engine"
                        checked={settings.securityEngine === 'standard'}
                        onChange={() => handleChange('securityEngine', 'standard')}
                        className="text-primary"
                      />
                      <span className="font-bold">Standard</span>
                    </div>
                    <p className="text-xs text-foreground-muted">Balanced checks for common vulnerabilities and known threats.</p>
                  </label>

                  <label className={`flex-1 p-4 rounded-lg border cursor-pointer transition-all ${settings.securityEngine === 'aggressive' ? 'bg-destructive/10 border-destructive' : 'bg-background/50 border-border hover:border-border-strong'}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <input
                        type="radio"
                        name="engine"
                        checked={settings.securityEngine === 'aggressive'}
                        onChange={() => handleChange('securityEngine', 'aggressive')}
                        className="text-destructive"
                      />
                      <span className="font-bold text-destructive">Aggressive</span>
                    </div>
                    <p className="text-xs text-foreground-muted">Deep heuristic analysis. May produce more false positives.</p>
                  </label>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};

export default SettingsPage;