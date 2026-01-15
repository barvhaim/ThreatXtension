import React from "react";

import { Settings, Shield, Bell, Lock } from "lucide-react";
import { Button } from "../components/ui/button";

const SettingsPage = () => {
  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">⚙️ Settings</h1>
        <p className="page-subtitle">
          Configure ThreatXtension system settings and preferences
        </p>
      </div>

      <div className="glass-card max-w-4xl mx-auto">
        <div className="flex items-center gap-3 mb-6 border-b border-border/50 pb-4">
          <Settings className="w-6 h-6 text-primary" />
          <h2 className="text-xl font-bold">System Configuration</h2>
        </div>

        <div className="space-y-6">
          <div className="flex items-center justify-between p-4 rounded-lg bg-surface/50 border border-border/50">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-success" />
              <div>
                <div className="font-semibold">Security Engine</div>
                <div className="text-sm text-foreground-muted">Configure SAST rules and sensitivity</div>
              </div>
            </div>
            <Button variant="outline" size="sm">Configure</Button>
          </div>

          <div className="flex items-center justify-between p-4 rounded-lg bg-surface/50 border border-border/50">
            <div className="flex items-center gap-3">
              <Bell className="w-5 h-5 text-warning" />
              <div>
                <div className="font-semibold">Notifications</div>
                <div className="text-sm text-foreground-muted">Alert preferences and webhooks</div>
              </div>
            </div>
            <Button variant="outline" size="sm">Configure</Button>
          </div>

          <div className="flex items-center justify-between p-4 rounded-lg bg-surface/50 border border-border/50">
            <div className="flex items-center gap-3">
              <Lock className="w-5 h-5 text-accent" />
              <div>
                <div className="font-semibold">API Access</div>
                <div className="text-sm text-foreground-muted">Manage API keys and rate limits</div>
              </div>
            </div>
            <Button variant="outline" size="sm">Manage</Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;