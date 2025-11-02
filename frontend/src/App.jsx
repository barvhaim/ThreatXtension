import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import {
  Header,
  HeaderContainer,
  HeaderName,
  HeaderNavigation,
  HeaderMenuItem,
} from "@carbon/react";
import { Dashboard, Document, Play, ChartLine } from "@carbon/icons-react";
import DashboardPage from "./pages/DashboardPage";
import ScanHistoryPage from "./pages/ScanHistoryPage";
import LiveScanPage from "./pages/LiveScanPage";
import AnalysisPage from "./pages/AnalysisPage";
import SettingsPage from "./pages/SettingsPage";
import "./App.scss";

function App() {
  // Set dark theme by default
  React.useEffect(() => {
    document.documentElement.setAttribute("data-theme", "dark");
  }, []);

  return (
    <Router>
      <div className="app">
        <HeaderContainer
          render={({ isSideNavExpanded, onClickSideNavExpand }) => (
            <Header className="professional-header">
              <HeaderName className="header-brand" href="#" prefix="">
                🔍 ThreatXtension
              </HeaderName>
              <HeaderNavigation className="header-navigation">
                <HeaderMenuItem className="header-menu-item" href="/">
                  <Dashboard size={20} />
                  <span>Dashboard</span>
                </HeaderMenuItem>
                <HeaderMenuItem
                  className="header-menu-item"
                  href="/scan-history"
                >
                  <Document size={20} />
                  <span>Scan History</span>
                </HeaderMenuItem>
                <HeaderMenuItem className="header-menu-item" href="/live-scan">
                  <Play size={20} />
                  <span>Live Scan</span>
                </HeaderMenuItem>
                <HeaderMenuItem className="header-menu-item" href="/analysis">
                  <ChartLine size={20} />
                  <span>Analysis</span>
                </HeaderMenuItem>
              </HeaderNavigation>
            </Header>
          )}
        />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/scan-history" element={<ScanHistoryPage />} />
            <Route path="/live-scan" element={<LiveScanPage />} />
            <Route path="/analysis" element={<AnalysisPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
