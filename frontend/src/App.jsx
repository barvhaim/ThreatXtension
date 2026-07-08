import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  NavLink,
} from "react-router-dom";
import DashboardPage from "./pages/DashboardPage";
import ScanHistoryPage from "./pages/ScanHistoryPage";

import AnalysisPage from "./pages/AnalysisPage";
import SASTSignaturesPage from "./pages/SASTSignaturesPage";
import SettingsPage from "./pages/SettingsPage";
import "./App.scss";

function App() {
  // Set dark mode
  React.useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  return (
    <Router>
      <div className="app">
        <header className="modern-header">
          <div className="header-content">
            <NavLink to="/" className="logo-link">
              <div className="logo-icon">
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
              <div className="flex flex-col">
                <span className="logo-text">ThreatXtension</span>
                <span className="text-[10px] text-muted-foreground font-medium tracking-wider uppercase">
                  Extension Security
                </span>
              </div>
              <div className="logo-badge">BETA</div>
            </NavLink>

            <nav className="main-nav">
              <NavLink
                to="/"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
                end
              >
                <span className="nav-icon">📊</span>
                <span className="nav-text">Dashboard</span>
              </NavLink>
              <NavLink
                to="/scan-history"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
              >
                <span className="nav-icon">📋</span>
                <span className="nav-text">History</span>
              </NavLink>

              <NavLink
                to="/analysis"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
              >
                <span className="nav-icon">🔬</span>
                <span className="nav-text">Analysis</span>
              </NavLink>

              <NavLink
                to="/sast-signatures"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
              >
                <span className="nav-icon">✨</span>
                <span className="nav-text">SAST Signatures</span>
              </NavLink>
            </nav>

            <div className="header-actions">
              <NavLink
                to="/settings"
                className="action-btn settings-btn"
                aria-label="Settings"
              >
                <span>⚙️</span>
              </NavLink>
            </div>
          </div>
          <div className="header-glow"></div>
        </header>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/scan-history" element={<ScanHistoryPage />} />

            <Route path="/analysis" element={<AnalysisPage />} />
            <Route path="/sast-signatures" element={<SASTSignaturesPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
