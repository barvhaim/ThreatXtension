import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  NavLink,
} from "react-router-dom";
import {
  LayoutDashboard,
  ScrollText,
  Microscope,
  Fingerprint,
  Settings,
  ShieldHalf,
  Terminal,
} from "lucide-react";
import DashboardPage from "./pages/DashboardPage";
import ScanHistoryPage from "./pages/ScanHistoryPage";
import AnalysisPage from "./pages/AnalysisPage";
import SASTSignaturesPage from "./pages/SASTSignaturesPage";
import SettingsPage from "./pages/SettingsPage";
import "./App.scss";

const NAV = [
  { to: "/", label: "Dashboard", code: "01", Icon: LayoutDashboard, end: true },
  { to: "/scan-history", label: "History", code: "02", Icon: ScrollText },
  { to: "/analysis", label: "Analysis", code: "03", Icon: Microscope },
  { to: "/sast-signatures", label: "Signatures", code: "04", Icon: Fingerprint },
];

function App() {
  React.useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  return (
    <Router>
      <div className="app">
        <header className="console-header">
          <div className="header-scanline" aria-hidden="true" />
          <div className="header-content">
            <NavLink to="/" className="logo-link" end>
              <div className="logo-mark">
                <ShieldHalf size={20} strokeWidth={2.25} />
              </div>
              <div className="logo-copy">
                <span className="logo-text">
                  threat<span className="logo-x">x</span>tension
                  <span className="cursor-block" aria-hidden="true" />
                </span>
                <span className="logo-sub">chrome extension threat console</span>
              </div>
              <span className="logo-badge">v0·BETA</span>
            </NavLink>

            <nav className="main-nav" aria-label="Primary">
              {NAV.map(({ to, label, code, Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    `nav-link ${isActive ? "active" : ""}`
                  }
                >
                  <span className="nav-code">{code}</span>
                  <Icon className="nav-icon" size={16} strokeWidth={2} />
                  <span className="nav-text">{label}</span>
                </NavLink>
              ))}
            </nav>

            <div className="header-actions">
              <div className="sys-status" title="Analysis engine online">
                <span className="sys-led" />
                <span className="sys-text">ENGINE&nbsp;ONLINE</span>
              </div>
              <NavLink
                to="/settings"
                className={({ isActive }) =>
                  `action-btn ${isActive ? "active" : ""}`
                }
                aria-label="Settings"
              >
                <Settings size={18} strokeWidth={2} />
              </NavLink>
            </div>
          </div>
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

        <footer className="console-footer">
          <span className="footer-dot" />
          <Terminal size={12} strokeWidth={2} />
          <span>read-only sandboxed analysis · no code executed</span>
          <span className="footer-sep">//</span>
          <span>static · sast · reputation · llm triage</span>
        </footer>
      </div>
    </Router>
  );
}

export default App;
