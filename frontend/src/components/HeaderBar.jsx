import React from 'react';
import { Header, HeaderName, HeaderNavigation, HeaderMenuItem, HeaderGlobalBar, HeaderGlobalAction } from '@carbon/react';

const HeaderBar = () => {
  return (
    <Header aria-label="ThreatXtension">
      <HeaderName href="/" prefix="">
        <div className="header-logo">
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">ThreatXtension</span>
        </div>
      </HeaderName>

      <HeaderNavigation aria-label="ThreatXtension Navigation">
        <HeaderMenuItem href="/">
          <span className="nav-item">
            <span className="nav-icon">📊</span>
            Dashboard
          </span>
        </HeaderMenuItem>
        <HeaderMenuItem href="/scan-history">
          <span className="nav-item">
            <span className="nav-icon">📋</span>
            Scan History
          </span>
        </HeaderMenuItem>
        <HeaderMenuItem href="/live-scan">
          <span className="nav-item">
            <span className="nav-icon">🔍</span>
            Live Scan
          </span>
        </HeaderMenuItem>
        <HeaderMenuItem href="/analysis">
          <span className="nav-item">
            <span className="nav-icon">🧠</span>
            Analysis
          </span>
        </HeaderMenuItem>
      </HeaderNavigation>

      <HeaderGlobalBar>
        <HeaderGlobalAction aria-label="Settings" tooltipAlignment="end">
          <span className="global-icon">⚙️</span>
        </HeaderGlobalAction>
        <HeaderGlobalAction aria-label="Notifications" tooltipAlignment="end">
          <span className="global-icon">🔔</span>
        </HeaderGlobalAction>
      </HeaderGlobalBar>
    </Header>
  );
};

export default HeaderBar;
import { Header, HeaderName, HeaderNavigation, HeaderMenuItem, HeaderGlobalBar, HeaderGlobalAction } from '@carbon/react';

const HeaderBar = () => {
  return (
    <Header aria-label="ThreatXtension">
      <HeaderName href="/" prefix="">
        <div className="header-logo">
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">ThreatXtension</span>
        </div>
      </HeaderName>

      <HeaderNavigation aria-label="ThreatXtension Navigation">
        <HeaderMenuItem href="/">
          <span className="nav-item">
            <span className="nav-icon">📊</span>
            Dashboard
          </span>
        </HeaderMenuItem>
        <HeaderMenuItem href="/scan-history">
          <span className="nav-item">
            <span className="nav-icon">📋</span>
            Scan History
          </span>
        </HeaderMenuItem>
        <HeaderMenuItem href="/live-scan">
          <span className="nav-item">
            <span className="nav-icon">🔍</span>
            Live Scan
          </span>
        </HeaderMenuItem>
        <HeaderMenuItem href="/analysis">
          <span className="nav-item">
            <span className="nav-icon">🧠</span>
            Analysis
          </span>
        </HeaderMenuItem>
      </HeaderNavigation>

      <HeaderGlobalBar>
        <HeaderGlobalAction aria-label="Settings" tooltipAlignment="end">
          <span className="global-icon">⚙️</span>
        </HeaderGlobalAction>
        <HeaderGlobalAction aria-label="Notifications" tooltipAlignment="end">
          <span className="global-icon">🔔</span>
        </HeaderGlobalAction>
      </HeaderGlobalBar>
    </Header>
  );
};

export default HeaderBar;
