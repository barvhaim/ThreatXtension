import React from 'react';
import HeaderBar from './HeaderBar';

const Layout = ({ children }) => {
  return (
    <div className="app-layout">
      <HeaderBar />
      <main className="main-content">
        <div className="content-wrapper">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;
import HeaderBar from './HeaderBar';

const Layout = ({ children }) => {
  return (
    <div className="app-layout">
      <HeaderBar />
      <main className="main-content">
        <div className="content-wrapper">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;
