/**
 * CryptoScan Global Shell
 * Injects the global sidebar and topbar into authenticated pages,
 * handles responsive sidebar toggling, search command palette, notifications drawer,
 * documentation guide modal, and user authentication state.
 */

class AppShell {
  constructor() {
    this.init();
  }

  init() {
    const path = window.location.pathname;
    const page = path.split('/').pop() || 'dashboard.html';
    
    // Inject CSS
    if (!document.querySelector('link[href*="global.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'assets/css/global.css';
      document.head.prepend(link);
    }
    if (!document.querySelector('link[href*="visuals.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'assets/css/visuals.css';
      document.head.appendChild(link);
    }

    // Inject Visuals JS
    if (!document.querySelector('script[src*="visuals.js"]')) {
      const script = document.createElement('script');
      script.src = 'assets/js/visuals.js';
      document.body.appendChild(script);
    }

    this.renderSidebar(page);
    this.renderTopbar(page);
    this.injectModals();
    this.bindEvents();
    this.loadUserData();
  }

  renderSidebar(currentPage) {
    const sidebar = document.getElementById('app-sidebar') || document.querySelector('.app-sidebar') || document.querySelector('.sb') || document.querySelector('.sidebar');
    if (!sidebar) return;

    const pageName = currentPage.split('/').pop() || 'dashboard.html';

    const navItems = [
      { group: 'OVERVIEW', items: [
        { name: 'Dashboard', url: 'dashboard.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/>' }
      ]},
      { group: 'ANALYSIS', items: [
        { name: 'Repositories', url: 'repositories.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>' },
        { name: 'Scan', url: 'scan.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/>' },
        { name: 'Findings', url: 'findings.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>' },
        { name: 'CBOM', url: 'cbom.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>' }
      ]},
      { group: 'SECURITY', items: [
        { name: 'Risk & Migration', url: 'risk-migration.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>' },
        { name: 'Verification', url: 'verification.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>' }
      ]},
      { group: 'SYSTEM', items: [
        { name: 'Profile', url: 'profile.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>' },
        { name: 'Settings', url: 'settings.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>' }
      ]}
    ];

    let navHtml = '';
    navItems.forEach(group => {
      navHtml += `<div class="sb-nav-group"><div class="sb-nav-group-title">${group.group}</div>`;
      group.items.forEach(item => {
        const isActive = (pageName === item.url || (pageName === '' && item.url === 'dashboard.html')) ? 'active' : '';
        navHtml += `
          <a href="${item.url}" class="sb-nav-item nav-item ${isActive}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">${item.icon}</svg>
            <span class="sb-label">${item.name}</span>
          </a>
        `;
      });
      navHtml += `</div>`;
    });

    sidebar.innerHTML = `
      <div class="sb-header">
        <a href="dashboard.html" class="sb-brand" style="display:flex; align-items:center; gap:10px; text-decoration:none; width:100%;">
          <img src="assets/images/nebula-logo.png" alt="NEBULA Logo" class="sb-brand-logo" style="height:32px; width:auto; max-height:32px; border-radius:6px; object-fit:contain; filter:drop-shadow(0 0 6px rgba(139,92,246,0.3)); flex-shrink:0;">
          <div style="display:flex; flex-direction:column; justify-content:center;">
            <span class="sb-brand-name" style="font-size:15px; font-weight:800; letter-spacing:1.2px; background:linear-gradient(135deg, #c084fc, #60a5fa); -webkit-background-clip:text; -webkit-text-fill-color:transparent; line-height:1.2;">NEBULA</span>
            <span style="font-size:8.5px; font-weight:600; color:var(--text-muted); letter-spacing:0.8px; text-transform:uppercase; line-height:1.2; margin-top:1px;">CryptoScan Security</span>
          </div>
        </a>
      </div>
      <nav class="sb-content">
        ${navHtml}
      </nav>
      <div class="sb-footer">
        <div class="sb-system-status">
          <div class="indicator"></div>
          <span class="status-text">System Operational</span>
        </div>
        <div class="sb-user">
          <div class="sb-user-avatar" id="sb-user-avatar">S</div>
          <div class="sb-user-info">
            <div class="sb-user-name" id="sb-user-name">Shravani Dinesh Joshi</div>
            <div class="sb-user-role">Security Analyst</div>
          </div>
        </div>
      </div>
    `;
  }

  renderTopbar(currentPage) {
    const topbar = document.getElementById('app-topbar') || document.querySelector('.app-topbar') || document.querySelector('.topbar');
    if (!topbar) return;

    const titles = {
      'dashboard.html': 'Dashboard',
      'repositories.html': 'Repositories',
      'scan.html': 'Scan Repository',
      'findings.html': 'Findings',
      'cbom.html': 'CBOM',
      'risk-migration.html': 'Risk & Migration',
      'verification.html': 'Verification',
      'profile.html': 'Profile',
      'settings.html': 'Settings'
    };
    const title = titles[currentPage] || 'Overview';

    topbar.className = 'app-topbar';
    topbar.id = 'app-topbar';
    topbar.innerHTML = `
      <div class="tb-left">
        <button class="mobile-menu-trigger" id="mobile-menu-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h16"/>
          </svg>
        </button>
        <div class="tb-breadcrumbs" style="display:flex; align-items:center; gap:8px;">
          <img src="assets/images/nebula-logo.png" alt="NEBULA" style="height:22px; width:auto; border-radius:4px;">
          <span style="font-weight:700; color:var(--text-h);">NEBULA</span>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/></svg>
          <span class="current" style="color:#c084fc; font-weight:600;">${title}</span>
        </div>
      </div>

      <div class="tb-right" style="display:flex; align-items:center; gap:12px; position:relative;">
        <!-- Search Trigger -->
        <button class="search-trigger" id="search-trigger-btn" title="Search CryptoScan (Cmd + K)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
          <span>Search</span>
          <kbd>⌘ K</kbd>
        </button>

        <!-- Theme Toggle -->
        <button class="icon-btn" id="theme-toggle-btn" title="Toggle Light/Dark Theme">
          <svg class="theme-icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;display:none;"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
          <svg class="theme-icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
        </button>

        <!-- Notifications Trigger -->
        <div style="position: relative;">
          <button class="icon-btn" id="notifications-btn" title="Security Notifications">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="badge-dot" id="notif-badge-dot"></span>
          </button>

          <!-- Notifications Dropdown Drawer -->
          <div class="notifications-dropdown" id="notifications-dropdown">
            <div class="notif-header">
              <div class="notif-title">
                <span>Notifications</span>
                <span class="notif-count" id="notif-count-badge">3</span>
              </div>
              <button class="notif-clear" id="notif-clear-btn">Mark all as read</button>
            </div>
            <div class="notif-list" id="notif-list-container">
              <a href="findings.html" class="notif-item unread">
                <div class="notif-icon danger">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                </div>
                <div>
                  <div class="notif-text"><strong>High Severity Vulnerability</strong>: Hardcoded RSA-1024 private key found in `backend/auth.js`.</div>
                  <div class="notif-time">10 minutes ago</div>
                </div>
              </a>
              <a href="verification.html" class="notif-item unread">
                <div class="notif-icon purple">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                </div>
                <div>
                  <div class="notif-text"><strong>Sepolia Anchored</strong>: Merkle Proof `#8401` successfully stamped by DigiCert TSA & anchored on Sepolia.</div>
                  <div class="notif-time">1 hour ago</div>
                </div>
              </a>
              <a href="cbom.html" class="notif-item unread">
                <div class="notif-icon success">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                </div>
                <div>
                  <div class="notif-text"><strong>CBOM Export Ready</strong>: CycloneDX v1.6 report generated with ML-DSA-65 migration advice.</div>
                  <div class="notif-time">2 hours ago</div>
                </div>
              </a>
            </div>
          </div>
        </div>

        <!-- Documentation / Guide Trigger -->
        <button class="icon-btn" id="guide-btn" title="CryptoScan Documentation & Guide">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l9-5-9-5-9 5 9 5z"/><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14z"/><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l9-5-9-5-9 5 9 5zm0 0l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14zm-4 6v-7.5l4-2.222"/></svg>
        </button>

        <!-- User Profile / Logout Button -->
        <button class="icon-btn" id="tb-user-btn" title="Account / Logout">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
        </button>
      </div>
    `;
  }

  injectModals() {
    // Inject Search Palette Modal
    if (!document.getElementById('search-modal-overlay')) {
      const searchModalHtml = `
        <div class="cs-overlay" id="search-modal-overlay">
          <div class="cs-modal" id="search-modal">
            <div class="cmd-palette-header">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              <input type="text" class="cmd-palette-input" id="cmd-search-input" placeholder="Search pages, repositories, findings, CBOM assets... (Esc to close)" autocomplete="off">
              <kbd style="font-size:11px; background:var(--bg-main); border:1px solid var(--border-color); padding:2px 6px; border-radius:4px; color:var(--accent-violet);">ESC</kbd>
            </div>
            <div class="cmd-palette-results" id="cmd-palette-results">
              <div class="cmd-group-title">PAGES & MODULES</div>
              <a href="dashboard.html" class="cmd-item">
                <div class="cmd-item-left">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6z"/></svg>
                  <div>
                    <div class="cmd-item-title">Security Dashboard</div>
                    <div class="cmd-item-sub">Overview of system health, scans & anchor proofs</div>
                  </div>
                </div>
                <span class="cmd-item-badge">Overview</span>
              </a>
              <a href="repositories.html" class="cmd-item">
                <div class="cmd-item-left">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2"/></svg>
                  <div>
                    <div class="cmd-item-title">Repositories</div>
                    <div class="cmd-item-sub">Manage uploaded source code archives</div>
                  </div>
                </div>
                <span class="cmd-item-badge">Analysis</span>
              </a>
              <a href="scan.html" class="cmd-item">
                <div class="cmd-item-left">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/></svg>
                  <div>
                    <div class="cmd-item-title">Run Cryptographic Scan</div>
                    <div class="cmd-item-sub">Trigger Python & JS AST scanner engine</div>
                  </div>
                </div>
                <span class="cmd-item-badge">Scanner</span>
              </a>
              <a href="findings.html" class="cmd-item">
                <div class="cmd-item-left">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                  <div>
                    <div class="cmd-item-title">Vulnerability Findings</div>
                    <div class="cmd-item-sub">View hardcoded keys, MD5, DES & RSA-1024 alerts</div>
                  </div>
                </div>
                <span class="cmd-item-badge">Vulnerabilities</span>
              </a>
              <a href="cbom.html" class="cmd-item">
                <div class="cmd-item-left">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                  <div>
                    <div class="cmd-item-title">CycloneDX CBOM Generator</div>
                    <div class="cmd-item-sub">Export Cryptographic Bill of Materials v1.6</div>
                  </div>
                </div>
                <span class="cmd-item-badge">CBOM</span>
              </a>
              <a href="risk-migration.html" class="cmd-item">
                <div class="cmd-item-left">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/></svg>
                  <div>
                    <div class="cmd-item-title">Risk & PQC Migration</div>
                    <div class="cmd-item-sub">Post-quantum roadmap (ML-KEM & ML-DSA)</div>
                  </div>
                </div>
                <span class="cmd-item-badge">PQC</span>
              </a>
              <a href="verification.html" class="cmd-item">
                <div class="cmd-item-left">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  <div>
                    <div class="cmd-item-title">Sepolia Blockchain Verification</div>
                    <div class="cmd-item-sub">Live CryptoAnchor.sol smart contract verifier</div>
                  </div>
                </div>
                <span class="cmd-item-badge">Blockchain</span>
              </a>
            </div>
          </div>
        </div>
      `;
      document.body.insertAdjacentHTML('beforeend', searchModalHtml);
    }

    // Inject Guide Modal
    if (!document.getElementById('guide-modal-overlay')) {
      const guideModalHtml = `
        <div class="cs-overlay" id="guide-modal-overlay">
          <div class="cs-modal" style="max-width: 680px; padding: 24px;">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border-color); padding-bottom:16px; margin-bottom:20px;">
              <div style="display:flex; align-items:center; gap:12px;">
                <div style="width:38px; height:38px; border-radius:10px; background:linear-gradient(135deg,#7c3aed,#8b5cf6); display:flex; align-items:center; justify-content:center; color:white;">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22"><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l9-5-9-5-9 5 9 5z"/><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14z"/></svg>
                </div>
                <div>
                  <h3 style="font-size:18px; font-weight:700; color:var(--text-h); margin:0;">CryptoScan Quick Guide</h3>
                  <p style="font-size:12px; color:var(--text-muted); margin:0;">Enterprise Cryptographic Discovery & On-Chain Verification</p>
                </div>
              </div>
              <button id="guide-close-btn" style="background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:20px; font-weight:700;">&times;</button>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:20px;">
              <div style="background:var(--bg-surface); padding:14px; border-radius:10px; border:1px solid var(--border-color);">
                <div style="font-weight:700; color:#c084fc; font-size:13px; margin-bottom:4px;">1. AST Scan Engine</div>
                <p style="font-size:12px; color:var(--text-muted); margin:0; line-height:1.4;">Analyzes Python & JS source code to find hardcoded keys, MD5, DES & RSA vulnerabilities.</p>
              </div>
              <div style="background:var(--bg-surface); padding:14px; border-radius:10px; border:1px solid var(--border-color);">
                <div style="font-weight:700; color:#c084fc; font-size:13px; margin-bottom:4px;">2. CycloneDX CBOM</div>
                <p style="font-size:12px; color:var(--text-muted); margin:0; line-height:1.4;">Generates standard Cryptographic Bill of Materials v1.6 with PQC transition recommendations.</p>
              </div>
              <div style="background:var(--bg-surface); padding:14px; border-radius:10px; border:1px solid var(--border-color);">
                <div style="font-weight:700; color:#c084fc; font-size:13px; margin-bottom:4px;">3. Merkle & TSA Stamp</div>
                <p style="font-size:12px; color:var(--text-muted); margin:0; line-height:1.4;">Hashes CBOM components into a deterministic Merkle root & stamps with DigiCert RFC 3161 TSA.</p>
              </div>
              <div style="background:var(--bg-surface); padding:14px; border-radius:10px; border:1px solid var(--border-color);">
                <div style="font-weight:700; color:#c084fc; font-size:13px; margin-bottom:4px;">4. Sepolia On-Chain Anchor</div>
                <p style="font-size:12px; color:var(--text-muted); margin:0; line-height:1.4;">Anchors Merkle root to Ethereum Sepolia (`CryptoAnchor.sol`) for zero-trust public proof.</p>
              </div>
            </div>
            <div style="text-align:right;">
              <button id="guide-ok-btn" style="background:linear-gradient(135deg,#7c3aed,#8b5cf6); color:white; border:none; padding:8px 20px; border-radius:8px; font-weight:600; cursor:pointer;">Got it!</button>
            </div>
          </div>
        </div>
      `;
      document.body.insertAdjacentHTML('beforeend', guideModalHtml);
    }
  }

  bindEvents() {
    // 1. Theme toggle
    const themeBtn = document.getElementById('theme-toggle-btn');
    if (themeBtn) {
      themeBtn.addEventListener('click', () => {
        const isLight = document.documentElement.classList.contains('light-mode');
        if (isLight) {
          document.documentElement.classList.remove('light-mode');
          document.documentElement.classList.add('dark');
          localStorage.setItem('cs_theme', 'dark');
        } else {
          document.documentElement.classList.remove('dark');
          document.documentElement.classList.add('light-mode');
          localStorage.setItem('cs_theme', 'light');
        }
        this.updateThemeIcons();
      });
    }
    this.updateThemeIcons();

    // 2. Mobile Sidebar Toggle
    const mobileBtn = document.getElementById('mobile-menu-btn');
    if (mobileBtn) {
      mobileBtn.addEventListener('click', () => {
        document.body.classList.toggle('sidebar-open');
      });
    }

    // 3. Search Palette Trigger & Modal Events
    const searchBtn = document.getElementById('search-trigger-btn');
    const searchOverlay = document.getElementById('search-modal-overlay');
    const searchInput = document.getElementById('cmd-search-input');
    const searchResults = document.getElementById('cmd-palette-results');

    const openSearchModal = () => {
      if (searchOverlay) {
        searchOverlay.classList.add('active');
        if (searchInput) {
          searchInput.value = '';
          searchInput.focus();
          filterSearchResults('');
        }
      }
    };

    const closeSearchModal = () => {
      if (searchOverlay) searchOverlay.classList.remove('active');
    };

    if (searchBtn) {
      searchBtn.addEventListener('click', openSearchModal);
    }

    if (searchOverlay) {
      searchOverlay.addEventListener('click', (e) => {
        if (e.target === searchOverlay) closeSearchModal();
      });
    }

    // Keyboard shortcuts (Cmd+K / Ctrl+K & Escape)
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (searchOverlay && searchOverlay.classList.contains('active')) {
          closeSearchModal();
        } else {
          openSearchModal();
        }
      } else if (e.key === 'Escape') {
        closeSearchModal();
        closeGuideModal();
        closeNotificationsDropdown();
      }
    });

    // Live search input filter
    const filterSearchResults = (query) => {
      if (!searchResults) return;
      const q = query.toLowerCase().trim();
      const items = searchResults.querySelectorAll('.cmd-item');
      items.forEach(item => {
        const title = item.querySelector('.cmd-item-title')?.textContent.toLowerCase() || '';
        const sub = item.querySelector('.cmd-item-sub')?.textContent.toLowerCase() || '';
        if (title.includes(q) || sub.includes(q)) {
          item.style.display = 'flex';
        } else {
          item.style.display = 'none';
        }
      });
    };

    if (searchInput) {
      searchInput.addEventListener('input', (e) => filterSearchResults(e.target.value));
    }

    // 4. Notifications Dropdown Trigger
    const notifBtn = document.getElementById('notifications-btn');
    const notifDropdown = document.getElementById('notifications-dropdown');
    const notifBadge = document.getElementById('notif-badge-dot');
    const notifCountBadge = document.getElementById('notif-count-badge');
    const notifClearBtn = document.getElementById('notif-clear-btn');

    const toggleNotificationsDropdown = (e) => {
      e.stopPropagation();
      if (notifDropdown) {
        notifDropdown.classList.toggle('active');
      }
    };

    const closeNotificationsDropdown = () => {
      if (notifDropdown) notifDropdown.classList.remove('active');
    };

    if (notifBtn) {
      notifBtn.addEventListener('click', toggleNotificationsDropdown);
    }

    document.addEventListener('click', (e) => {
      if (notifDropdown && notifDropdown.classList.contains('active')) {
        if (!notifDropdown.contains(e.target) && e.target !== notifBtn) {
          closeNotificationsDropdown();
        }
      }
    });

    if (notifClearBtn) {
      notifClearBtn.addEventListener('click', () => {
        const unreadItems = document.querySelectorAll('.notif-item.unread');
        unreadItems.forEach(item => item.classList.remove('unread'));
        if (notifBadge) notifBadge.style.display = 'none';
        if (notifCountBadge) notifCountBadge.textContent = '0';
      });
    }

    // 5. Documentation & Guide Modal Events
    const guideBtn = document.getElementById('guide-btn');
    const guideOverlay = document.getElementById('guide-modal-overlay');
    const guideCloseBtn = document.getElementById('guide-close-btn');
    const guideOkBtn = document.getElementById('guide-ok-btn');

    const openGuideModal = () => {
      if (guideOverlay) guideOverlay.classList.add('active');
    };
    const closeGuideModal = () => {
      if (guideOverlay) guideOverlay.classList.remove('active');
    };

    if (guideBtn) guideBtn.addEventListener('click', openGuideModal);
    if (guideCloseBtn) guideCloseBtn.addEventListener('click', closeGuideModal);
    if (guideOkBtn) guideOkBtn.addEventListener('click', closeGuideModal);
    if (guideOverlay) {
      guideOverlay.addEventListener('click', (e) => {
        if (e.target === guideOverlay) closeGuideModal();
      });
    }

    // 6. User Logout
    const userBtn = document.getElementById('tb-user-btn');
    if (userBtn) {
      userBtn.addEventListener('click', () => {
        if (confirm('Are you sure you want to log out of CryptoScan?')) {
          if (window.Auth && window.Auth.logout) {
            window.Auth.logout();
          } else {
            localStorage.removeItem('cs_token');
            localStorage.removeItem('cs_user');
            window.location.href = 'login.html';
          }
        }
      });
    }
  }

  updateThemeIcons() {
    const isLight = document.documentElement.classList.contains('light-mode');
    const sunIcons = document.querySelectorAll('.theme-icon-sun');
    const moonIcons = document.querySelectorAll('.theme-icon-moon');
    sunIcons.forEach(icon => icon.style.display = isLight ? 'block' : 'none');
    moonIcons.forEach(icon => icon.style.display = isLight ? 'none' : 'block');
  }

  loadUserData() {
    try {
      const u = JSON.parse(localStorage.getItem('cs_user'));
      if (u) {
        const name = u.name || (u.email ? u.email.split('@')[0] : 'User');
        const initial = name.charAt(0).toUpperCase();
        
        const avatarEl = document.getElementById('sb-user-avatar');
        const nameEl = document.getElementById('sb-user-name');
        
        if (avatarEl) avatarEl.textContent = initial;
        if (nameEl) nameEl.textContent = name;
      }
    } catch (e) {
      console.warn('Failed to load user data for shell', e);
    }
  }
}

// Initialize shell on DOM load
document.addEventListener('DOMContentLoaded', () => {
  new AppShell();
});
