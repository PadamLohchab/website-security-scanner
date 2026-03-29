// SecureScan - Popup script
document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scanBtn');
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  const noResults = document.getElementById('noResults');
  const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
  const warningsList = document.getElementById('warningsList');
  const infoList = document.getElementById('infoList');
  const exportBtn = document.getElementById('exportBtn');
  const clearBtn = document.getElementById('clearBtn');
  const copyBtn = document.getElementById('copyBtn');
  const themeToggle = document.getElementById('themeToggle');
  const settingsBtn = document.getElementById('settingsBtn');
  const settingsOverlay = document.getElementById('settingsOverlay');
  const settingsClose = document.getElementById('settingsClose');

  let currentScanResults = null;

  // --- Theme ---
  function applyTheme(isDark) {
    document.body.classList.toggle('light-mode', !isDark);
  }

  function loadTheme() {
    chrome.storage.local.get(['secureScanTheme'], (data) => {
      const isDark = data.secureScanTheme !== 'light';
      applyTheme(isDark);
    });
  }

  themeToggle?.addEventListener('click', () => {
    const isLight = document.body.classList.contains('light-mode');
    applyTheme(isLight);
    chrome.storage.local.set({ secureScanTheme: isLight ? 'dark' : 'light' });
  });

  loadTheme();

  // --- Settings ---
  function openSettings() {
    settingsOverlay?.classList.remove('hidden');
    const dark = document.getElementById('settingDarkMode');
    if (dark) dark.checked = !document.body.classList.contains('light-mode');
    chrome.storage.local.get(['secureScanScriptsYellow', 'secureScanScriptsRed', 'secureScanStylesYellow', 'secureScanStylesRed'], (d) => {
      const y1 = document.getElementById('settingScriptsYellow');
      const r1 = document.getElementById('settingScriptsRed');
      const y2 = document.getElementById('settingStylesYellow');
      const r2 = document.getElementById('settingStylesRed');
      if (y1) y1.value = d.secureScanScriptsYellow ?? 20;
      if (r1) r1.value = d.secureScanScriptsRed ?? 40;
      if (y2) y2.value = d.secureScanStylesYellow ?? 30;
      if (r2) r2.value = d.secureScanStylesRed ?? 50;
    });
  }

  function closeSettings() {
    settingsOverlay?.classList.add('hidden');
    const dark = document.getElementById('settingDarkMode');
    if (dark) {
      applyTheme(dark.checked);
      chrome.storage.local.set({ secureScanTheme: dark.checked ? 'dark' : 'light' });
    }
    const y1 = document.getElementById('settingScriptsYellow');
    const r1 = document.getElementById('settingScriptsRed');
    const y2 = document.getElementById('settingStylesYellow');
    const r2 = document.getElementById('settingStylesRed');
    if (y1) chrome.storage.local.set({ secureScanScriptsYellow: parseInt(y1.value, 10) || 20 });
    if (r1) chrome.storage.local.set({ secureScanScriptsRed: parseInt(r1.value, 10) || 40 });
    if (y2) chrome.storage.local.set({ secureScanStylesYellow: parseInt(y2.value, 10) || 30 });
    if (r2) chrome.storage.local.set({ secureScanStylesRed: parseInt(r2.value, 10) || 50 });
  }

  settingsBtn?.addEventListener('click', openSettings);
  settingsClose?.addEventListener('click', closeSettings);
  settingsOverlay?.addEventListener('click', (e) => { if (e.target === settingsOverlay) closeSettings(); });

  // --- Mobile tabs ---
  function switchTab(tabName) {
    ['panelFindings', 'panelSiteInfo', 'panelPerformance'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
    const targetId = tabName === 'findings' ? 'panelFindings' : tabName === 'siteinfo' ? 'panelSiteInfo' : 'panelPerformance';
    const target = document.getElementById(targetId);
    if (target) { target.style.display = 'flex'; target.style.flexDirection = 'column'; target.scrollTop = 0; }
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    const activeBtn = document.querySelector('.tab-btn[data-tab="' + tabName + '"]');
    if (activeBtn) activeBtn.classList.add('active');
  }

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.getAttribute('data-tab')));
  });

  async function getCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab;
  }

  scanBtn?.addEventListener('click', async () => {
    try {
      const tab = await getCurrentTab();
      loading?.classList.remove('hidden');
      results?.classList.add('hidden');
      noResults?.classList.add('hidden');
      const scanBtnText = document.getElementById('scanBtnText');
      if (scanBtnText) scanBtnText.textContent = 'Scanning…';
      scanBtn.disabled = true;
      scanBtn.classList.add('scanning');
      try {
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
      } catch (e) {}
      chrome.tabs.sendMessage(tab.id, { type: 'run-scan' }, () => {
        // Suppress lastError — content script may still be initialising
        // on SPA pages (e.g. HackMD). The timeout below loads results.
        void chrome.runtime.lastError;
      });
      setTimeout(() => {
        loadStoredResults();
        if (scanBtnText) scanBtnText.textContent = 'Scan current page';
        scanBtn.disabled = false;
        scanBtn.classList.remove('scanning');
      }, 3500);
    } catch (err) {
      console.error(err);
      loading?.classList.add('hidden');
      const scanBtnText = document.getElementById('scanBtnText');
      if (scanBtnText) scanBtnText.textContent = 'Scan current page';
      scanBtn.disabled = false;
      scanBtn.classList.remove('scanning');
      alert('Error running scan. Please try again.');
    }
  });

  function loadStoredResults() {
    chrome.storage.local.get(['lastScanResults'], (data) => {
      if (data.lastScanResults) {
        currentScanResults = data.lastScanResults;
        displayResults(data.lastScanResults);
      } else {
        loading?.classList.add('hidden');
        noResults?.classList.remove('hidden');
      }
    });
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text ?? '';
    return div.innerHTML;
  }

  function getRecommendationForType(type) {
    const map = {
      'mixed-content': 'Serve all resources over HTTPS. Replace http:// URLs with https:// or use protocol-relative URLs.',
      'cookies': 'Set the Secure flag on cookies when served over HTTPS.',
      'xss-pattern': 'Sanitize user input and use Content-Security-Policy headers.',
      'csrf': 'Add CSRF tokens to all state-changing forms (e.g. hidden input with token).',
      'headers': 'Configure security headers (CSP, HSTS, X-Frame-Options, etc.) on the server.',
      'password-exposure': 'Never expose passwords in client-side code or page content.',
      'api-key-exposure': 'Move API keys to server-side only; use environment variables.',
      'secret-exposure': 'Remove secrets from client-visible code; use backend-only config.',
      'token-exposure': 'Keep tokens server-side or in httpOnly cookies only.',
      'aws-key-exposure': 'Rotate exposed keys immediately; never commit to frontend.',
      'autocomplete': 'Set autocomplete="off" on sensitive inputs (password, card).',
      'outdated-library': 'Update the library to a supported version; check for CVEs.',
      'sql-injection-pattern': 'Use parameterized queries and input validation.',
      'input-validation': 'Add maxlength and server-side validation for all inputs.'
    };
    return map[type] || 'Review and fix this finding according to security best practices.';
  }

  function computeSecurityScore(scanData) {
    let score = 100;
    (scanData.vulnerabilities || []).forEach(v => {
      if (v.severity === 'critical') score -= 25;
      else if (v.severity === 'high') score -= 15;
    });
    (scanData.warnings || []).forEach(w => {
      if (w.severity === 'medium') score -= 5;
      else if (w.severity === 'low') score -= 2;
    });
    (scanData.info || []).forEach(() => { score -= 1; });
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  function displayResults(scanData) {
    switchTab('findings'); // always reset to findings tab on new results
    loading?.classList.add('hidden');
    results?.classList.remove('hidden');
    noResults?.classList.add('hidden');

    document.getElementById('currentUrl').textContent = scanData.url || '';

    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    (scanData.vulnerabilities || []).forEach(v => { counts[v.severity] = (counts[v.severity] || 0) + 1; });
    (scanData.warnings || []).forEach(w => { counts[w.severity] = (counts[w.severity] || 0) + 1; });
    (scanData.info || []).forEach(i => { counts[i.severity] = (counts[i.severity] || 0) + 1; });

    ['critical', 'high', 'medium', 'low', 'info'].forEach(s => {
      const el = document.getElementById(s + 'Count');
      if (el) el.textContent = counts[s] || 0;
    });

    const pillCritical = document.getElementById('pillCritical');
    if (pillCritical) {
      pillCritical.classList.toggle('pulse', (counts.critical || 0) > 0);
    }

    const score = computeSecurityScore(scanData);
    const scoreEl = document.getElementById('securityScore');
    if (scoreEl) scoreEl.textContent = score;
    const circle = document.getElementById('scoreCircle');
    if (circle) {
      const circumference = 2 * Math.PI * 42;
      const offset = circumference * (1 - score / 100);
      circle.style.strokeDashoffset = offset;
      circle.style.stroke = score >= 70 ? 'var(--low)' : score >= 40 ? 'var(--medium)' : 'var(--critical)';
    }

    if (scanData.websiteInfo) {
      displayWebsiteInfo(scanData.websiteInfo);
      displayStatistics(scanData);
    }

    displayVulnerabilitiesInfo(scanData.vulnerabilityChecks || {}, scanData);
    renderFindingsList(vulnerabilitiesList, scanData.vulnerabilities || [], 'vulnerability');
    renderFindingsList(warningsList, scanData.warnings || [], 'warning');
    renderFindingsList(infoList, groupInfoItems(scanData.info || []), 'info');
  }

  // Group similar info items to avoid noisy repeated messages
  function groupInfoItems(items) {
    const groups = {};
    items.forEach(item => {
      // Use type as group key
      const key = item.type || item.message;
      if (!groups[key]) {
        groups[key] = { ...item, count: 1 };
      } else {
        groups[key].count++;
      }
    });
    return Object.values(groups).map(item => {
      if (item.count > 1) {
        return { ...item, message: `${item.message} (×${item.count})` };
      }
      return item;
    });
  }

  function renderFindingsList(container, items, type) {
    if (!container) return;
    container.innerHTML = '';
    if (items.length === 0) {
      container.innerHTML = '<p class="no-items">No findings.</p>';
      return;
    }
    items.forEach((item, index) => {
      const card = createFindingCard(item, type, index);
      container.appendChild(card);
    });
  }

  function createFindingCard(item, type, index) {
    const div = document.createElement('div');
    div.className = `finding-card severity-${item.severity}`;

    const fixText = getRecommendationForType(item.type);

    const header = document.createElement('div');
    header.className = 'finding-header';
    header.innerHTML = `
      <span class="finding-title">${escapeHtml(item.message)}</span>
      <span class="finding-badges">
        <span class="severity-badge ${item.severity}">${(item.severity || '').toUpperCase()}</span>
      </span>
      <button type="button" class="finding-toggle" aria-expanded="false">▼</button>
    `;

    const body = document.createElement('div');
    body.className = 'finding-body';
    let detailsHtml = '';
    if (item.details) {
      if (Array.isArray(item.details)) {
        detailsHtml = '<ul>';
        item.details.forEach(d => {
          detailsHtml += '<li>' + escapeHtml(typeof d === 'object' ? JSON.stringify(d) : d) + '</li>';
        });
        detailsHtml += '</ul>';
      } else if (typeof item.details === 'object') {
        detailsHtml = '<pre>' + escapeHtml(JSON.stringify(item.details, null, 2)) + '</pre>';
      } else {
        detailsHtml = '<p>' + escapeHtml(item.details) + '</p>';
      }
    }
    body.innerHTML = `
      <div class="finding-details">${detailsHtml || '<p>No additional details.</p>'}</div>
      <div class="finding-fix"><strong>Recommended fix</strong><br>${escapeHtml(fixText)}</div>
    `;

    div.appendChild(header);
    div.appendChild(body);

    header.addEventListener('click', () => {
      div.classList.toggle('expanded');
      const toggle = div.querySelector('.finding-toggle');
      if (toggle) toggle.setAttribute('aria-expanded', div.classList.contains('expanded'));
    });

    return div;
  }

  function displayVulnerabilitiesInfo(checks, scanData) {
    const container = document.getElementById('vulnerabilitiesInfo');
    if (!container) return;
    const entries = Object.entries(checks);
    const totalIssues = (scanData?.vulnerabilities?.length || 0) + (scanData?.warnings?.length || 0);

    if (entries.length === 0) {
      container.innerHTML = '<h3>Vulnerabilities info</h3><p class="no-items">Run a scan to see checked categories.</p>';
      return;
    }

    if (totalIssues === 0 && entries.every(([, d]) => d.passed)) {
      container.innerHTML = `
        <h3>Vulnerabilities info</h3>
        <div class="all-clear">
          <span class="check-icon">✅</span>
          <span>All Clear</span>
        </div>
      `;
      return;
    }

    let html = '<h3>Vulnerabilities info</h3><ul>';
    entries.forEach(([, data]) => {
      const icon = data.passed ? '✅' : '❌';
      const cls = data.passed ? 'vuln-pass' : 'vuln-fail';
      html += `<li class="${cls}">${icon} ${escapeHtml(data.label)}</li>`;
    });
    html += '</ul>';
    container.innerHTML = html;
  }

  function displayStatistics(scanData) {
    const dashboard = document.getElementById('statsDashboard');
    if (!dashboard) return;

    const totalIssues = (scanData.vulnerabilities?.length || 0) + (scanData.warnings?.length || 0) + (scanData.info?.length || 0);
    const techStackCount = (scanData.websiteInfo?.technology?.frameworks?.length || 0) +
      (scanData.websiteInfo?.technology?.cms?.length || 0) +
      (scanData.websiteInfo?.technology?.libraries?.length || 0);
    const formsCount = scanData.websiteInfo?.forms?.total ?? 0;
    const linksCount = scanData.websiteInfo?.resources?.totalLinks ?? scanData.websiteInfo?.performance?.links ?? 0;

    dashboard.innerHTML = `
      <div class="stat-card ${totalIssues > 0 ? 'warn' : 'good'}">
        <span class="stat-value">${totalIssues}</span>
        <span class="stat-label">Issues</span>
      </div>
      <div class="stat-card good">
        <span class="stat-value">${techStackCount}</span>
        <span class="stat-label">Technologies</span>
      </div>
      <div class="stat-card">
        <span class="stat-value">${formsCount}</span>
        <span class="stat-label">Forms</span>
      </div>
      <div class="stat-card">
        <span class="stat-value">${linksCount}</span>
        <span class="stat-label">Links</span>
      </div>
    `;
    dashboard.classList.remove('hidden');
  }

  function getThresholds(cb) {
    chrome.storage.local.get(['secureScanScriptsYellow', 'secureScanScriptsRed', 'secureScanStylesYellow', 'secureScanStylesRed'], (d) => {
      cb({
        scriptsYellow: d.secureScanScriptsYellow ?? 20,
        scriptsRed: d.secureScanScriptsRed ?? 40,
        stylesYellow: d.secureScanStylesYellow ?? 30,
        stylesRed: d.secureScanStylesRed ?? 50
      });
    });
  }

  function displayWebsiteInfo(websiteInfo) {
    if (websiteInfo.basic) {
      const el = document.getElementById('basicInfo');
      if (el) el.innerHTML = `
        <div class="info-row"><strong>Title</strong> ${escapeHtml(websiteInfo.basic.title)}</div>
        <div class="info-row"><strong>Description</strong> ${escapeHtml(websiteInfo.basic.description || '—')}</div>
        <div class="info-row"><strong>Language</strong> ${escapeHtml(websiteInfo.basic.language)}</div>
        <div class="info-row"><strong>Charset</strong> ${escapeHtml(websiteInfo.basic.charset)}</div>
      `;
    }

    if (websiteInfo.technology) {
      const tech = websiteInfo.technology;
      const el = document.getElementById('technologyInfo');
      if (el) el.innerHTML = `
        ${tech.frameworks?.length ? `<div class="info-row"><strong>Frameworks</strong> ${tech.frameworks.join(', ')}</div>` : ''}
        ${tech.cms?.length ? `<div class="info-row"><strong>CMS</strong> ${tech.cms.join(', ')}</div>` : ''}
        ${tech.libraries?.length ? `<div class="info-row"><strong>Libraries</strong> ${tech.libraries.join(', ')}</div>` : ''}
        ${!tech.frameworks?.length && !tech.cms?.length && !tech.libraries?.length ? '<div class="info-row">No frameworks or CMS detected</div>' : ''}
      `;
    }

    if (websiteInfo.resources) {
      getThresholds(th => {
        const res = websiteInfo.resources;
        const scriptsWarn = res.scripts?.total > th.scriptsRed ? 'perf-warn-red' : (res.scripts?.total > th.scriptsYellow ? 'perf-warn-yellow' : '');
        const stylesWarn = res.stylesheets?.total > th.stylesRed ? 'perf-warn-red' : (res.stylesheets?.total > th.stylesYellow ? 'perf-warn-yellow' : '');
        const el = document.getElementById('resourcesInfo');
        if (el) el.innerHTML = `
          <div class="info-row"><strong>Internal links</strong> ${res.internalLinks?.length ?? 0}</div>
          <div class="info-row"><strong>External links</strong> ${res.externalLinks?.length ?? 0}</div>
          <div class="info-row"><strong>Images</strong> ${res.images?.total ?? 0} (${res.images?.missingAlt ?? 0} missing alt)</div>
          <div class="info-row ${scriptsWarn}"><strong>Scripts</strong> ${res.scripts?.total ?? 0} ${res.scripts?.total > th.scriptsRed ? '⚠️ High' : res.scripts?.total > th.scriptsYellow ? '⚠️ Elevated' : ''}</div>
          <div class="info-row ${stylesWarn}"><strong>Stylesheets</strong> ${res.stylesheets?.total ?? 0} ${res.stylesheets?.total > th.stylesRed ? '⚠️ High' : res.stylesheets?.total > th.stylesYellow ? '⚠️ Elevated' : ''}</div>
        `;
      });
    }

    if (websiteInfo.forms) {
      const forms = websiteInfo.forms;
      const el = document.getElementById('formsInfo');
      if (el) {
        if (forms.total === 0) el.innerHTML = '<div class="info-row">No forms found</div>';
        else {
          let html = `<div class="info-row"><strong>Total forms</strong> ${forms.total}</div>`;
          (forms.forms || []).slice(0, 5).forEach((f, i) => {
            html += `<div class="info-row">Form ${i + 1}: ${f.method} → ${escapeHtml(f.action || '—')}, CSRF: ${f.hasCSRFToken ? 'Yes' : 'No'}</div>`;
          });
          el.innerHTML = html;
        }
      }
    }

    if (websiteInfo.domain) {
      const d = websiteInfo.domain;
      const el = document.getElementById('domainInfo');
      if (el) el.innerHTML = `
        <div class="info-row"><strong>Protocol</strong> ${d.protocol}</div>
        <div class="info-row"><strong>Hostname</strong> ${d.hostname}</div>
        <div class="info-row"><strong>HTTPS</strong> ${d.isHTTPS ? 'Yes' : 'No'}</div>
        <div class="info-row"><strong>Cookies</strong> ${d.cookies}</div>
        <div class="info-row"><strong>Local Storage</strong> ${d.localStorage}</div>
        <div class="info-row"><strong>Session Storage</strong> ${d.sessionStorage}</div>
      `;
    }

    if (websiteInfo.performance) {
      getThresholds(th => {
        const perf = websiteInfo.performance;
        const loadTimeValid = typeof perf.loadTime === 'number' && perf.loadTime > 0;
        const loadTimeStr = loadTimeValid ? (perf.loadTime / 1000).toFixed(2) + 's' : 'N/A';
        const scriptsWarn = perf.scripts > th.scriptsRed ? 'perf-warn-red' : (perf.scripts > th.scriptsYellow ? 'perf-warn-yellow' : '');
        const stylesWarn = perf.stylesheets > th.stylesRed ? 'perf-warn-red' : (perf.stylesheets > th.stylesYellow ? 'perf-warn-yellow' : '');
        const perfEl = document.getElementById('performanceInfo');
        if (perfEl) perfEl.innerHTML = `
          <div class="info-row"><strong>DOM elements</strong> ${(perf.domElements ?? 0).toLocaleString()}</div>
          <div class="info-row"><strong>Images</strong> ${perf.images ?? 0}</div>
          <div class="info-row ${scriptsWarn}"><strong>Scripts</strong> ${perf.scripts ?? 0}</div>
          <div class="info-row ${stylesWarn}"><strong>Stylesheets</strong> ${perf.stylesheets ?? 0}</div>
          <div class="info-row"><strong>Links</strong> ${perf.links ?? 0}</div>
          <div class="info-row"><strong>Page load time</strong> ${loadTimeStr}</div>
        `;

        const maxDom = Math.max(perf.domElements || 0, 5000);
        const maxScripts = Math.max(perf.scripts || 0, 50);
        const maxStyles = Math.max(perf.stylesheets || 0, 30);
        const metersEl = document.getElementById('perfMeters');
        if (metersEl) metersEl.innerHTML = `
          <div class="perf-meter">
            <div class="perf-meter-header"><span>DOM elements</span><span>${(perf.domElements ?? 0).toLocaleString()}</span></div>
            <div class="perf-meter-bar-wrap"><div class="perf-meter-bar" style="width:${Math.min(100, ((perf.domElements || 0) / maxDom) * 100)}%; background:var(--accent)"></div></div>
          </div>
          <div class="perf-meter">
            <div class="perf-meter-header"><span>Scripts</span><span>${perf.scripts ?? 0}</span></div>
            <div class="perf-meter-bar-wrap"><div class="perf-meter-bar" style="width:${Math.min(100, ((perf.scripts || 0) / maxScripts) * 100)}%; background:${(perf.scripts || 0) > th.scriptsRed ? 'var(--danger)' : (perf.scripts || 0) > th.scriptsYellow ? 'var(--warning)' : 'var(--success)'}"></div></div>
          </div>
          <div class="perf-meter">
            <div class="perf-meter-header"><span>Stylesheets</span><span>${perf.stylesheets ?? 0}</span></div>
            <div class="perf-meter-bar-wrap"><div class="perf-meter-bar" style="width:${Math.min(100, ((perf.stylesheets || 0) / maxStyles) * 100)}%; background:${(perf.stylesheets || 0) > th.stylesRed ? 'var(--danger)' : (perf.stylesheets || 0) > th.stylesYellow ? 'var(--warning)' : 'var(--success)'}"></div></div>
          </div>
        `;
      });
    }
  }

  function generateRecommendations(scanData) {
    const recs = [];
    if (scanData.vulnerabilities?.length) recs.push({ priority: 'High', category: 'Security', message: 'Address critical vulnerabilities immediately.' });
    if (scanData.websiteInfo?.domain && !scanData.websiteInfo.domain.isHTTPS) recs.push({ priority: 'High', category: 'SSL/TLS', message: 'Enable HTTPS.' });
    if (scanData.websiteInfo?.resources?.images?.missingAlt > 0) recs.push({ priority: 'Medium', category: 'Accessibility', message: `Add alt text to ${scanData.websiteInfo.resources.images.missingAlt} image(s).` });
    if (scanData.websiteInfo?.forms?.forms?.some(f => f.method === 'POST' && !f.hasCSRFToken)) recs.push({ priority: 'High', category: 'Security', message: 'Implement CSRF tokens for POST forms.' });
    return recs;
  }

  function getPlainTextSummary(scanData) {
    const score = computeSecurityScore(scanData);
    let s = `SecureScan Report\n${'='.repeat(40)}\nURL: ${scanData.url}\nDate: ${new Date(scanData.timestamp).toLocaleString()}\nSecurity Score: ${score}/100\n\n`;
    s += `Findings: ${scanData.vulnerabilities?.length || 0} critical/high, ${scanData.warnings?.length || 0} warnings, ${scanData.info?.length || 0} info\n\n`;
    (scanData.vulnerabilities || []).forEach(v => { s += `- [${v.severity}] ${v.message}\n`; });
    (scanData.warnings || []).forEach(w => { s += `- [${w.severity}] ${w.message}\n`; });
    s += '\nRecommendations:\n';
    generateRecommendations(scanData).forEach(r => { s += `- [${r.priority}] ${r.message}\n`; });
    return s;
  }

  copyBtn?.addEventListener('click', () => {
    if (!currentScanResults) {
      alert('No results to copy.');
      return;
    }
    const text = getPlainTextSummary(currentScanResults);
    navigator.clipboard.writeText(text).then(() => alert('Summary copied to clipboard.')).catch(() => alert('Could not copy.'));
  });

  exportBtn?.addEventListener('click', () => {
    if (!currentScanResults) {
      alert('No results to export.');
      return;
    }
    const score = computeSecurityScore(currentScanResults);
    const recs = generateRecommendations(currentScanResults);
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SecureScan Report</title>
  <style>
    body { font-family: Inter, Segoe UI, sans-serif; max-width: 800px; margin: 0 auto; padding: 24px; background: #0f1117; color: #e6e8ec; }
    h1 { color: #4f8ef7; }
    .meta { color: #8b8f98; font-size: 14px; margin-bottom: 24px; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; }
    th, td { border: 1px solid #2a2e3a; padding: 10px 12px; text-align: left; }
    th { background: #1a1d27; color: #4f8ef7; }
    .critical { color: #ef4444; }
    .high { color: #f97316; }
    .medium { color: #eab308; }
    .low { color: #22c55e; }
    .info { color: #4f8ef7; }
    .score { font-size: 32px; font-weight: 700; margin: 16px 0; }
    ul { padding-left: 20px; }
  </style>
</head>
<body>
  <h1>🛡️ SecureScan Report</h1>
  <div class="meta">Generated ${new Date().toISOString()} | URL: ${escapeHtml(currentScanResults.url)}</div>
  <p><strong>Security Score:</strong> <span class="score">${score}/100</span></p>
  <h2>Executive Summary</h2>
  <p>Total issues: ${(currentScanResults.vulnerabilities?.length || 0) + (currentScanResults.warnings?.length || 0) + (currentScanResults.info?.length || 0)} (Critical/High: ${currentScanResults.vulnerabilities?.length || 0}, Warnings: ${currentScanResults.warnings?.length || 0}, Info: ${currentScanResults.info?.length || 0})</p>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Message</th></tr></thead>
    <tbody>
      ${(currentScanResults.vulnerabilities || []).map(v => `<tr><td class="${v.severity}">${v.severity}</td><td>${escapeHtml(v.message)}</td></tr>`).join('')}
      ${(currentScanResults.warnings || []).map(w => `<tr><td class="${w.severity}">${w.severity}</td><td>${escapeHtml(w.message)}</td></tr>`).join('')}
      ${(currentScanResults.info || []).map(i => `<tr><td class="${i.severity}">${i.severity}</td><td>${escapeHtml(i.message)}</td></tr>`).join('')}
    </tbody>
  </table>
  <h2>Recommendations</h2>
  <ul>
    ${recs.map(r => `<li><strong>${r.priority}</strong> [${r.category}] ${escapeHtml(r.message)}</li>`).join('')}
  </ul>
</body>
</html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `securescan-report-${new Date().toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  });

  clearBtn?.addEventListener('click', () => {
    chrome.storage.local.remove(['lastScanResults'], () => {
      currentScanResults = null;
      results?.classList.add('hidden');
      noResults?.classList.remove('hidden');
    });
  });

  loadStoredResults();

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'scan-complete') {
      currentScanResults = message.data;
      displayResults(message.data);
    }
  });
});
