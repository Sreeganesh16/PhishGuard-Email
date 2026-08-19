document.addEventListener('DOMContentLoaded', () => {
  // UI Elements
  const dropZone = document.getElementById('dropZone');
  const emailFileInput = document.getElementById('emailFile');
  const fileInfo = document.getElementById('fileInfo');
  const fileNameDisplay = document.getElementById('fileName');
  const btnClearFile = document.getElementById('btnClearFile');
  const scannedCountBadge = document.getElementById('scannedCountBadge');
  const smtpStreamList = document.getElementById('smtpStreamList');
  
  const emptyStatePanel = document.getElementById('emptyStatePanel');
  const resultsPanel = document.getElementById('resultsPanel');
  
  // Settings Elements
  const vtApiKeyInput = document.getElementById('vtApiKeyInput');
  const btnSaveSettings = document.getElementById('btnSaveSettings');
  const vtKeyStatus = document.getElementById('vtKeyStatus');

  // Dashboard Metrics
  const scoreVal = document.getElementById('scoreVal');
  const scoreCircle = document.getElementById('scoreCircle');
  const verdictBadge = document.getElementById('verdictBadge');
  
  const linkCount = document.getElementById('linkCount');
  const attachmentCount = document.getElementById('attachmentCount');
  const indicatorCountBadge = document.getElementById('indicatorCountBadge');

  // Live Threat Intel Dashboard Elements
  const intelIP = document.getElementById('intelIP');
  const intelGeo = document.getElementById('intelGeo');
  const intelISP = document.getElementById('intelISP');
  const dnsMxBadge = document.getElementById('dnsMxBadge');
  const dnsSpfRecord = document.getElementById('dnsSpfRecord');
  const vtRepContent = document.getElementById('vtRepContent');
  
  // Lists & Tables
  const indicatorList = document.getElementById('indicatorList');
  const mitreList = document.getElementById('mitreList');
  const owaspList = document.getElementById('owaspList');
  const urlList = document.getElementById('urlList');
  const attachmentList = document.getElementById('attachmentList');
  const headerTableBody = document.getElementById('headerTableBody');
  const headerSearch = document.getElementById('headerSearch');

  let allHeaders = []; // Cache to allow fast search filtering
  let streamEmails = []; // In-memory cache for live scanned emails

  // Initialize Lucide Icons
  lucide.createIcons();

  // Initialize SVG Circle circumference
  const radius = scoreCircle.r.baseVal.value;
  const circumference = radius * 2 * Math.PI;
  scoreCircle.style.strokeDasharray = `${circumference} ${circumference}`;
  scoreCircle.style.strokeDashoffset = circumference;

  // -------------------------------------------------------------
  // 1. Settings & Key Configuration
  // -------------------------------------------------------------
  async function checkSettingsStatus() {
    try {
      const res = await fetch('/api/settings');
      const data = await res.json();
      updateSettingsUI(data.vtKeySet);
    } catch (err) {
      console.error('Error fetching settings:', err);
    }
  }

  function updateSettingsUI(isKeySet) {
    if (isKeySet) {
      vtKeyStatus.textContent = 'VT Status: Key Configured (Live Mode)';
      vtKeyStatus.style.color = 'var(--severity-safe)';
      vtApiKeyInput.placeholder = '••••••••••••••••••••••••';
    } else {
      vtKeyStatus.textContent = 'VT Status: Unconfigured (Simulation Mode)';
      vtKeyStatus.style.color = 'var(--text-muted)';
      vtApiKeyInput.placeholder = 'VirusTotal API Key...';
    }
  }

  btnSaveSettings.addEventListener('click', async () => {
    const key = vtApiKeyInput.value.trim();
    if (!key) {
      alert('Please enter a valid API key string.');
      return;
    }

    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vtApiKey: key })
      });
      const data = await res.json();
      if (data.success) {
        updateSettingsUI(data.vtKeySet);
        vtApiKeyInput.value = '';
        alert('VirusTotal API Key configured successfully.');
      }
    } catch (err) {
      alert('Failed to configure settings: ' + err.message);
    }
  });

  // -------------------------------------------------------------
  // 2. Connect to Live Server-Sent Events (Live Ingestion Stream)
  // -------------------------------------------------------------
  function connectSMTPStream() {
    const eventSource = new EventSource('/api/stream');

    eventSource.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'history') {
          streamEmails = payload.data || [];
          renderSMTPStream();
          if (streamEmails.length > 0) {
            displayAnalysisResults(streamEmails[0]);
            highlightActiveStreamItem(0);
          }
        } else if (payload.type === 'new-email') {
          // Check if already in stream
          const exists = streamEmails.some(e => e.id === payload.data.id);
          if (!exists) {
            streamEmails.unshift(payload.data);
            if (streamEmails.length > 30) streamEmails.pop();
            renderSMTPStream();
            displayAnalysisResults(payload.data);
            highlightActiveStreamItem(0);
          }
        }
      } catch (err) {
        console.error('Error processing stream message:', err);
      }
    };

    eventSource.onerror = (err) => {
      console.error('EventSource connection error, reconnecting...', err);
    };
  }

  function highlightActiveStreamItem(index) {
    setTimeout(() => {
      document.querySelectorAll('.stream-item').forEach(el => el.classList.remove('active'));
      const items = smtpStreamList.querySelectorAll('.stream-item');
      if (items[index]) items[index].classList.add('active');
    }, 100);
  }

  function renderSMTPStream() {
    smtpStreamList.innerHTML = '';
    
    if (scannedCountBadge) {
      scannedCountBadge.textContent = `${streamEmails.length} Mail${streamEmails.length === 1 ? '' : 's'}`;
    }

    if (streamEmails.length === 0) {
      smtpStreamList.innerHTML = `<div class="empty-stream-msg">No scanned emails yet. Connect your email above or upload an .eml file.</div>`;
      return;
    }

    streamEmails.forEach((email, index) => {
      const item = document.createElement('div');
      item.className = 'stream-item';
      item.dataset.index = index;
      
      let scoreColor = 'var(--severity-safe)';
      if (email.score >= 75) {
        scoreColor = 'var(--severity-critical)';
      } else if (email.score >= 50) {
        scoreColor = 'var(--severity-high)';
      } else if (email.score >= 25) {
        scoreColor = 'var(--severity-medium)';
      } else if (email.score > 0) {
        scoreColor = 'var(--severity-low)';
      }

      // Extract raw sender
      const fromStr = email.smtpSession ? email.smtpSession.from : (email.from || 'Unknown');
      const tag = email.sourceType || (email.smtpSession ? 'SMTP' : 'Upload');

      item.innerHTML = `
        <div class="stream-item-info">
          <div class="stream-item-title">${escapeHtml(email.subject)}</div>
          <div class="stream-item-sub">From: ${escapeHtml(fromStr)} <span style="opacity: 0.6; font-size: 0.7rem;">(${escapeHtml(tag)})</span></div>
        </div>
        <div class="stream-item-score" style="color: ${scoreColor}; border: 1px solid ${scoreColor}; background: ${scoreColor}10">
          ${email.score}
        </div>
      `;

      item.addEventListener('click', () => {
        document.querySelectorAll('.stream-item').forEach(el => el.classList.remove('active'));
        item.classList.add('active');
        displayAnalysisResults(email);
      });

      smtpStreamList.appendChild(item);
    });
  }

  // -------------------------------------------------------------
  // 3. Perform Upload Analysis
  // -------------------------------------------------------------
  async function uploadAndAnalyzeFile(file) {
    showLoading();
    
    // Show selected file UI
    fileNameDisplay.textContent = file.name;
    fileInfo.style.display = 'flex';
    dropZone.classList.add('hidden');

    const formData = new FormData();
    formData.append('emailFile', file);

    try {
      const res = await fetch('/api/analyze-upload', {
        method: 'POST',
        body: formData
      });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Server returned error');
      }
      const data = await res.json();
      data.sourceType = 'EML Upload';
      
      // Add to stream list
      streamEmails.unshift(data);
      renderSMTPStream();
      displayAnalysisResults(data);
      highlightActiveStreamItem(0);
    } catch (err) {
      alert('Analysis failed: ' + err.message);
      resetToEmptyState();
    }
  }

  // -------------------------------------------------------------
  // 5. Render Dashboard View
  // -------------------------------------------------------------
  function displayAnalysisResults(data) {
    hideLoading();
    emptyStatePanel.style.display = 'none';
    resultsPanel.style.display = 'flex';

    // 1. Update Threat Score Dial
    animateScoreDial(data.score);

    // 2. Update Severity Badge
    verdictBadge.textContent = data.severity.toUpperCase();
    verdictBadge.className = 'verdict-badge'; // reset
    
    // Theme colors based on severity
    let themeClass = 'severity-safe';
    let progressColor = 'var(--severity-safe)';
    
    if (data.severity === 'Critical') {
      themeClass = 'severity-critical';
      progressColor = 'var(--severity-critical)';
    } else if (data.severity === 'High') {
      themeClass = 'severity-high';
      progressColor = 'var(--severity-high)';
    } else if (data.severity === 'Medium') {
      themeClass = 'severity-medium';
      progressColor = 'var(--severity-medium)';
    } else if (data.severity === 'Low') {
      themeClass = 'severity-low';
      progressColor = 'var(--severity-low)';
    }

    verdictBadge.classList.add(themeClass);
    scoreCircle.style.stroke = progressColor;

    // 3. Update Mini Statistics Card Data
    linkCount.textContent = data.links.length;
    attachmentCount.textContent = data.attachments.length;
    indicatorCountBadge.textContent = `${data.indicators.length} Threat Flags`;

    // 4. Update Live Threat Intelligence Card
    updateThreatIntel(data.intel);

    // 5. Populate Threat Indicators
    populateIndicators(data.indicators);

    // 6. Populate MITRE & OWASP Framework Mappings
    populateFrameworks(data.mitreMapping, data.owaspMapping);

    // 7. Populate Headers Table
    allHeaders = data.headers;
    filterAndRenderHeaders('');

    // 8. Populate Extracted Links & Attachments
    populateArtifacts(data.links, data.attachments);

    // Re-initialize Lucide Icons for dynamic content
    lucide.createIcons();
  }

  function animateScoreDial(score) {
    let currentScore = 0;
    const duration = 800; // ms
    const stepTime = 15;
    const steps = duration / stepTime;
    const increment = score / steps;
    
    const interval = setInterval(() => {
      currentScore += increment;
      if (currentScore >= score) {
        currentScore = score;
        clearInterval(interval);
      }
      
      scoreVal.textContent = Math.round(currentScore);
      
      // Calculate offset
      const offset = circumference - (currentScore / 100) * circumference;
      scoreCircle.style.strokeDashoffset = offset;
    }, stepTime);
  }

  function updateThreatIntel(intel) {
    if (!intel) return;

    // IP Geolocation info
    intelIP.textContent = intel.senderIP || 'Not Extracted';
    if (intel.ipLocation) {
      const loc = intel.ipLocation;
      intelGeo.textContent = `${loc.city}, ${loc.country}`;
      intelISP.textContent = `${loc.isp}`;
      intelISP.title = `${loc.org} // ${loc.as}`;
    } else {
      intelGeo.textContent = 'Geolocation Unavailable';
      intelISP.textContent = 'Private / LAN Routing Address';
    }

    // DNS Records Info
    if (intel.dnsStatus) {
      if (intel.dnsStatus.mxVerified) {
        dnsMxBadge.textContent = 'VERIFIED';
        dnsMxBadge.className = 'auth-badge pass';
      } else {
        dnsMxBadge.textContent = 'MISSING / FAIL';
        dnsMxBadge.className = 'auth-badge fail';
      }

      dnsSpfRecord.textContent = intel.dnsStatus.spfRecord 
        ? `SPF: ${intel.dnsStatus.spfRecord}` 
        : 'SPF: No SPF TXT Record Found';
      dnsSpfRecord.title = dnsSpfRecord.textContent;
    }

    // VirusTotal Reputation Info
    if (intel.virusTotal) {
      const vt = intel.virusTotal;
      vtRepContent.innerHTML = `
        <div class="vt-grid">
          <div class="vt-stat" style="color: ${vt.malicious > 0 ? 'var(--severity-critical)' : 'var(--text-secondary)'};">
            Malicious: <strong>${vt.malicious}</strong>
          </div>
          <div class="vt-stat" style="color: ${vt.suspicious > 0 ? 'var(--severity-medium)' : 'var(--text-secondary)'};">
            Suspicious: <strong>${vt.suspicious}</strong>
          </div>
          <div class="vt-stat" style="color: var(--severity-safe);">
            Clean: <strong>${vt.harmless}</strong>
          </div>
          <div class="vt-stat" style="color: var(--text-muted);">
            Unrated: <strong>${vt.undetected}</strong>
          </div>
        </div>
        <div class="intel-sub" style="margin-top: 4px; font-size: 0.65rem; text-transform: uppercase;">
          ${vt.source}
        </div>
      `;
    } else {
      vtRepContent.innerHTML = `
        <span class="intel-val">Unconfigured</span>
        <span class="intel-label">Credentials key not set</span>
      `;
    }
  }

  function populateIndicators(indicators) {
    indicatorList.innerHTML = '';
    
    if (indicators.length === 0) {
      indicatorList.innerHTML = `
        <div class="empty-list-notice">
          <i data-lucide="check-circle" style="color: var(--severity-safe);"></i>
          <span>No critical phishing indicators detected. The email structure conforms to regular business patterns.</span>
        </div>`;
      return;
    }

    indicators.forEach(ind => {
      const item = document.createElement('div');
      
      let severityClass = 'severity-medium';
      let icon = 'alert-circle';
      if (ind.severity === 'critical') {
        severityClass = 'severity-critical';
        icon = 'shield-alert';
      } else if (ind.severity === 'high') {
        severityClass = 'severity-high';
        icon = 'alert-triangle';
      } else if (ind.severity === 'low') {
        severityClass = 'severity-low';
        icon = 'info';
      }

      item.className = `indicator-item ${severityClass}`;
      item.innerHTML = `
        <div class="indicator-icon-box">
          <i data-lucide="${icon}"></i>
        </div>
        <div class="indicator-body">
          <div class="indicator-title">${ind.title}</div>
          <div class="indicator-desc">${ind.description}</div>
        </div>
      `;
      
      indicatorList.appendChild(item);
    });
  }

  function populateFrameworks(mitre, owasp) {
    mitreList.innerHTML = '';
    owaspList.innerHTML = '';

    // MITRE ATT&CK
    if (mitre.length === 0) {
      mitreList.innerHTML = `<div class="empty-list-notice">No adversary behavior mapping found.</div>`;
    } else {
      mitre.forEach(tech => {
        const item = document.createElement('div');
        item.className = 'framework-card';
        
        let subHtml = '';
        if (tech.subtechniques && tech.subtechniques.length > 0) {
          subHtml = `
            <div class="subtechniques-list">
              ${tech.subtechniques.map(sub => `
                <div class="subtechnique-item">
                  <span class="sub-id">${sub.id}</span>
                  <span class="sub-name">${sub.name}</span>
                </div>
              `).join('')}
            </div>
          `;
        }

        item.innerHTML = `
          <span class="framework-id">${tech.id}</span>
          <div class="framework-name">${tech.technique}</div>
          <div class="framework-desc">${tech.description}</div>
          ${subHtml}
        `;
        mitreList.appendChild(item);
      });
    }

    // OWASP Top 10
    if (owasp.length === 0) {
      owaspList.innerHTML = `<div class="empty-list-notice">No OWASP vulnerability mapping found.</div>`;
    } else {
      owasp.forEach(vuln => {
        const item = document.createElement('div');
        item.className = 'framework-card';
        item.innerHTML = `
          <span class="framework-id" style="color: var(--accent-blue); background: rgba(79, 172, 254, 0.05); border-color: rgba(79, 172, 254, 0.15);">${vuln.id}</span>
          <div class="framework-name">${vuln.name}</div>
          <div class="framework-desc">${vuln.desc}</div>
        `;
        owaspList.appendChild(item);
      });
    }
  }

  function filterAndRenderHeaders(filterText) {
    headerTableBody.innerHTML = '';
    
    const filtered = allHeaders.filter(h => 
      h.key.toLowerCase().includes(filterText.toLowerCase()) || 
      h.value.toLowerCase().includes(filterText.toLowerCase())
    );

    if (filtered.length === 0) {
      headerTableBody.innerHTML = `<tr><td colspan="2" style="text-align: center; color: var(--text-muted);">No headers match search filter.</td></tr>`;
      return;
    }

    filtered.forEach(h => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${escapeHtml(h.key)}</td>
        <td>${escapeHtml(h.value)}</td>
      `;
      headerTableBody.appendChild(row);
    });
  }

  // Artifact URL and Attachment tables
  function populateArtifacts(links, attachments) {
    urlList.innerHTML = '';
    attachmentList.innerHTML = '';

    // Links Rendering
    if (links.length === 0) {
      urlList.innerHTML = `<div class="empty-list-notice">No URLs found in the email content.</div>`;
    } else {
      links.forEach(l => {
        const item = document.createElement('div');
        item.className = `artifact-item ${l.isSuspicious ? 'suspicious' : ''}`;
        
        let badgeHtml = `<span class="artifact-badge safe">SAFE / SUSPICION FREE</span>`;
        let threatBullets = '';

        if (l.isSuspicious) {
          badgeHtml = `<span class="artifact-badge warning">SUSPICIOUS URL</span>`;
          threatBullets = `
            <ul class="threat-bullets">
              ${l.threats.map(t => `<li>${escapeHtml(t)}</li>`).join('')}
            </ul>
          `;
        }

        item.innerHTML = `
          <div class="artifact-info">
            <i data-lucide="${l.isSuspicious ? 'alert-triangle' : 'link'}" style="color: ${l.isSuspicious ? 'var(--severity-critical)' : 'var(--accent-blue)'};"></i>
            <div class="artifact-meta">
              <span class="artifact-title">${escapeHtml(l.url)}</span>
              <span class="artifact-subtitle">Host: ${escapeHtml(l.host)}</span>
            </div>
          </div>
          ${badgeHtml}
          ${threatBullets}
        `;
        urlList.appendChild(item);
      });
    }

    // Attachments Rendering
    if (attachments.length === 0) {
      attachmentList.innerHTML = `<div class="empty-list-notice">No attachments present in the email structure.</div>`;
    } else {
      attachments.forEach(att => {
        const item = document.createElement('div');
        item.className = `artifact-item ${att.isSuspicious ? 'suspicious' : ''}`;
        
        let badgeHtml = `<span class="artifact-badge safe">PASSED EXTENSION CHECK</span>`;
        let threatBullets = '';
        const displaySize = (att.size / 1024).toFixed(1) + ' KB';

        if (att.isSuspicious) {
          badgeHtml = `<span class="artifact-badge warning">HIGH RISK ATTACHMENT</span>`;
          threatBullets = `
            <ul class="threat-bullets">
              ${att.threats.map(t => `<li>${escapeHtml(t)}</li>`).join('')}
            </ul>
          `;
        }

        item.innerHTML = `
          <div class="artifact-info">
            <i data-lucide="${att.isSuspicious ? 'file-warning' : 'file-text'}" style="color: ${att.isSuspicious ? 'var(--severity-critical)' : 'var(--severity-medium)'};"></i>
            <div class="artifact-meta">
              <span class="artifact-title">${escapeHtml(att.filename)}</span>
              <span class="artifact-subtitle">Size: ${displaySize} // MIME: ${escapeHtml(att.contentType)}</span>
            </div>
          </div>
          ${badgeHtml}
          ${threatBullets}
        `;
        attachmentList.appendChild(item);
      });
    }
  }

  // -------------------------------------------------------------
  // 6. Utility / UI Helpers
  // -------------------------------------------------------------
  function showLoading() {
    emptyStatePanel.style.display = 'none';
    resultsPanel.style.display = 'none';
    
    let loadingCard = document.getElementById('dashboardLoadingSpinner');
    if (!loadingCard) {
      loadingCard = document.createElement('div');
      loadingCard.id = 'dashboardLoadingSpinner';
      loadingCard.className = 'glass-card empty-card';
      loadingCard.style.margin = '100px auto';
      loadingCard.style.maxWidth = '400px';
      loadingCard.innerHTML = `
        <i data-lucide="loader" class="empty-icon animate-spin" style="color: var(--accent-cyan);"></i>
        <h1>Running Threat Intelligence</h1>
        <p style="color: var(--text-muted);">Parsing RFC 822 source, resolving MX/SPF DNS records, geolocating origin IPs, and querying live threat indicators...</p>
      `;
      resultsPanel.parentNode.appendChild(loadingCard);
      lucide.createIcons();
    }
    loadingCard.style.display = 'flex';
  }

  function hideLoading() {
    const loadingCard = document.getElementById('dashboardLoadingSpinner');
    if (loadingCard) {
      loadingCard.style.display = 'none';
    }
  }

  function resetToEmptyState() {
    hideLoading();
    emptyStatePanel.style.display = 'flex';
    resultsPanel.style.display = 'none';
    fileInfo.style.display = 'none';
    dropZone.classList.remove('hidden');
    emailFileInput.value = '';
    document.querySelectorAll('.preset-item, .stream-item').forEach(el => el.classList.remove('active'));
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;');
  }

  // -------------------------------------------------------------
  // 7. Setup Interactive Event Listeners
  // -------------------------------------------------------------
  
  // Drag and Drop File Handlers
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      analyzeFile(files[0]);
    }
  });

  emailFileInput.addEventListener('change', () => {
    if (emailFileInput.files.length > 0) {
      analyzeFile(emailFileInput.files[0]);
    }
  });

  function analyzeFile(file) {
    if (!file.name.endsWith('.eml')) {
      alert('Invalid file format. Please drop a raw RFC 822 email file (.eml).');
      return;
    }
    uploadAndAnalyzeFile(file);
  }

  // Clear File button
  btnClearFile.addEventListener('click', () => {
    resetToEmptyState();
  });

  // Navigation Tab switching logic
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(btn.dataset.tab);
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
  });

  // Header Real-time Search Box
  headerSearch.addEventListener('input', (e) => {
    filterAndRenderHeaders(e.target.value);
  });

  // Add styles to animate loading spinner spin
  const styleEl = document.createElement('style');
  styleEl.innerHTML = `
    .animate-spin {
      animation: spin 1.5s linear infinite;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .hidden {
      display: none !important;
    }
    .empty-list-notice {
      display: flex;
      align-items: center;
      gap: 12px;
      color: var(--text-muted);
      font-size: 0.85rem;
      background: rgba(255,255,255,0.01);
      border: 1px dashed var(--border-light);
      border-radius: 8px;
      padding: 20px;
    }
    .empty-list-notice i {
      width: 20px;
      height: 20px;
    }
    .error-msg {
      color: var(--severity-critical);
      font-size: 0.8rem;
      padding: 10px;
    }
  `;
  document.head.appendChild(styleEl);

  // -------------------------------------------------------------
  // 5. Live IMAP Mailbox Scanner Integration
  // -------------------------------------------------------------
  const providerBtns = document.querySelectorAll('.provider-btn');
  const imapEmailInput = document.getElementById('imapEmail');
  const imapPassInput = document.getElementById('imapPass');
  const btnTogglePwd = document.getElementById('btnTogglePwd');
  const pwdEyeIcon = document.getElementById('pwdEyeIcon');
  const btnAppPassHelp = document.getElementById('btnAppPassHelp');
  const appPassHelpBox = document.getElementById('appPassHelpBox');
  const helpContentGmail = document.getElementById('helpContentGmail');
  const helpContentOutlook = document.getElementById('helpContentOutlook');
  const helpContentYahoo = document.getElementById('helpContentYahoo');
  const advancedImapSettings = document.getElementById('advancedImapSettings');
  const imapHostInput = document.getElementById('imapHost');
  const imapPortInput = document.getElementById('imapPort');
  const imapSecureInput = document.getElementById('imapSecure');
  const btnConnectImap = document.getElementById('btnConnectImap');
  const imapBtnText = document.getElementById('imapBtnText');
  const imapSubActions = document.getElementById('imapSubActions');
  const btnSyncRecent = document.getElementById('btnSyncRecent');
  const btnDisconnectImap = document.getElementById('btnDisconnectImap');
  const imapStatusBanner = document.getElementById('imapStatusBanner');
  const imapStatusText = document.getElementById('imapStatusText');
  const imapStatusDot = document.getElementById('imapStatusDot');

  let selectedProvider = 'gmail';

  const providerConfigs = {
    gmail: { host: 'imap.gmail.com', port: 993, secure: true, placeholder: 'user@gmail.com' },
    outlook: { host: 'outlook.office365.com', port: 993, secure: true, placeholder: 'user@outlook.com' },
    yahoo: { host: 'imap.mail.yahoo.com', port: 993, secure: true, placeholder: 'user@yahoo.com' },
    custom: { host: '', port: 993, secure: true, placeholder: 'user@yourdomain.com' }
  };

  // Provider Selection Handler
  providerBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      providerBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      selectedProvider = btn.dataset.provider;

      const conf = providerConfigs[selectedProvider];
      imapEmailInput.placeholder = conf.placeholder;

      if (selectedProvider === 'custom') {
        advancedImapSettings.style.display = 'block';
        imapHostInput.value = '';
        imapPortInput.value = '993';
        imapSecureInput.checked = true;
      } else {
        advancedImapSettings.style.display = 'none';
        imapHostInput.value = conf.host;
        imapPortInput.value = conf.port;
        imapSecureInput.checked = conf.secure;
      }

      // Update Help Box display based on provider
      helpContentGmail.style.display = selectedProvider === 'gmail' ? 'block' : 'none';
      helpContentOutlook.style.display = selectedProvider === 'outlook' ? 'block' : 'none';
      helpContentYahoo.style.display = selectedProvider === 'yahoo' ? 'block' : 'none';
    });
  });

  // Toggle Password Visibility
  if (btnTogglePwd) {
    btnTogglePwd.addEventListener('click', () => {
      const isPassword = imapPassInput.type === 'password';
      imapPassInput.type = isPassword ? 'text' : 'password';
      if (pwdEyeIcon) {
        pwdEyeIcon.setAttribute('data-lucide', isPassword ? 'eye-off' : 'eye');
        lucide.createIcons();
      }
    });
  }

  // Toggle App Password Help Box
  if (btnAppPassHelp) {
    btnAppPassHelp.addEventListener('click', (e) => {
      e.preventDefault();
      const isHidden = appPassHelpBox.style.display === 'none';
      appPassHelpBox.style.display = isHidden ? 'block' : 'none';
    });
  }

  // Check IMAP Connection Status
  async function checkImapStatus() {
    try {
      const res = await fetch('/api/imap/status');
      const data = await res.json();
      updateImapUI(data);
    } catch (err) {
      console.error('Error fetching IMAP status:', err);
    }
  }

  function updateImapUI(status) {
    if (status.connected) {
      imapStatusBanner.className = 'imap-status-banner connected';
      imapStatusText.innerHTML = `<strong>● Online:</strong> ${status.user} (Watching ${status.mailbox})`;
      imapStatusDot.className = 'status-dot active';

      btnConnectImap.style.display = 'none';
      imapSubActions.style.display = 'grid';
      imapEmailInput.disabled = true;
      imapPassInput.disabled = true;
    } else {
      imapStatusBanner.className = 'imap-status-banner';
      if (status.error) {
        imapStatusBanner.className = 'imap-status-banner error';
        imapStatusText.textContent = `Error: ${status.error}`;
        imapStatusDot.className = 'status-dot error';
      } else {
        imapStatusText.textContent = 'Status: Disconnected';
        imapStatusDot.className = 'status-dot';
      }

      btnConnectImap.style.display = 'flex';
      btnConnectImap.disabled = false;
      imapBtnText.textContent = 'Connect & Start Live Monitoring';
      imapSubActions.style.display = 'none';
      imapEmailInput.disabled = false;
      imapPassInput.disabled = false;
    }
  }

  // Connect IMAP
  if (btnConnectImap) {
    btnConnectImap.addEventListener('click', async () => {
      const email = imapEmailInput.value.trim();
      const pass = imapPassInput.value.trim();
      const host = imapHostInput.value.trim() || providerConfigs[selectedProvider].host;
      const port = parseInt(imapPortInput.value, 10) || 993;
      const secure = imapSecureInput.checked;

      if (!email || !pass) {
        alert('Please provide both your email address and App Password.');
        return;
      }

      btnConnectImap.disabled = true;
      imapBtnText.textContent = 'Authenticating & Connecting...';
      imapStatusBanner.className = 'imap-status-banner connecting';
      imapStatusText.textContent = 'Connecting to IMAP server...';
      imapStatusDot.className = 'status-dot connecting';

      try {
        const res = await fetch('/api/imap/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host, port, secure, user: email, pass, mailbox: 'INBOX' })
        });

        const data = await res.json();
        if (res.ok && data.success) {
          updateImapUI(data.status);
          // Auto-trigger scanning recent emails right upon connection
          await syncRecentEmails(5, true);
        } else {
          throw new Error(data.error || 'Connection failed');
        }
      } catch (err) {
        alert('IMAP Connection Failed: ' + err.message);
        updateImapUI({ connected: false, error: err.message });
      }
    });
  }

  // Disconnect IMAP
  if (btnDisconnectImap) {
    btnDisconnectImap.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/imap/disconnect', { method: 'POST' });
        const data = await res.json();
        updateImapUI(data.status);
      } catch (err) {
        alert('Error disconnecting: ' + err.message);
      }
    });
  }

  // Unified Sync Recent Emails function
  async function syncRecentEmails(count = 5, silent = false) {
    if (btnSyncRecent) {
      btnSyncRecent.disabled = true;
      btnSyncRecent.innerHTML = `<i data-lucide="loader-2" class="animate-spin"></i> Scanning...`;
      lucide.createIcons();
    }

    try {
      const res = await fetch('/api/imap/sync-recent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count })
      });

      const data = await res.json();
      if (res.ok) {
        if (data.results && data.results.length > 0) {
          // Update stream emails
          data.results.forEach(analysis => {
            const exists = streamEmails.some(e => e.id === analysis.id);
            if (!exists) streamEmails.unshift(analysis);
          });
          renderSMTPStream();
          displayAnalysisResults(data.results[data.results.length - 1]);
          highlightActiveStreamItem(0);
          if (!silent) {
            alert(`Analyzed ${data.results.length} recent email(s) from your inbox!`);
          }
        } else if (!silent) {
          alert('Mailbox is empty or no recent messages found.');
        }
      } else {
        throw new Error(data.error || 'Sync failed');
      }
    } catch (err) {
      if (!silent) {
        alert('Failed to scan recent emails: ' + err.message);
      }
    } finally {
      if (btnSyncRecent) {
        btnSyncRecent.disabled = false;
        btnSyncRecent.innerHTML = `<i data-lucide="refresh-cw"></i> Scan Last 5 Emails`;
        lucide.createIcons();
      }
    }
  }

  // Sync Recent Emails Button
  if (btnSyncRecent) {
    btnSyncRecent.addEventListener('click', () => {
      syncRecentEmails(5, false);
    });
  }

  // Initialize
  checkSettingsStatus();
  checkImapStatus();
  connectSMTPStream();
});


