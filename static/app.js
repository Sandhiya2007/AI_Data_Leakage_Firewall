/**
 * AI Data Leakage Firewall — Frontend Application Logic
 * Member 4: Web Interface and Dashboard
 * IBM Z / LinuxONE Datathon Edition
 *
 * Implements:
 * 1. Live backend connection monitoring
 * 2. Secure prompt submission with role selection
 * 3. Verified security decision rendering (ALLOW, MASK, BLOCK)
 * 4. Risk assessment & sensitive data detection visualization
 * 5. Dynamic audit trail with summary counters
 * 6. Defensive response parsing and safe DOM handling (zero unsafe innerHTML)
 */

(function () {
  'use strict';

  // =========================================================================
  // 1. Centralized API Configuration & State
  // =========================================================================
  const CONFIG = {
    ENDPOINTS: {
      QUERY: '/api/query',
      AUDIT: '/api/audit'
    },
    TIMEOUT_MS: 15000,
    MAX_AUDIT_ROWS_DISPLAY: 25,
    BANNER_AUTO_DISMISS_MS: 6000
  };

  const STATE = {
    isSubmitting: false,
    isConnected: false,
    lastAuditRecords: []
  };

  // =========================================================================
  // 2. DOM Element Selectors
  // =========================================================================
  const DOM = {
    // Top Navigation & Connection
    connectionStatus: document.getElementById('connectionStatus'),
    connectionText: document.getElementById('connectionText'),
    refreshDashboardBtn: document.getElementById('refreshDashboardBtn'),

    // Feedback Notification Banner
    feedbackBanner: document.getElementById('feedbackBanner'),
    feedbackIcon: document.getElementById('feedbackIcon'),
    feedbackMessage: document.getElementById('feedbackMessage'),
    feedbackDismissBtn: document.getElementById('feedbackDismissBtn'),

    // Summary Statistics
    statTotalRequests: document.getElementById('statTotalRequests'),
    statAllowedRequests: document.getElementById('statAllowedRequests'),
    statMaskedRequests: document.getElementById('statMaskedRequests'),
    statBlockedRequests: document.getElementById('statBlockedRequests'),

    // Prompt Form
    promptForm: document.getElementById('promptForm'),
    roleSelector: document.getElementById('roleSelector'),
    promptInput: document.getElementById('promptInput'),
    charCounter: document.getElementById('charCounter'),
    promptError: document.getElementById('promptError'),
    clearPromptBtn: document.getElementById('clearPromptBtn'),
    submitPromptBtn: document.getElementById('submitPromptBtn'),
    submitBtnText: document.getElementById('submitBtnText'),
    submitBtnSpinner: document.querySelector('.btn-spinner'),
    presetButtons: document.querySelectorAll('.btn-preset'),

    // Security Decision Panel
    decisionBadgeContainer: document.getElementById('decisionBadgeContainer'),
    decisionEmptyState: document.getElementById('decisionEmptyState'),
    decisionResultContent: document.getElementById('decisionResultContent'),
    decisionBanner: document.getElementById('decisionBanner'),
    decisionBannerIcon: document.getElementById('decisionBannerIcon'),
    decisionHeadline: document.getElementById('decisionHeadline'),
    decisionReasonText: document.getElementById('decisionReasonText'),
    responseOutput: document.getElementById('responseOutput'),
    responseStatusTag: document.getElementById('responseStatusTag'),

    // Decision Metadata Breakdown
    metaRole: document.getElementById('metaRole'),
    metaClientLatency: document.getElementById('metaClientLatency'),
    metaProcessingTime: document.getElementById('metaProcessingTime'),
    metaTimestamp: document.getElementById('metaTimestamp'),

    // Risk Assessment
    riskScoreNumber: document.getElementById('riskScoreNumber'),
    riskLevelBadge: document.getElementById('riskLevelBadge'),
    riskProgressBarContainer: document.getElementById('riskProgressBarContainer'),
    riskProgressBar: document.getElementById('riskProgressBar'),
    riskExplanation: document.getElementById('riskExplanation'),

    // Sensitive Data Detection
    detectionChipsList: document.getElementById('detectionChipsList'),
    detectionCountBadge: document.getElementById('detectionCountBadge'),

    // Audit Trail Table
    refreshAuditBtn: document.getElementById('refreshAuditBtn'),
    auditCounterBadge: document.getElementById('auditCounterBadge'),
    auditTableBody: document.getElementById('auditTableBody')
  };

  let bannerTimer = null;

  // =========================================================================
  // 3. Application Initialization
  // =========================================================================
  document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
    updateCharCounter();
    checkBackendHealthAndLoad();
  });

  function initEventListeners() {
    // Form submission
    if (DOM.promptForm) {
      DOM.promptForm.addEventListener('submit', handlePromptSubmit);
    }

    // Clear button
    if (DOM.clearPromptBtn) {
      DOM.clearPromptBtn.addEventListener('click', () => {
        DOM.promptInput.value = '';
        clearPromptError();
        updateCharCounter();
        DOM.promptInput.focus();
      });
    }

    // Textarea input event for char counter & error clear
    if (DOM.promptInput) {
      DOM.promptInput.addEventListener('input', () => {
        clearPromptError();
        updateCharCounter();
      });
    }

    // Datathon Preset Scenario Buttons
    if (DOM.presetButtons && DOM.presetButtons.length > 0) {
      DOM.presetButtons.forEach((btn) => {
        btn.addEventListener('click', () => {
          const role = btn.getAttribute('data-role');
          const prompt = btn.getAttribute('data-prompt');

          if (role && DOM.roleSelector) {
            DOM.roleSelector.value = role;
          }
          if (prompt && DOM.promptInput) {
            DOM.promptInput.value = prompt;
            clearPromptError();
            updateCharCounter();
            DOM.promptInput.focus();
          }
        });
      });
    }

    // Refresh buttons
    if (DOM.refreshDashboardBtn) {
      DOM.refreshDashboardBtn.addEventListener('click', () => {
        checkBackendHealthAndLoad(true);
      });
    }

    if (DOM.refreshAuditBtn) {
      DOM.refreshAuditBtn.addEventListener('click', () => {
        fetchAuditRecords(true);
      });
    }

    // Feedback banner dismiss
    if (DOM.feedbackDismissBtn) {
      DOM.feedbackDismissBtn.addEventListener('click', hideFeedbackBanner);
    }
  }

  // =========================================================================
  // 4. Connection Status & Backend Health
  // =========================================================================
  function setConnectionStatus(status, text) {
    DOM.connectionStatus.classList.remove('status-connected', 'status-connecting', 'status-offline');

    if (status === 'connected') {
      DOM.connectionStatus.classList.add('status-connected');
      DOM.connectionText.textContent = text || 'Connected';
      STATE.isConnected = true;
    } else if (status === 'offline') {
      DOM.connectionStatus.classList.add('status-offline');
      DOM.connectionText.textContent = text || 'Offline';
      STATE.isConnected = false;
    } else {
      DOM.connectionStatus.classList.add('status-connecting');
      DOM.connectionText.textContent = text || 'Connecting...';
    }
  }

  async function checkBackendHealthAndLoad(showUserNotice = false) {
    setConnectionStatus('connecting', 'Connecting...');

    try {
      // We ping the audit endpoint to verify Flask is actively serving API requests
      await fetchAuditRecords(false);
      setConnectionStatus('connected', 'Connected');
      if (showUserNotice) {
        showFeedback('Connected to IBM Z Firewall Backend. All metrics synchronized.', 'success');
      }
    } catch (err) {
      setConnectionStatus('offline', 'Offline');
      renderAuditErrorState('Unable to reach backend at ' + CONFIG.ENDPOINTS.AUDIT + '. Please verify the Flask server is running.');
      if (showUserNotice) {
        showFeedback('Backend offline: Unable to reach ' + CONFIG.ENDPOINTS.AUDIT, 'danger');
      }
    }
  }

  // =========================================================================
  // 5. Prompt Submission Handler
  // =========================================================================
  async function handlePromptSubmit(event) {
    event.preventDefault();

    if (STATE.isSubmitting) return;

    const promptText = DOM.promptInput.value.trim();
    const selectedRole = DOM.roleSelector.value;

    // Frontend validation
    if (!promptText) {
      showPromptError('Please enter a prompt before submitting.');
      DOM.promptInput.focus();
      return;
    }

    clearPromptError();
    setSubmittingState(true);

    const startTime = performance.now();
    const clientLatencyLabel = 'Measuring...';
    DOM.metaClientLatency.textContent = clientLatencyLabel;

    try {
      const response = await fetchWithTimeout(CONFIG.ENDPOINTS.QUERY, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          role: selectedRole,
          prompt: promptText
        })
      }, CONFIG.TIMEOUT_MS);

      const endTime = performance.now();
      const elapsedMs = Math.round(endTime - startTime);

      // Backend returned non-2xx status
      if (!response.ok) {
        let errorData = null;
        try {
          errorData = await response.json();
        } catch (_) {}

        const errorMsg = (errorData && (errorData.message || errorData.error || errorData.reason)) 
          ? (errorData.message || errorData.error || errorData.reason)
          : `HTTP ${response.status} ${response.statusText}`;

        handleQueryFailure(errorMsg, selectedRole, elapsedMs);
        setConnectionStatus('connected', 'Connected');
        return;
      }

      let data;
      try {
        data = await response.json();
      } catch (jsonErr) {
        throw new Error('Received invalid JSON response from firewall backend.');
      }

      // Backend succeeded — update connection & render response
      setConnectionStatus('connected', 'Connected');
      renderSecurityDecision(data, selectedRole, elapsedMs);

      // Refresh audit logs to capture the newly logged event and update counters
      fetchAuditRecords(false);

    } catch (err) {
      const endTime = performance.now();
      const elapsedMs = Math.round(endTime - startTime);
      setConnectionStatus('offline', 'Offline');
      handleQueryFailure(err.message || 'Network connection failed.', selectedRole, elapsedMs);
    } finally {
      setSubmittingState(false);
    }
  }

  // =========================================================================
  // 6. Security Decision Rendering (ALLOW, MASK, BLOCK)
  // =========================================================================
  function renderSecurityDecision(payload, role, clientLatencyMs) {
    if (!payload || typeof payload !== 'object') {
      handleQueryFailure('Malformed payload received from firewall.', role, clientLatencyMs);
      return;
    }

    // Defensive field extraction
    const rawDecision = (payload.decision || payload.verdict || payload.status || 'UNKNOWN').toString().toUpperCase().trim();
    const responseBody = payload.response !== undefined 
      ? payload.response 
      : (payload.output !== undefined ? payload.output : (payload.message !== undefined ? payload.message : 'No response content returned.'));
    
    const reasonText = payload.reason || payload.decision_reason || payload.policy_reason || 'Evaluated against firewall policy rules.';
    const riskScore = payload.risk_score !== undefined ? payload.risk_score : payload.risk;
    const riskLevel = payload.risk_level || payload.severity;
    const detectedCategories = payload.detected_categories || payload.sensitive_categories || payload.sensitive_data_detected;
    const backendProcessing = payload.processing_time || payload.latency_ms || payload.duration;
    const timestamp = payload.timestamp || payload.created_at || new Date().toLocaleTimeString();

    // Reveal results panel & hide empty placeholder
    DOM.decisionEmptyState.hidden = true;
    DOM.decisionResultContent.hidden = false;

    // Reset Decision Banner Classes
    DOM.decisionBanner.classList.remove('banner-allow', 'banner-mask', 'banner-block');
    DOM.decisionHeadline.textContent = rawDecision;
    DOM.decisionReasonText.textContent = reasonText;

    // Configure Decision Banner & Badge
    if (rawDecision === 'ALLOW') {
      DOM.decisionBanner.classList.add('banner-allow');
      setDecisionBadge('ALLOW', 'badge-allow');
      setDecisionIcon('allow');
      DOM.responseStatusTag.textContent = 'Authorized';
      DOM.responseStatusTag.style.color = 'var(--color-allow)';
      showFeedback('Request permitted by security policy.', 'success');
    } else if (rawDecision === 'MASK') {
      DOM.decisionBanner.classList.add('banner-mask');
      setDecisionBadge('MASK', 'badge-mask');
      setDecisionIcon('mask');
      DOM.responseStatusTag.textContent = 'Sanitized (Redacted)';
      DOM.responseStatusTag.style.color = 'var(--color-mask)';
      showFeedback('Sensitive information masked before delivery.', 'warning');
    } else if (rawDecision === 'BLOCK') {
      DOM.decisionBanner.classList.add('banner-block');
      setDecisionBadge('BLOCK', 'badge-block');
      setDecisionIcon('block');
      DOM.responseStatusTag.textContent = 'Denied';
      DOM.responseStatusTag.style.color = 'var(--color-block)';
      showFeedback('Request blocked by security policy.', 'danger');
    } else {
      setDecisionBadge(rawDecision, 'badge-neutral');
      setDecisionIcon('neutral');
      DOM.responseStatusTag.textContent = 'Unverified Verdict';
      DOM.responseStatusTag.style.color = 'var(--text-secondary)';
      showFeedback(`Received security verdict: ${rawDecision}`, 'warning');
    }

    // Render Safe Response (Strictly textContent to prevent XSS / script injection)
    DOM.responseOutput.textContent = typeof responseBody === 'object' 
      ? JSON.stringify(responseBody, null, 2) 
      : String(responseBody);

    // Update Decision Metadata
    DOM.metaRole.textContent = role || 'Not provided';
    DOM.metaClientLatency.textContent = clientLatencyMs ? `${clientLatencyMs} ms (Client)` : '—';
    DOM.metaProcessingTime.textContent = backendProcessing ? `${backendProcessing}` : 'Not provided';
    DOM.metaTimestamp.textContent = timestamp ? String(timestamp) : 'Not provided';

    // Update Sub-Panels
    renderRiskAssessment(riskScore, riskLevel, reasonText);
    renderSensitiveCategories(detectedCategories);
  }

  function handleQueryFailure(errorMessage, role, clientLatencyMs) {
    DOM.decisionEmptyState.hidden = true;
    DOM.decisionResultContent.hidden = false;

    DOM.decisionBanner.classList.remove('banner-allow', 'banner-mask', 'banner-block');
    DOM.decisionBanner.classList.add('banner-block');
    DOM.decisionHeadline.textContent = 'ERROR / BLOCKED';
    DOM.decisionReasonText.textContent = 'Firewall query failed or was rejected: ' + errorMessage;

    setDecisionBadge('ERROR', 'badge-block');
    setDecisionIcon('block');

    DOM.responseStatusTag.textContent = 'Transmission Error';
    DOM.responseStatusTag.style.color = 'var(--color-block)';
    DOM.responseOutput.textContent = `[FIREWALL GATEWAY ERROR]\nUnable to complete secure evaluation.\nDetails: ${errorMessage}`;

    DOM.metaRole.textContent = role || '—';
    DOM.metaClientLatency.textContent = clientLatencyMs ? `${clientLatencyMs} ms (Client)` : '—';
    DOM.metaProcessingTime.textContent = 'N/A';
    DOM.metaTimestamp.textContent = new Date().toLocaleTimeString();

    renderRiskAssessment(null, null, 'Error state: risk not computable.');
    renderSensitiveCategories(null);

    showFeedback('Query could not be evaluated: ' + errorMessage, 'danger');
  }

  function setDecisionBadge(text, badgeClass) {
    DOM.decisionBadgeContainer.replaceChildren();
    const span = document.createElement('span');
    span.className = `decision-badge badge ${badgeClass}`;
    span.textContent = text;
    DOM.decisionBadgeContainer.appendChild(span);
  }

  function setDecisionIcon(type) {
    DOM.decisionBannerIcon.replaceChildren();
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '24');
    svg.setAttribute('height', '24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2.5');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');

    if (type === 'allow') {
      const polyline = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
      polyline.setAttribute('points', '20 6 9 17 4 12');
      svg.appendChild(polyline);
    } else if (type === 'mask') {
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '12');
      circle.setAttribute('cy', '12');
      circle.setAttribute('r', '10');
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', '4.93');
      line.setAttribute('y1', '4.93');
      line.setAttribute('x2', '19.07');
      line.setAttribute('y2', '19.07');
      svg.appendChild(circle);
      svg.appendChild(line);
    } else {
      const line1 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line1.setAttribute('x1', '18');
      line1.setAttribute('y1', '6');
      line1.setAttribute('x2', '6');
      line1.setAttribute('y2', '18');
      const line2 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line2.setAttribute('x1', '6');
      line2.setAttribute('y1', '6');
      line2.setAttribute('x2', '18');
      line2.setAttribute('y2', '18');
      svg.appendChild(line1);
      svg.appendChild(line2);
    }

    DOM.decisionBannerIcon.appendChild(svg);
  }

  // =========================================================================
  // 7. Risk Assessment Panel Rendering
  // =========================================================================
  function renderRiskAssessment(score, level, reasonText) {
    if (score === null || score === undefined || isNaN(Number(score))) {
      DOM.riskScoreNumber.textContent = '—';
      DOM.riskLevelBadge.textContent = level ? String(level) : 'Not provided';
      DOM.riskLevelBadge.className = 'badge badge-neutral';
      DOM.riskProgressBar.style.width = '0%';
      DOM.riskProgressBarContainer.setAttribute('aria-valuenow', '0');
      DOM.riskExplanation.textContent = 'Risk score was not supplied by the backend for this transaction.';
      return;
    }

    const numericScore = Math.min(Math.max(Number(score), 0), 100);
    DOM.riskScoreNumber.textContent = String(numericScore);
    DOM.riskProgressBar.style.width = `${numericScore}%`;
    DOM.riskProgressBarContainer.setAttribute('aria-valuenow', String(numericScore));

    // Determine badge display & styling
    DOM.riskLevelBadge.className = 'badge';
    if (level) {
      DOM.riskLevelBadge.textContent = String(level);
      const lvlUpper = String(level).toUpperCase();
      if (lvlUpper.includes('LOW')) {
        DOM.riskLevelBadge.classList.add('badge-allow');
      } else if (lvlUpper.includes('MED')) {
        DOM.riskLevelBadge.classList.add('badge-mask');
      } else {
        DOM.riskLevelBadge.classList.add('badge-block');
      }
    } else {
      // If backend only supplied numeric score, infer label respectfully
      if (numericScore < 30) {
        DOM.riskLevelBadge.textContent = 'Low Risk';
        DOM.riskLevelBadge.classList.add('badge-allow');
      } else if (numericScore < 70) {
        DOM.riskLevelBadge.textContent = 'Medium Risk';
        DOM.riskLevelBadge.classList.add('badge-mask');
      } else {
        DOM.riskLevelBadge.textContent = 'High Risk';
        DOM.riskLevelBadge.classList.add('badge-block');
      }
    }

    DOM.riskExplanation.textContent = reasonText || `Evaluated policy risk index at ${numericScore}/100.`;
  }

  // =========================================================================
  // 8. Sensitive Data Detection Panel Rendering
  // =========================================================================
  function renderSensitiveCategories(categories) {
    DOM.detectionChipsList.replaceChildren();

    if (categories === undefined || categories === null) {
      DOM.detectionCountBadge.textContent = 'Not provided';
      DOM.detectionCountBadge.className = 'badge badge-neutral';

      const chip = document.createElement('span');
      chip.className = 'chip chip-empty';
      chip.textContent = 'Category scan details not provided';
      DOM.detectionChipsList.appendChild(chip);
      return;
    }

    if (!Array.isArray(categories) || categories.length === 0) {
      DOM.detectionCountBadge.textContent = '0 detected';
      DOM.detectionCountBadge.className = 'badge badge-allow';

      const chip = document.createElement('span');
      chip.className = 'chip chip-empty';
      chip.textContent = 'No sensitive data categories detected';
      DOM.detectionChipsList.appendChild(chip);
      return;
    }

    DOM.detectionCountBadge.textContent = `${categories.length} detected`;
    DOM.detectionCountBadge.className = 'badge badge-mask';

    categories.forEach((cat) => {
      const chip = document.createElement('span');
      const catStr = String(cat).trim();
      const isSecret = /secret|credential|key|password|token/i.test(catStr);

      chip.className = `chip ${isSecret ? 'chip-secret' : 'chip-category'}`;
      chip.textContent = catStr;
      DOM.detectionChipsList.appendChild(chip);
    });
  }

  // =========================================================================
  // 9. Audit Trail Table & Summary Counters
  // =========================================================================
  async function fetchAuditRecords(showNotification = false) {
    try {
      const response = await fetchWithTimeout(CONFIG.ENDPOINTS.AUDIT, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      }, CONFIG.TIMEOUT_MS);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText}`);
      }

      const rawData = await response.json();
      
      // Defensive extraction for either bare array or wrapper object
      let records = [];
      if (Array.isArray(rawData)) {
        records = rawData;
      } else if (rawData && typeof rawData === 'object') {
        records = rawData.audit_logs || rawData.records || rawData.logs || rawData.data || [];
      }

      STATE.lastAuditRecords = records;
      renderAuditTable(records);
      updateSummaryMetrics(records);

      if (showNotification) {
        showFeedback(`Audit trail synchronized. ${records.length} records retrieved.`, 'success');
      }

      return records;
    } catch (err) {
      if (showNotification) {
        showFeedback(`Failed to refresh audit trail: ${err.message}`, 'danger');
      }
      throw err;
    }
  }

  function renderAuditTable(records) {
    DOM.auditTableBody.replaceChildren();

    if (!records || records.length === 0) {
      DOM.auditCounterBadge.textContent = '0 records';
      const emptyRow = document.createElement('tr');
      emptyRow.className = 'audit-row-empty';
      const cell = document.createElement('td');
      cell.colSpan = 6;
      cell.className = 'text-center py-4';
      cell.innerHTML = '<div class="table-empty-message">No audit records found on firewall backend.</div>';
      emptyRow.appendChild(cell);
      DOM.auditTableBody.appendChild(emptyRow);
      return;
    }

    DOM.auditCounterBadge.textContent = `${records.length} records`;

    // Limit display rows to avoid DOM overload
    const displayRecords = records.slice(0, CONFIG.MAX_AUDIT_ROWS_DISPLAY);

    displayRecords.forEach((entry) => {
      const tr = document.createElement('tr');

      // 1. Timestamp
      const tdTime = document.createElement('td');
      tdTime.className = 'cell-timestamp';
      tdTime.textContent = entry.timestamp || entry.created_at || entry.time || '—';
      tr.appendChild(tdTime);

      // 2. Role
      const tdRole = document.createElement('td');
      tdRole.className = 'cell-role';
      tdRole.textContent = entry.role || entry.user_role || 'Analyst';
      tr.appendChild(tdRole);

      // 3. Action / Request Type
      const tdAction = document.createElement('td');
      tdAction.className = 'cell-action';
      tdAction.textContent = entry.action || entry.request_type || entry.query_type || 'Query';
      tr.appendChild(tdAction);

      // 4. Decision Badge
      const tdDecision = document.createElement('td');
      const badge = document.createElement('span');
      const decStr = (entry.decision || entry.verdict || 'UNKNOWN').toString().toUpperCase().trim();
      badge.textContent = decStr;
      badge.className = 'badge';

      if (decStr === 'ALLOW') {
        badge.classList.add('badge-allow');
      } else if (decStr === 'MASK') {
        badge.classList.add('badge-mask');
      } else if (decStr === 'BLOCK') {
        badge.classList.add('badge-block');
      } else {
        badge.classList.add('badge-neutral');
      }

      tdDecision.appendChild(badge);
      tr.appendChild(tdDecision);

      // 5. Reason
      const tdReason = document.createElement('td');
      tdReason.className = 'cell-reason';
      tdReason.textContent = entry.reason || entry.decision_reason || '—';
      tr.appendChild(tdReason);

      // 6. Risk Score
      const tdRisk = document.createElement('td');
      tdRisk.className = 'cell-risk';
      const riskVal = entry.risk_score !== undefined ? entry.risk_score : entry.risk;
      if (riskVal !== undefined && riskVal !== null && !isNaN(Number(riskVal))) {
        tdRisk.textContent = `${Number(riskVal)} / 100`;
        if (Number(riskVal) >= 70) tdRisk.style.color = 'var(--color-block)';
        else if (Number(riskVal) >= 30) tdRisk.style.color = 'var(--color-mask)';
        else tdRisk.style.color = 'var(--color-allow)';
      } else {
        tdRisk.textContent = '—';
        tdRisk.style.color = 'var(--text-tertiary)';
      }
      tr.appendChild(tdRisk);

      DOM.auditTableBody.appendChild(tr);
    });
  }

  function renderAuditErrorState(errorMessage) {
    DOM.auditTableBody.replaceChildren();
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'text-center py-4';
    const div = document.createElement('div');
    div.className = 'table-error-message';
    div.textContent = errorMessage;
    td.appendChild(div);
    tr.appendChild(td);
    DOM.auditTableBody.appendChild(tr);

    DOM.statTotalRequests.textContent = '—';
    DOM.statAllowedRequests.textContent = '—';
    DOM.statMaskedRequests.textContent = '—';
    DOM.statBlockedRequests.textContent = '—';
    DOM.auditCounterBadge.textContent = 'Offline';
  }

  function updateSummaryMetrics(records) {
    if (!Array.isArray(records)) {
      DOM.statTotalRequests.textContent = '—';
      DOM.statAllowedRequests.textContent = '—';
      DOM.statMaskedRequests.textContent = '—';
      DOM.statBlockedRequests.textContent = '—';
      return;
    }

    let allowCount = 0;
    let maskCount = 0;
    let blockCount = 0;

    records.forEach((record) => {
      const dec = (record.decision || record.verdict || '').toString().toUpperCase().trim();
      if (dec === 'ALLOW') allowCount++;
      else if (dec === 'MASK') maskCount++;
      else if (dec === 'BLOCK') blockCount++;
    });

    DOM.statTotalRequests.textContent = String(records.length);
    DOM.statAllowedRequests.textContent = String(allowCount);
    DOM.statMaskedRequests.textContent = String(maskCount);
    DOM.statBlockedRequests.textContent = String(blockCount);
  }

  // =========================================================================
  // 10. Helper Functions & UI Utilities
  // =========================================================================
  function updateCharCounter() {
    const len = DOM.promptInput ? DOM.promptInput.value.length : 0;
    if (DOM.charCounter) {
      DOM.charCounter.textContent = `${len} / 1000`;
    }
  }

  function showPromptError(message) {
    if (DOM.promptError) {
      DOM.promptError.textContent = message;
      DOM.promptError.hidden = false;
    }
  }

  function clearPromptError() {
    if (DOM.promptError) {
      DOM.promptError.textContent = '';
      DOM.promptError.hidden = true;
    }
  }

  function setSubmittingState(isSubmitting) {
    STATE.isSubmitting = isSubmitting;
    DOM.submitPromptBtn.disabled = isSubmitting;

    if (isSubmitting) {
      DOM.submitBtnSpinner.hidden = false;
      DOM.submitBtnText.textContent = 'Evaluating Policy...';
    } else {
      DOM.submitBtnSpinner.hidden = true;
      DOM.submitBtnText.textContent = 'Submit to Firewall';
    }
  }

  function showFeedback(message, type = 'info') {
    if (bannerTimer) {
      clearTimeout(bannerTimer);
      bannerTimer = null;
    }

    DOM.feedbackBanner.classList.remove('banner-success', 'banner-warning', 'banner-danger');

    if (type === 'success') {
      DOM.feedbackBanner.classList.add('banner-success');
    } else if (type === 'warning') {
      DOM.feedbackBanner.classList.add('banner-warning');
    } else if (type === 'danger') {
      DOM.feedbackBanner.classList.add('banner-danger');
    }

    DOM.feedbackMessage.textContent = message;
    DOM.feedbackBanner.hidden = false;

    bannerTimer = setTimeout(() => {
      hideFeedbackBanner();
    }, CONFIG.BANNER_AUTO_DISMISS_MS);
  }

  function hideFeedbackBanner() {
    DOM.feedbackBanner.hidden = true;
    if (bannerTimer) {
      clearTimeout(bannerTimer);
      bannerTimer = null;
    }
  }

  async function fetchWithTimeout(resource, options = {}, timeoutMs = 15000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(resource, {
        ...options,
        signal: controller.signal
      });
      clearTimeout(id);
      return response;
    } catch (error) {
      clearTimeout(id);
      if (error.name === 'AbortError') {
        throw new Error(`Request timed out after ${Math.round(timeoutMs / 1000)} seconds.`);
      }
      throw error;
    }
  }

  // Expose configuration hook for testing or developer console overrides
  window.__AI_FIREWALL_DASHBOARD__ = {
    config: CONFIG,
    state: STATE,
    refreshAudit: fetchAuditRecords,
    checkHealth: checkBackendHealthAndLoad
  };

})();
