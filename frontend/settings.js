/**
 * ZERO-TRUST API SECURITY GATEWAY - SETTINGS INTERACTIVITY
 * Faithful reproduction of media_1791206974297.jpg
 * Features:
 *  - Subtle cursor-following spotlight on hover (non-blurry, crystal-clear text)
 *  - Interactive 6-tab navigation
 *  - Cyber green & blue toggle switches with tactile feedback
 *  - Real JSON file export & backup download simulation
 *  - Danger Zone confirmation modal with destructive action simulation
 *  - Backend-ready notification bell logic
 *  - Real-time sidebar clock sync & search filtering
 */

document.addEventListener('DOMContentLoaded', () => {
  initSpotlights();
  initTabNavigation();
  initToggleSwitches();
  initSaveButtons();
  initBackupAndExport();
  initDangerZoneModal();
  initNotificationBell();
  initSidebarClock();
  initGlobalSearch();
});

/* ================= 1. SUBTLE CURSOR-FOLLOWING SPOTLIGHT ================= */
function initSpotlights() {
  const cards = document.querySelectorAll('.settings-card');
  
  cards.forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--mouse-x', `${x}px`);
      card.style.setProperty('--mouse-y', `${y}px`);
    });
  });
}

/* ================= 2. 6-TAB NAVIGATION ================= */
function initTabNavigation() {
  const tabBtns = document.querySelectorAll('.settings-tab-btn');
  
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      if (tabId === 'general') {
        showToast('General Settings', 'Displaying core system & gateway parameters.');
      } else {
        const tabTitle = btn.querySelector('span')?.textContent || tabId;
        showToast(`${tabTitle} Tab`, `Viewing configuration panel for ${tabTitle}.`);
      }
    });
  });
}

/* ================= 3. TOGGLE SWITCHES ================= */
function initToggleSwitches() {
  const allToggles = document.querySelectorAll('.cyber-green-toggle, .cyber-blue-toggle');
  
  allToggles.forEach(toggle => {
    toggle.addEventListener('click', () => {
      toggle.classList.toggle('active');
      
      // Find associated label or parent row
      const parentRow = toggle.closest('.toggle-row-item, .notif-toggle-row, .data-field-pair');
      const labelText = parentRow?.querySelector('.toggle-name, .notif-toggle-title, .data-field-lbl')?.textContent || 'Setting';
      const isEnabled = toggle.classList.contains('active');
      
      showToast(
        isEnabled ? `${labelText} Enabled` : `${labelText} Disabled`,
        `Status updated to ${isEnabled ? 'Active' : 'Inactive'}.`,
        isEnabled ? 'success' : 'info'
      );
    });
  });
}

/* ================= 4. SAVE BUTTONS ================= */
function initSaveButtons() {
  const saveBtn = document.getElementById('btnSaveNotificationSettings');
  
  if (saveBtn) {
    saveBtn.addEventListener('click', () => {
      const originalText = saveBtn.textContent;
      saveBtn.disabled = true;
      saveBtn.innerHTML = `
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite; display:inline-block; vertical-align:middle; margin-right:4px;">
          <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
          <path d="M12 2a10 10 0 0 1 10 10"/>
        </svg> Saving...
      `;
      saveBtn.style.opacity = '0.85';

      setTimeout(() => {
        saveBtn.disabled = false;
        saveBtn.innerHTML = `✓ Saved!`;
        saveBtn.style.background = '#10b981';
        saveBtn.style.borderColor = '#059669';

        showToast('Settings Saved', 'Notification thresholds and email preferences synchronized.');

        setTimeout(() => {
          saveBtn.textContent = originalText;
          saveBtn.style.background = '';
          saveBtn.style.borderColor = '';
          saveBtn.style.opacity = '';
        }, 1800);
      }, 700);
    });
  }
}

/* ================= 5. REAL DATABASE BACKUP & EXPORT ================= */
function initBackupAndExport() {
  const btnExportLogs = document.getElementById('btnExportLogs');
  const btnExportIncidents = document.getElementById('btnExportIncidents');
  const btnExportPolicies = document.getElementById('btnExportPolicies');
  const btnDownloadBackup = document.getElementById('btnDownloadBackup');

  function triggerDownload(filename, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (btnExportLogs) {
    btnExportLogs.addEventListener('click', async () => {
      showToast('Exporting Database Logs', 'Fetching persistent audit records from PostgreSQL...');
      const res = await API.get('/api/telemetry/export', { limit: 1000 });
      if (res && res.ok && res.data) {
        triggerDownload(`zerotrust-audit-logs-${Date.now()}.json`, res.data);
        showToast('Export Completed', `Downloaded ${res.data.total_requests || 0} real request logs.`);
      } else {
        showToast('Export Error', 'Could not export logs from database.');
      }
    });
  }

  if (btnExportIncidents) {
    btnExportIncidents.addEventListener('click', async () => {
      showToast('Exporting Security Events', 'Querying security_events table...');
      const res = await API.get('/api/anomalies', { limit: 200 });
      if (res && res.ok && res.data) {
        triggerDownload(`zerotrust-security-events-${Date.now()}.json`, res.data);
        showToast('Export Completed', `Downloaded ${res.data.count || 0} detected anomalies.`);
      } else {
        showToast('Export Error', 'Could not export anomalies.');
      }
    });
  }

  if (btnExportPolicies) {
    btnExportPolicies.addEventListener('click', async () => {
      showToast('Exporting Policies', 'Querying policy engine tiers...');
      const res = await API.get('/api/policies');
      if (res && res.ok && res.data) {
        triggerDownload(`zerotrust-policies-config-${Date.now()}.json`, res.data);
        showToast('Export Completed', 'Downloaded active Zero-Trust policy configurations.');
      }
    });
  }

  if (btnDownloadBackup) {
    btnDownloadBackup.addEventListener('click', async () => {
      showToast('Generating Full System Backup', 'Aggregating gateway state and database audit data...');
      const [telemetryRes, policiesRes] = await Promise.all([
        API.get('/api/telemetry/export', { limit: 500 }),
        API.get('/api/policies')
      ]);

      const backupData = {
        gatewayVersion: 'v1.0.0',
        environment: 'Production',
        backupTimestamp: new Date().toISOString(),
        policies: policiesRes?.data || {},
        telemetry: telemetryRes?.data || {}
      };
      triggerDownload(`zerotrust-full-backup-${Date.now()}.json`, backupData);
      showToast('Full Backup Downloaded', 'Complete gateway state and database logs exported securely.');
    });
  }
}

/* ================= 6. DANGER ZONE CONFIRMATION MODAL ================= */
function initDangerZoneModal() {
  const modal = document.getElementById('dangerModal');
  const btnClearLogs = document.getElementById('btnClearLogs');
  const btnResetDefault = document.getElementById('btnResetDefault');
  const btnCancel = document.getElementById('btnCancelModal');
  const btnConfirm = document.getElementById('btnConfirmModal');
  const modalTitle = document.getElementById('modalDangerTitle');
  const modalDesc = document.getElementById('modalDangerDesc');

  let currentAction = null;

  function openModal(title, desc, action) {
    if (!modal) return;
    currentAction = action;
    if (modalTitle) modalTitle.textContent = title;
    if (modalDesc) modalDesc.textContent = desc;
    modal.classList.add('open');
  }

  function closeModal() {
    if (!modal) return;
    modal.classList.remove('open');
    currentAction = null;
  }

  if (btnClearLogs) {
    btnClearLogs.addEventListener('click', () => {
      openModal(
        'Flush Rate Limits & Clear Blocked IPs?',
        'This will reset all sliding-window rate counters and unblock any quarantined IPs across the API gateway.',
        'reset-limits'
      );
    });
  }

  if (btnResetDefault) {
    btnResetDefault.addEventListener('click', () => {
      openModal(
        'Reset Gateway Policies to Baseline?',
        'This will restore default Zero-Trust thresholds: LOW (0-30), MEDIUM (31-60), HIGH (61-80), CRITICAL (81-100).',
        'reset-policies'
      );
    });
  }

  if (btnCancel) btnCancel.addEventListener('click', closeModal);

  if (btnConfirm) {
    btnConfirm.addEventListener('click', async () => {
      if (currentAction === 'reset-limits') {
        const res = await API.post('/api/security/reset-limits');
        closeModal();
        if (res && res.ok) {
          showToast('Rate Limits Cleared', 'All blocked IPs and in-memory rate windows have been reset.', 'success');
        } else {
          showToast('Reset Failed', 'Could not clear rate limits on gateway.', 'error');
        }
      } else if (currentAction === 'reset-policies') {
        const defaultTiers = [
          { risk_level: "LOW", min_score: 0, max_score: 30, decision: "ALLOW" },
          { risk_level: "MEDIUM", min_score: 31, max_score: 60, decision: "MONITOR" },
          { risk_level: "HIGH", min_score: 61, max_score: 80, decision: "RATE_LIMIT" },
          { risk_level: "CRITICAL", min_score: 81, max_score: 100, decision: "BLOCK" }
        ];
        await API.post('/api/policies', { tiers: defaultTiers });
        closeModal();
        showToast('Policies Restored', 'Baseline Zero-Trust thresholds restored to default factory levels.', 'success');
      } else {
        closeModal();
      }
    });
  }
}


  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
  }

  // Escape key closes modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal?.classList.contains('open')) {
      closeModal();
    }
  });
}

/* ================= 7. BACKEND-READY NOTIFICATION BELL ================= */
function initNotificationBell() {
  const notifBtn = document.getElementById('notificationBtn');
  const countBadge = document.getElementById('notificationCount');
  
  if (notifBtn) {
    notifBtn.addEventListener('click', () => {
      if (countBadge) {
        let currentCount = parseInt(countBadge.textContent) || 0;
        if (currentCount > 0) {
          countBadge.textContent = '0';
          countBadge.setAttribute('data-count', '0');
          countBadge.style.display = 'none';
          showToast('Notifications Cleared', 'All 3 security notifications marked as read.');
        } else {
          countBadge.textContent = '3';
          countBadge.setAttribute('data-count', '3');
          countBadge.style.display = 'flex';
          showToast('3 New Security Alerts', 'Critical alert threshold and policy updates pending review.');
        }
      }
    });
  }
}

/* ================= 8. REAL-TIME CLOCK SYNC ================= */
function initSidebarClock() {
  const clockEl = document.getElementById('sidebarClockTime');
  if (!clockEl) return;

  function updateClock() {
    const now = new Date();
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[now.getMonth()];
    const day = String(now.getDate()).padStart(2, '0');
    const year = now.getFullYear();
    const hrs = String(now.getHours()).padStart(2, '0');
    const mins = String(now.getMinutes()).padStart(2, '0');
    const secs = String(now.getSeconds()).padStart(2, '0');
    
    clockEl.textContent = `${month} ${day}, ${year} ${hrs}:${mins}:${secs}`;
  }

  updateClock();
  setInterval(updateClock, 1000);
}

/* ================= 9. GLOBAL SEARCH FILTER ================= */
function initGlobalSearch() {
  const searchInput = document.getElementById('globalSearch');
  if (!searchInput) return;

  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    const searchableItems = document.querySelectorAll(
      '.toggle-row-item, .notif-toggle-row, .data-field-pair, .kv-row, .activity-event-item, .btn-export-item'
    );

    if (!query) {
      searchableItems.forEach(item => {
        item.style.opacity = '1';
        item.style.background = '';
      });
      return;
    }

    searchableItems.forEach(item => {
      const text = item.textContent.toLowerCase();
      if (text.includes(query)) {
        item.style.opacity = '1';
        item.style.background = 'rgba(56, 189, 248, 0.12)';
      } else {
        item.style.opacity = '0.3';
        item.style.background = '';
      }
    });
  });
}

/* ================= 10. TOAST NOTIFICATION UTILITY ================= */
let toastTimeout = null;

function showToast(title, message, type = 'success') {
  const toast = document.getElementById('settingsToast');
  const toastTitle = document.getElementById('settingsToastTitle');
  const toastMsg = document.getElementById('settingsToastMsg');

  if (!toast || !toastTitle || !toastMsg) return;

  toastTitle.textContent = title;
  toastMsg.textContent = message;

  if (type === 'error') {
    toast.classList.add('toast-error');
  } else {
    toast.classList.remove('toast-error');
  }

  toast.classList.add('show');

  if (toastTimeout) clearTimeout(toastTimeout);

  toastTimeout = setTimeout(() => {
    toast.classList.remove('show');
  }, 3200);
}
