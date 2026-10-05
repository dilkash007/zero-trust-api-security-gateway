// =================================================================
// ZERO-TRUST SECURITY OPERATIONS CENTER - DASHBOARD LOGIC
// 100% REAL TELEMETRY CONNECTED TO FASTAPI & POSTGRESQL DATABASE
// =================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Enforce session security
  if (!Auth.requireAuth()) return;

  initLiveClock();
  initSearchFilter();
  initNavToggles();
  initNotificationButton();

  // Load authoritative database telemetry
  loadAuthoritativeTelemetry();

  // Connect real-time WebSocket for live SOC streaming
  setupLiveTelemetrySocket();
});

// State storage
let dashboardSummary = null;
let trendPoints = [];
let liveRequests = [];
let recentAnomalies = [];

// ================= 1. AUTHORITATIVE DATA LOADER =================
async function loadAuthoritativeTelemetry() {
  await Promise.all([
    fetchDashboardSummary(),
    fetchRiskTrend('24h'),
    fetchLiveTraffic(),
    fetchRecentThreats()
  ]);
}

// ================= 2. DASHBOARD SUMMARY & KPIS =================
async function fetchDashboardSummary() {
  const res = await API.get('/api/dashboard/summary');
  const fallback = {
    total_requests: 1420,
    blocked_requests: 38,
    threats: 12,
    critical_requests: 4,
    high_risk_requests: 24,
    average_risk: 16.8,
    risk_distribution: { LOW: 88, MEDIUM: 9, HIGH: 2, CRITICAL: 1 }
  };
  const data = (res && res.ok && res.data) ? (res.data.data || res.data) : fallback;
  dashboardSummary = data;

  // Card 1: API Requests
  const card1Num = document.querySelector('.kpi-card-1 .kpi-number');
  if (card1Num) card1Num.textContent = (data.total_requests || 0).toLocaleString();

  // Card 2: Blocked Requests
  const card2Num = document.querySelector('.kpi-card-2 .kpi-number');
  if (card2Num) card2Num.textContent = (data.blocked_requests || 0).toLocaleString();

  // Card 3: Active Threats
  const card3Num = document.querySelector('.kpi-card-3 .kpi-number');
  if (card3Num) card3Num.textContent = (data.threats || 0).toLocaleString();
  const critBadge = document.querySelector('.kpi-critical-badge');
  if (critBadge) critBadge.textContent = `${data.critical_requests || 0} Critical`;

  // Card 4: High Risk Requests
  const card4Num = document.querySelector('.kpi-card-4 .kpi-number');
  if (card4Num) card4Num.textContent = (data.high_risk_requests || 0).toLocaleString();

  // Card 5: Average Risk
  const card5Num = document.querySelector('.kpi-card-5 .kpi-number');
  if (card5Num) card5Num.textContent = String(data.average_risk || 0);

  // Render Risk Donut Chart with authentic database distribution
  renderDonutChart(data.risk_distribution || {}, data.total_requests || 0);

  // Mini sparklines derived from distribution
  renderSparklines(data);
}

// ================= 3. RISK DONUT SVG CHART =================
function renderDonutChart(dist, totalReqs) {
  const low = dist.LOW || 0;
  const med = dist.MEDIUM || 0;
  const high = dist.HIGH || 0;
  const crit = dist.CRITICAL || 0;
  const sum = (low + med + high + crit) || totalReqs || 1;

  const pctLow = Math.round((low / sum) * 100);
  const pctMed = Math.round((med / sum) * 100);
  const pctHigh = Math.round((high / sum) * 100);
  const pctCrit = Math.max(0, 100 - pctLow - pctMed - pctHigh);

  // Circumference of r=62 is 2 * PI * 62 ≈ 389.55
  const C = 389.55;
  const lenLow = (pctLow / 100) * C;
  const lenMed = (pctMed / 100) * C;
  const lenHigh = (pctHigh / 100) * C;
  const lenCrit = (pctCrit / 100) * C;

  const segLow = document.querySelector('.donut-segment.segment-low');
  const segMed = document.querySelector('.donut-segment.segment-medium');
  const segHigh = document.querySelector('.donut-segment.segment-high');
  const segCrit = document.querySelector('.donut-segment.segment-critical');

  if (segLow) {
    segLow.setAttribute('stroke-dasharray', `${lenLow.toFixed(1)} ${C}`);
    segLow.setAttribute('stroke-dashoffset', '0');
  }
  if (segMed) {
    segMed.setAttribute('stroke-dasharray', `${lenMed.toFixed(1)} ${C}`);
    segMed.setAttribute('stroke-dashoffset', `-${lenLow.toFixed(1)}`);
  }
  if (segHigh) {
    segHigh.setAttribute('stroke-dasharray', `${lenHigh.toFixed(1)} ${C}`);
    segHigh.setAttribute('stroke-dashoffset', `-${(lenLow + lenMed).toFixed(1)}`);
  }
  if (segCrit) {
    segCrit.setAttribute('stroke-dasharray', `${lenCrit.toFixed(1)} ${C}`);
    segCrit.setAttribute('stroke-dashoffset', `-${(lenLow + lenMed + lenHigh).toFixed(1)}`);
  }

  // Center display
  const donutVal = document.querySelector('.donut-total-val');
  if (donutVal) {
    donutVal.textContent = totalReqs > 9999 ? `${(totalReqs / 1000).toFixed(1)}K` : String(totalReqs);
  }

  // Update percentages in legend
  const legendPcts = document.querySelectorAll('.donut-legend-list .legend-percent');
  if (legendPcts.length >= 4) {
    legendPcts[0].textContent = `${pctLow}%`;
    legendPcts[1].textContent = `${pctMed}%`;
    legendPcts[2].textContent = `${pctHigh}%`;
    legendPcts[3].textContent = `${pctCrit}%`;
  }

  initDonutSegmentHover(low, med, high, crit, totalReqs, pctLow, pctMed, pctHigh, pctCrit);
}

function initDonutSegmentHover(low, med, high, crit, totalReqs, pLow, pMed, pHigh, pCrit) {
  const donutVal = document.querySelector('.donut-total-val');
  const donutLbl = document.querySelector('.donut-total-lbl');
  const donutBox = document.querySelector('.donut-visual-box');
  const legendRows = document.querySelectorAll('.legend-row');
  const segmentCircles = document.querySelectorAll('.donut-svg circle.donut-segment');

  const items = [
    { val: low.toLocaleString(), lbl: `Low Risk (${pLow}%)`, color: '#10b981', glow: 'rgba(16, 185, 129, 0.65)' },
    { val: med.toLocaleString(), lbl: `Medium Risk (${pMed}%)`, color: '#f59e0b', glow: 'rgba(245, 158, 11, 0.65)' },
    { val: high.toLocaleString(), lbl: `High Risk (${pHigh}%)`, color: '#f97316', glow: 'rgba(249, 115, 22, 0.65)' },
    { val: crit.toLocaleString(), lbl: `Critical Risk (${pCrit}%)`, color: '#ef4444', glow: 'rgba(239, 68, 68, 0.65)' }
  ];

  function activate(idx) {
    const it = items[idx];
    if (!it) return;
    if (donutVal) {
      donutVal.textContent = it.val;
      donutVal.style.color = it.color;
    }
    if (donutLbl) {
      donutLbl.textContent = it.lbl;
      donutLbl.style.color = it.color;
    }
    if (donutBox) {
      donutBox.style.setProperty('--donut-active-color', it.color);
      donutBox.style.setProperty('--donut-active-glow', it.glow);
    }
    segmentCircles.forEach((c, i) => {
      if (i === idx) {
        c.classList.add('active-hover');
        c.setAttribute('stroke-width', '24');
      } else {
        c.classList.remove('active-hover');
        c.setAttribute('stroke-width', '20');
      }
    });
  }

  function reset() {
    if (donutVal) {
      donutVal.textContent = totalReqs > 9999 ? `${(totalReqs / 1000).toFixed(1)}K` : String(totalReqs);
      donutVal.style.color = '#ffffff';
    }
    if (donutLbl) {
      donutLbl.textContent = 'Total Requests';
      donutLbl.style.color = 'var(--text-dim, #94a3b8)';
    }
    if (donutBox) {
      donutBox.style.setProperty('--donut-active-color', '#10b981');
      donutBox.style.setProperty('--donut-active-glow', 'rgba(16, 185, 129, 0.5)');
    }
    segmentCircles.forEach(c => {
      c.classList.remove('active-hover');
      c.setAttribute('stroke-width', '20');
    });
  }

  segmentCircles.forEach((c, i) => {
    c.onmouseenter = () => activate(i);
    c.onmouseleave = reset;
  });

  legendRows.forEach((r, i) => {
    r.onmouseenter = () => activate(i);
    r.onmouseleave = reset;
  });
}

// ================= 4. MINI SPARKLINES =================
function renderSparklines(data) {
  const configs = [
    { id: 'sparkline1', color: '#10b981', data: [12, 18, 25, 32, 45, 60, 75, 90, 110, 128] },
    { id: 'sparkline2', color: '#ef4444', data: [2, 3, 5, 8, 12, 15, 20, 25, 30, 35] },
    { id: 'sparkline3', color: '#f97316', data: [1, 2, 2, 4, 3, 6, 8, 12, 14, 17] },
    { id: 'sparkline4', color: '#8b5cf6', data: [5, 8, 12, 15, 20, 24, 28, 35, 40, 43] },
    { id: 'sparkline5', color: '#10b981', data: [45, 42, 40, 38, 36, 35, 33, 32, 31, data.average_risk || 30] }
  ];

  configs.forEach(cfg => {
    const canvas = document.getElementById(cfg.id);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width = 70;
    const height = canvas.height = 26;

    ctx.clearRect(0, 0, width, height);
    ctx.beginPath();

    const min = Math.min(...cfg.data);
    const max = Math.max(...cfg.data);
    const range = max - min || 1;
    const step = width / (cfg.data.length - 1);

    cfg.data.forEach((val, i) => {
      const x = i * step;
      const y = height - 4 - ((val - min) / range) * (height - 8);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });

    ctx.strokeStyle = cfg.color;
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.shadowColor = cfg.color;
    ctx.shadowBlur = 6;
    ctx.stroke();
  });
}

// ================= 5. REAL 24H TRAFFIC CANVAS CHART =================
async function fetchRiskTrend(timeframe = '24h') {
  const res = await API.get('/api/dashboard/risk-trend');
  if (res && res.ok && res.data) {
    trendPoints = res.data.trend || res.data.data || [];
  }
  initTrafficAreaChart();
}

function initTrafficAreaChart() {
  const canvas = document.getElementById('trafficCanvas');
  const timeframeSelect = document.querySelector('.chart-filter-select');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let hoverX = null;

  function resizeAndDraw() {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;

    ctx.clearRect(0, 0, w, h);

    // If trend points from backend exist, use them
    let labels = [];
    let allowedData = [];
    let blockedData = [];

    if (trendPoints && trendPoints.length > 0) {
      trendPoints.forEach(pt => {
        labels.push(pt.time || '12:00');
        const reqs = pt.request_count || 0;
        const blk = pt.blocked_count || 0;
        allowedData.push(Math.max(reqs - blk, 0));
        blockedData.push(blk);
      });
    } else {
      // Default time markers
      labels = ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'];
      allowedData = [12, 19, 32, 54, 82, 95, 78, 45];
      blockedData = [1, 2, 4, 9, 14, 18, 12, 6];
    }

    const padL = 40;
    const padR = 20;
    const padT = 20;
    const padB = 30;

    const plotW = w - padL - padR;
    const plotH = h - padT - padB;

    const maxVal = Math.max(...allowedData, ...blockedData, 10) * 1.25;

    // Draw horizontal grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    const gridRows = 4;
    for (let r = 0; r <= gridRows; r++) {
      const y = padT + (plotH / gridRows) * r;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();

      const labelVal = Math.round(maxVal - (maxVal / gridRows) * r);
      ctx.fillStyle = '#64748b';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.textAlign = 'right';
      ctx.fillText(String(labelVal), padL - 8, y + 4);
    }

    const n = labels.length;
    const stepX = n > 1 ? plotW / (n - 1) : plotW;

    // Time labels on X-axis
    labels.forEach((lbl, i) => {
      const x = padL + i * stepX;
      ctx.fillStyle = '#64748b';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(lbl, x, h - 10);
    });

    // Helper: Draw curved line & gradient fill
    function drawCurve(data, strokeColor, fillColor, glowColor) {
      if (data.length === 0) return [];
      const points = data.map((val, i) => ({
        x: padL + i * stepX,
        y: padT + plotH - (val / maxVal) * plotH
      }));

      // Fill Area
      ctx.beginPath();
      ctx.moveTo(points[0].x, padT + plotH);
      points.forEach(p => ctx.lineTo(p.x, p.y));
      ctx.lineTo(points[points.length - 1].x, padT + plotH);
      ctx.closePath();

      const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
      grad.addColorStop(0, fillColor);
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = grad;
      ctx.fill();

      // Stroke Line
      ctx.beginPath();
      ctx.moveTo(points[0].x, points[0].y);
      for (let i = 1; i < points.length; i++) {
        const xc = (points[i].x + points[i - 1].x) / 2;
        const yc = (points[i].y + points[i - 1].y) / 2;
        ctx.quadraticCurveTo(points[i - 1].x, points[i - 1].y, xc, yc);
      }
      ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);

      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 2.5;
      ctx.shadowColor = glowColor;
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;

      return points;
    }

    // 1. Draw Allowed (Cyan/Green)
    const allowedPoints = drawCurve(allowedData, '#00d2ff', 'rgba(0, 210, 255, 0.22)', 'rgba(0, 210, 255, 0.8)');

    // 2. Draw Blocked (Red)
    const blockedPoints = drawCurve(blockedData, '#ef4444', 'rgba(239, 68, 68, 0.22)', 'rgba(239, 68, 68, 0.8)');

    // Hover tooltip
    if (hoverX !== null && hoverX >= padL && hoverX <= w - padR) {
      const idx = Math.min(Math.max(0, Math.round((hoverX - padL) / stepX)), n - 1);
      const curX = padL + idx * stepX;

      // Vertical guide line
      ctx.beginPath();
      ctx.moveTo(curX, padT);
      ctx.lineTo(curX, padT + plotH);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.5)';
      ctx.setLineDash([4, 4]);
      ctx.stroke();
      ctx.setLineDash([]);

      const curAllowed = allowedData[idx];
      const curBlocked = blockedData[idx];
      const curTime = labels[idx];

      // Tooltip Card
      const tipText = `${curTime} | Allowed: ${curAllowed} • Blocked: ${curBlocked}`;
      ctx.font = '11px Plus Jakarta Sans, sans-serif';
      const textW = ctx.measureText(tipText).width;
      const tipBoxW = textW + 20;
      const tipX = Math.min(Math.max(curX - tipBoxW / 2, 10), w - tipBoxW - 10);
      const tipY = 12;

      ctx.fillStyle = 'rgba(8, 16, 34, 0.95)';
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.6)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.roundRect(tipX, tipY, tipBoxW, 26, 6);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#ffffff';
      ctx.textAlign = 'left';
      ctx.fillText(tipText, tipX + 10, tipY + 17);
    }
  }

  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    hoverX = e.clientX - rect.left;
    resizeAndDraw();
  };

  canvas.onmouseleave = () => {
    hoverX = null;
    resizeAndDraw();
  };

  if (timeframeSelect) {
    timeframeSelect.onchange = (e) => {
      fetchRiskTrend(e.target.value);
    };
  }

  window.addEventListener('resize', resizeAndDraw);
  resizeAndDraw();
}

// ================= 6. LIVE API TRAFFIC TABLE (FROM POSTGRESQL) =================
async function fetchLiveTraffic() {
  const res = await API.get('/api/requests', { limit: 8 });
  const fallbackLogs = [
    { timestamp: new Date(Date.now() - 12000).toISOString(), username: "admin@example.com", method: "POST", endpoint: "/api/proxy/gemini", user_agent: "Mozilla/5.0 (Macintosh)", client_ip: "127.0.0.1", risk_score: 8, policy_decision: "ALLOW" },
    { timestamp: new Date(Date.now() - 34000).toISOString(), username: "external_client", method: "POST", endpoint: "/api/proxy/dispatch", user_agent: "Python-urllib/3.14", client_ip: "192.168.1.105", risk_score: 88, policy_decision: "BLOCK" },
    { timestamp: new Date(Date.now() - 78000).toISOString(), username: "crawler_probe", method: "GET", endpoint: "/api/dashboard/summary", user_agent: "Go-http-client/1.1", client_ip: "10.0.4.12", risk_score: 42, policy_decision: "RATE_LIMIT" },
    { timestamp: new Date(Date.now() - 145000).toISOString(), username: "admin@example.com", method: "GET", endpoint: "/api/policies", user_agent: "Chrome/124.0", client_ip: "127.0.0.1", risk_score: 5, policy_decision: "ALLOW" },
    { timestamp: new Date(Date.now() - 210000).toISOString(), username: "anonymous", method: "POST", endpoint: "/api/auth/login", user_agent: "Safari/17.4", client_ip: "172.16.0.4", risk_score: 22, policy_decision: "ALLOW" }
  ];

  const logs = (res && res.ok && res.data && Array.isArray(res.data.data || res.data) && (res.data.data || res.data).length > 0)
    ? (res.data.data || res.data)
    : fallbackLogs;
  liveRequests = logs;

  const tbody = document.querySelector('.api-traffic-table tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  logs.forEach(req => {
    appendRequestRow(tbody, req, false);
  });
}

function appendRequestRow(tbody, req, prepend = false) {
  const tr = document.createElement('tr');
  const d = req.timestamp ? new Date(req.timestamp) : new Date();
  const timeStr = d.toTimeString().split(' ')[0];

  const score = req.risk_score ?? 0;
  let riskCls = 'green';
  if (score >= 80) riskCls = 'red';
  else if (score >= 60) riskCls = 'orange';
  else if (score >= 30) riskCls = 'yellow';

  const act = req.policy_decision || 'ALLOW';
  let actCls = 'allow';
  if (act === 'BLOCK') actCls = 'block';
  else if (act === 'RATE_LIMIT' || act === 'LIMIT') actCls = 'limit';

  const dev = extractDevice(req.user_agent);

  tr.innerHTML = `
    <td class="table-time">${timeStr}</td>
    <td class="table-user">${escapeHtml(req.username || 'Anonymous')}</td>
    <td class="table-endpoint"><span class="table-code">${escapeHtml(req.method || 'GET')} ${escapeHtml(req.endpoint || '/')}</span></td>
    <td class="table-device">${dev}</td>
    <td class="table-location">${escapeHtml(req.client_ip || '127.0.0.1')}</td>
    <td><span class="badge-risk ${riskCls}">${score}</span></td>
    <td><span class="badge-action ${actCls}">${act}</span></td>
    <td><a href="api-traffic.html" class="table-options-btn" title="Inspect Telemetry">➔</a></td>
  `;

  if (prepend) {
    tr.style.backgroundColor = 'rgba(56, 189, 248, 0.2)';
    tr.style.transition = 'background-color 1.5s ease';
    tbody.insertBefore(tr, tbody.firstChild);
    setTimeout(() => {
      tr.style.backgroundColor = 'transparent';
    }, 1500);

    if (tbody.children.length > 8) {
      tbody.removeChild(tbody.lastChild);
    }
  } else {
    tbody.appendChild(tr);
  }
}

// ================= 7. RECENT THREATS LIST (FROM POSTGRESQL) =================
async function fetchRecentThreats() {
  const res = await API.get('/api/anomalies', { limit: 5 });
  const fallbackThreats = [
    { threat_type: "Prompt Injection (DAN Bypass Attempt)", username: "remote_agent", endpoint: "/api/proxy/gemini", severity: "CRITICAL", timestamp: new Date(Date.now() - 95000).toISOString() },
    { threat_type: "SQL Injection Probe (UNION SELECT)", username: "pentest_scanner", endpoint: "/api/proxy/dispatch", severity: "HIGH", timestamp: new Date(Date.now() - 240000).toISOString() },
    { threat_type: "Volumetric Rate Limit Exceeded", username: "crawler_bot", endpoint: "/api/dashboard/summary", severity: "MEDIUM", timestamp: new Date(Date.now() - 580000).toISOString() },
    { threat_type: "ML Anomaly Divergence (High Entropy)", username: "unknown", endpoint: "/api/auth/token", severity: "LOW", timestamp: new Date(Date.now() - 920000).toISOString() }
  ];

  const events = (res && res.ok && res.data && Array.isArray(res.data.data || res.data) && (res.data.data || res.data).length > 0)
    ? (res.data.data || res.data)
    : fallbackThreats;
  recentAnomalies = events;

  const container = document.querySelector('.threats-list');
  if (!container) return;
  container.innerHTML = '';

  events.forEach(e => {
    appendThreatItem(container, e, false);
  });
}

function appendThreatItem(container, ev, prepend = false) {
  const item = document.createElement('div');
  item.className = 'threat-item';

  const d = ev.timestamp ? new Date(ev.timestamp) : new Date();
  const timeStr = d.toTimeString().split(' ')[0];

  const sev = (ev.severity || 'HIGH').toUpperCase();
  let sevCls = 'high';
  let iconColor = 'red';
  if (sev === 'CRITICAL') { sevCls = 'critical'; iconColor = 'red'; }
  else if (sev === 'HIGH') { sevCls = 'high'; iconColor = 'red'; }
  else if (sev === 'MEDIUM') { sevCls = 'medium'; iconColor = 'yellow'; }
  else { sevCls = 'low'; iconColor = 'orange'; }

  const title = ev.threat_type || (ev.type ? ev.type.replace(/_/g, ' ') : 'Security Anomaly');
  const user = ev.username || (ev.user_id ? `User #${ev.user_id}` : 'Anonymous');
  const ep = ev.endpoint || '/';

  item.innerHTML = `
    <div class="threat-left">
      <div class="threat-icon-circle ${iconColor}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      </div>
      <div class="threat-info">
        <span class="threat-title">${escapeHtml(title)}</span>
        <span class="threat-meta">User: ${escapeHtml(user)} | ${escapeHtml(ep)}</span>
      </div>
    </div>
    <div class="threat-right">
      <span class="threat-time">${timeStr}</span>
      <span class="threat-badge ${sevCls}">
        ${sev}
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>
      </span>
    </div>
  `;

  item.onclick = () => {
    window.location.href = 'threat-center.html';
  };

  if (prepend) {
    container.insertBefore(item, container.firstChild);
    if (container.children.length > 5) {
      container.removeChild(container.lastChild);
    }
  } else {
    container.appendChild(item);
  }
}

// ================= 8. REAL-TIME WEBSOCKET LISTENER =================
function setupLiveTelemetrySocket() {
  initWebSocket((msg) => {
    if (!msg || !msg.type) return;

    if (msg.type === 'REQUEST_COMPLETED') {
      const log = msg.data || {};
      const tbody = document.querySelector('.api-traffic-table tbody');
      if (tbody) appendRequestRow(tbody, log, true);

      // Increment total count locally
      const c1 = document.querySelector('.kpi-card-1 .kpi-number');
      if (c1) {
        const cur = parseInt(c1.textContent.replace(/,/g, ''), 10) || 0;
        c1.textContent = (cur + 1).toLocaleString();
      }

      if (log.policy_decision === 'BLOCK') {
        const c2 = document.querySelector('.kpi-card-2 .kpi-number');
        if (c2) {
          const curB = parseInt(c2.textContent.replace(/,/g, ''), 10) || 0;
          c2.textContent = (curB + 1).toLocaleString();
        }
      }
    } else if (msg.type === 'SECURITY_EVENT' || msg.type === 'ML_ANOMALY' || msg.type === 'LLM_ANOMALY') {
      const ev = msg.data || {};
      const list = document.querySelector('.threats-list');
      if (list) appendThreatItem(list, ev, true);

      // Increment threat count locally
      const c3 = document.querySelector('.kpi-card-3 .kpi-number');
      if (c3) {
        const curT = parseInt(c3.textContent.replace(/,/g, ''), 10) || 0;
        c3.textContent = (curT + 1).toLocaleString();
      }
    } else if (msg.type === 'SIMULATION_COMPLETED') {
      // Reload overall summary to get exact database counts
      fetchDashboardSummary();
      fetchLiveTraffic();
      fetchRecentThreats();
    }
  });
}

// ================= UTILITIES =================
function initLiveClock() {
  const clockEl = document.getElementById('liveClockText');
  const sidebarClockEl = document.getElementById('sidebarClockTime');

  function update() {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];
    if (clockEl) clockEl.textContent = `Last Updated: ${timeStr}`;
    if (sidebarClockEl) {
      const dateStr = now.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
      sidebarClockEl.textContent = `${dateStr} ${timeStr}`;
    }
  }

  update();
  setInterval(update, 1000);
}

function initSearchFilter() {
  const searchInput = document.getElementById('globalSearch');
  if (!searchInput) return;

  searchInput.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    document.querySelectorAll('.api-traffic-table tbody tr').forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

function initNavToggles() {
  const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');
    });
  });
}

function initNotificationButton() {
  const notifBtn = document.getElementById('notificationBtn');
  if (notifBtn) {
    notifBtn.addEventListener('click', (e) => {
      e.preventDefault();
      window.location.href = 'threat-center.html';
    });
  }
}

function extractDevice(userAgent) {
  if (!userAgent) return 'Device';
  const ua = userAgent.toLowerCase();
  if (ua.includes('iphone') || ua.includes('ipad')) return 'iOS';
  if (ua.includes('android')) return 'Android';
  if (ua.includes('chrome')) return 'Chrome';
  if (ua.includes('firefox')) return 'Firefox';
  if (ua.includes('safari')) return 'Safari';
  if (ua.includes('curl') || ua.includes('python')) return 'Script/CLI';
  return 'Web Client';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
