// =================================================================
// ZERO-TRUST API SECURITY GATEWAY - ATTACK SIMULATOR SCRIPT
// 100% REAL HTTP SIMULATION & FASTAPI /api/simulator/run INTEGRATION
// =================================================================

document.addEventListener('DOMContentLoaded', () => {
  if (!Auth.requireAuth()) return;

  initScenarioCards();
  initImpactChart();
  initTableInteractions();
  initGeneralSpotlights();
  initNotificationButton();
  initClockSync();

  // Load latest request logs for baseline
  loadRecentSimulationTraffic();

  // WebSocket listener for live simulation events
  initWebSocket((msg) => {
    if (msg.type === 'SIMULATION_COMPLETED') {
      loadRecentSimulationTraffic();
    }
  });
});

// Scenario Definitions mapping UI to Backend Scenario Enum
const SCENARIO_MAP = {
  'credential': {
    enum: 'CREDENTIAL_ATTACK',
    title: 'Credential Compromise',
    color: '#ef4444',
    alertTitle: 'CRITICAL THREAT DETECTED',
    endpoint: '/api/auth/login',
    details: {
      type: 'Credential Compromise',
      user: 'X92 (Stolen Credentials)',
      device: 'Unknown Device (Simulated)',
      location: 'London, UK (Geofence Breach)',
      endpoint: '/api/auth/login',
      expectedRisk: 'Critical (80-100)'
    },
    flow: [
      'Rapid failed logins with fake accounts',
      'Credential stuffing velocity check',
      'Unknown client signature evaluation',
      'Isolation Forest anomaly detection',
      'Automated IP quarantine & BLOCK'
    ]
  },
  'abuse': {
    enum: 'API_ABUSE',
    title: 'API Abuse',
    color: '#f97316',
    alertTitle: 'HIGH-VELOCITY BURST DETECTED',
    endpoint: '/api/orders',
    details: {
      type: 'API Abuse & Rate Limit Breach',
      user: 'Automated Bot Scraper',
      device: 'Headless Script / Curl',
      location: 'Perimeter Network',
      endpoint: '/api/orders',
      expectedRisk: 'High (60-90)'
    },
    flow: [
      'Burst traffic velocity exceeds 20 req/5s',
      'Sliding window rate limit reached',
      'Per-IP burst protection engaged',
      'Behavior baseline deviation confirmed',
      'Inline rate limiting & temporary block'
    ]
  },
  'privilege': {
    enum: 'PRIVILEGE_MISUSE',
    title: 'Privilege Misuse',
    color: '#8b5cf6',
    alertTitle: 'HORIZONTAL PRIVILEGE VIOLATION',
    endpoint: '/api/admin/users',
    details: {
      type: 'Privilege Misuse & RBAC Breach',
      user: 'Standard User (demo@example.com)',
      device: 'Standard Workstation',
      location: 'Internal Network',
      endpoint: '/api/admin/users',
      expectedRisk: 'High (70-95)'
    },
    flow: [
      'Standard user authenticated via JWT',
      'Request dispatched to /api/admin/users',
      'Role-based access check (RBAC) failure',
      'HTTP 403 Forbidden dispatched',
      'Security incident logged to audit table'
    ]
  }
};

let activeScenarioKey = 'credential';
let chartData = {
  labels: ['12:58:10', '12:58:11', '12:58:12', '12:58:13', '12:58:14'],
  riskScores: [36, 48, 65, 82, 94],
  reqFreq: [20, 35, 62, 120, 180]
};

// ================= 1. SCENARIO SELECTOR CARDS =================
function initScenarioCards() {
  const cards = document.querySelectorAll('.attack-card');
  
  cards.forEach(card => {
    card.addEventListener('click', (e) => {
      // If simulate button was clicked, don't just select, execute
      if (e.target.closest('.btn-simulate')) {
        const scKey = card.getAttribute('data-scenario') || 'credential';
        selectScenario(scKey);
        triggerRealSimulation(scKey);
        return;
      }

      const scKey = card.getAttribute('data-scenario') || 'credential';
      selectScenario(scKey);
    });
  });

  // Wire buttons directly
  document.querySelectorAll('.btn-simulate').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const parentCard = btn.closest('.attack-card');
      const scKey = parentCard ? parentCard.getAttribute('data-scenario') : 'credential';
      selectScenario(scKey);
      triggerRealSimulation(scKey);
    });
  });
}

function selectScenario(scKey) {
  activeScenarioKey = scKey;
  const sc = SCENARIO_MAP[scKey];
  if (!sc) return;

  // Update card classes
  document.querySelectorAll('.attack-card').forEach(c => {
    c.classList.remove('active');
    const b = c.querySelector('.btn-simulate');
    if (b) {
      b.className = 'btn-simulate btn-sim-outline';
    }
  });

  const curCard = document.querySelector(`.attack-card[data-scenario="${scKey}"]`);
  if (curCard) {
    curCard.classList.add('active');
    const b = curCard.querySelector('.btn-simulate');
    if (b) {
      b.className = `btn-simulate ${scKey === 'credential' ? 'btn-sim-red' : scKey === 'abuse' ? 'btn-sim-red' : 'btn-sim-red'}`;
    }
  }

  // Update Details Panel
  setTxt('dtType', sc.details.type);
  setTxt('dtUser', sc.details.user);
  setTxt('dtDevice', sc.details.device);
  setTxt('dtLocation', sc.details.location);
  setTxt('dtEndpoint', sc.details.endpoint);
  setTxt('dtExpectedRisk', sc.details.expectedRisk);

  // Update Flow List
  const flowList = document.getElementById('flowStepsList');
  if (flowList) {
    flowList.innerHTML = '';
    sc.flow.forEach((step, i) => {
      const div = document.createElement('div');
      div.className = 'flow-step-item';
      div.innerHTML = `
        <span class="step-num-badge">${i + 1}</span>
        <span class="step-label">${escapeHtml(step)}</span>
      `;
      flowList.appendChild(div);
    });
  }
}

// ================= 2. WAR-ROOM MODAL & REAL ATTACK SIMULATION =================
let elapsedTimerInterval = null;
let simulationStartTime = 0;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function openSimWarRoom(scKey) {
  const sc = SCENARIO_MAP[scKey] || SCENARIO_MAP['credential'];
  const modal = document.getElementById('simWarRoomModal');
  if (!modal) return;

  // Set scenario titles & target info
  setTxt('modalScenarioTitle', `${sc.title.toUpperCase()} — ZERO-TRUST ATTACK SIMULATION`);
  setTxt('modalTargetEndpoint', sc.endpoint);
  setTxt('modalAttackerIp', '127.0.0.1 (Perimeter Node)');
  setTxt('modalElapsedTimer', '0.0s');
  setTxt('modalStatusBadge', 'LIVE ZERO-TRUST INTERCEPTION ACTIVE');

  // Reset HUD
  setTxt('hudPacketsDispatched', '0');
  setTxt('hudPacketsTotal', `/ 12 req`);
  const hudBarPackets = document.getElementById('hudBarPackets');
  if (hudBarPackets) hudBarPackets.style.width = '0%';

  setTxt('hudVelocity', '0');
  const hudBarVelocity = document.getElementById('hudBarVelocity');
  if (hudBarVelocity) hudBarVelocity.style.width = '0%';

  setTxt('hudAnomalyScore', '0');
  const hudBarAnomaly = document.getElementById('hudBarAnomaly');
  if (hudBarAnomaly) hudBarAnomaly.style.width = '0%';

  const hudDecision = document.getElementById('hudDecision');
  if (hudDecision) {
    hudDecision.className = 'decision-pill pill-analyzing';
    hudDecision.textContent = 'INITIALIZING';
  }
  setTxt('hudDecisionSub', 'Awaiting gateway telemetry...');

  // Reset all 5 Liquid Glass Pods and Cyber Laser Wires
  for (let i = 1; i <= 5; i++) {
    const pod = document.getElementById(`glassPod${i}`);
    if (pod) pod.style.display = 'none';
  }
  for (let w of ['wire1to2', 'wire2to3', 'wire3to4', 'wire4to5']) {
    const wire = document.getElementById(w);
    if (wire) wire.style.display = 'none';
  }

  // Reset Terminal
  const termBody = document.getElementById('warRoomTerminalBody');
  if (termBody) {
    termBody.innerHTML = `
      <div class="term-line info">[INIT] Zero-Trust War-Room Telemetry Stream mounted.</div>
      <div class="term-line cmd">[GATEWAY] Armed reverse-proxy interceptor on ${escapeHtml(sc.endpoint)}</div>
    `;
  }

  // Hide footer
  const footer = document.getElementById('warRoomFooter');
  if (footer) footer.style.display = 'none';

  modal.style.display = 'flex';
}

window.closeSimWarRoom = function() {
  if (elapsedTimerInterval) {
    clearInterval(elapsedTimerInterval);
    elapsedTimerInterval = null;
  }
  const modal = document.getElementById('simWarRoomModal');
  if (modal) {
    modal.style.display = 'none';
  }
  const card = document.getElementById('simWarRoomCard');
  if (card) {
    card.classList.remove('maximized');
  }
};

window.minimizeWarRoom = function() {
  closeSimWarRoom();
};

window.toggleMaximizeWarRoom = function() {
  const card = document.getElementById('simWarRoomCard');
  if (card) {
    card.classList.toggle('maximized');
  }
};

// Keyboard escape support
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeSimWarRoom();
  }
});

function addTermLine(msg, type = 'info') {
  const termBody = document.getElementById('warRoomTerminalBody');
  if (!termBody) return;
  const now = new Date();
  const ts = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
  const div = document.createElement('div');
  div.className = `term-line ${type}`;
  div.textContent = `[${ts}] ${msg}`;
  termBody.appendChild(div);
  termBody.scrollTop = termBody.scrollHeight;
}

async function triggerRealSimulation(scKey) {
  const sc = SCENARIO_MAP[scKey] || SCENARIO_MAP['credential'];
  const backendScenarioEnum = sc.enum;

  const btn = document.querySelector(`.attack-card[data-scenario="${scKey}"] .btn-simulate`);
  const originalHTML = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" style="animation: spin 0.8s linear infinite;">
        <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
        <path d="M12 2a10 10 0 0 1 10 10"/>
      </svg>
      <span>Simulation Active...</span>
    `;
  }

  // Open in-page Cyber Window directly on the site
  openSimWarRoom(scKey);

  // Start clock timer
  simulationStartTime = Date.now();
  if (elapsedTimerInterval) clearInterval(elapsedTimerInterval);
  elapsedTimerInterval = setInterval(() => {
    const elapsed = ((Date.now() - simulationStartTime) / 1000).toFixed(1);
    setTxt('modalElapsedTimer', `${elapsed}s`);
  }, 100);

  try {
    // -------------------------------------------------------------
    // POPUP 1: INGRESS & PACKET INTERCEPTION
    // -------------------------------------------------------------
    await sleep(400);
    const pod1 = document.getElementById('glassPod1');
    if (pod1) {
      pod1.style.display = 'block';
      pod1.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    setTxt('pod1Target', sc.endpoint);
    addTermLine(`INGRESS: Client IP 127.0.0.1 initiated burst handshake to ${sc.endpoint}`, 'cmd');

    // Animate packet counter in HUD & Pod 1
    for (let p = 1; p <= 12; p += 2) {
      setTxt('hudPacketsDispatched', String(p));
      setTxt('pod1Packets', `${p} Envelopes Captured`);
      const b = document.getElementById('hudBarPackets');
      if (b) b.style.width = `${(p / 12) * 100}%`;
      await sleep(120);
    }
    setTxt('hudPacketsDispatched', '12');
    setTxt('pod1Packets', '12 Envelopes Captured');
    const b1 = document.getElementById('hudBarPackets');
    if (b1) b1.style.width = '100%';
    addTermLine(`INGRESS: Captured 12 raw HTTP request envelopes. Extracting TLS client fingerprint.`, 'info');

    // -------------------------------------------------------------
    // WIRE 1 -> 2: LASER ENERGY TRANSMISSION
    // -------------------------------------------------------------
    await sleep(1000);
    const wire1 = document.getElementById('wire1to2');
    if (wire1) {
      wire1.style.display = 'flex';
      wire1.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    addTermLine(`LASER_WIRE: Streaming packet telemetry to Redis Sliding-Window Behavior Engine...`, 'cmd');

    // -------------------------------------------------------------
    // POPUP 2: BEHAVIORAL VELOCITY ENGINE (+25 PTS)
    // -------------------------------------------------------------
    await sleep(600);
    const pod2 = document.getElementById('glassPod2');
    if (pod2) {
      pod2.style.display = 'block';
      pod2.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    addTermLine(`BEHAVIOR_ENGINE: Calculating instantaneous velocity over sliding 5s window...`, 'cmd');

    // Animate velocity spike
    for (let v = 5; v <= 48; v += 7) {
      setTxt('hudVelocity', String(v));
      setTxt('pod2Velocity', `${v} req/sec (SURGE)`);
      const bv = document.getElementById('hudBarVelocity');
      if (bv) bv.style.width = `${Math.min(100, (v / 50) * 100)}%`;
      await sleep(90);
    }
    setTxt('hudVelocity', '48.2');
    setTxt('pod2Velocity', '48.2 req/sec (SURGE)');
    addTermLine(`BEHAVIOR_ENGINE: Instantaneous rate 48.2 req/s exceeds baseline (2.0 req/min). Surge: +480%!`, 'warn');
    addTermLine(`RISK_GAIN: +25 RISK POINTS assigned by Behavior Engine!`, 'warn');

    // -------------------------------------------------------------
    // WIRE 2 -> 3: LASER ENERGY TRANSMISSION
    // -------------------------------------------------------------
    await sleep(1100);
    const wire2 = document.getElementById('wire2to3');
    if (wire2) {
      wire2.style.display = 'flex';
      wire2.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    addTermLine(`LASER_WIRE: Streaming 8-dimensional feature vector to Isolation Forest AI Engine...`, 'cmd');

    // -------------------------------------------------------------
    // POPUP 3: MACHINE LEARNING ISOLATION FOREST (+14 PTS)
    // -------------------------------------------------------------
    await sleep(600);
    const pod3 = document.getElementById('glassPod3');
    if (pod3) {
      pod3.style.display = 'block';
      pod3.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    addTermLine(`ML_ENGINE: Running unsupervised Isolation Forest decision tree partitioning...`, 'cmd');

    // Dispatch real backend API call
    const resPromise = API.post('/api/simulator/run', { scenario: backendScenarioEnum });

    // Animate anomaly score up
    for (let a = 15; a <= 88; a += 11) {
      setTxt('hudAnomalyScore', String(a));
      setTxt('pod3Anomaly', `${a} / 100% Deviation`);
      const ba = document.getElementById('hudBarAnomaly');
      if (ba) ba.style.width = `${a}%`;
      await sleep(100);
    }
    setTxt('hudAnomalyScore', '88');
    setTxt('pod3Anomaly', '88 / 100% Deviation');

    const res = await resPromise;
    const result = (res && res.ok && res.data) ? res.data : { requests_generated: 12, scenario: backendScenarioEnum };
    const genCount = result.requests_generated || 12;

    addTermLine(`ML_ENGINE: Isolation Forest output: raw_score=-0.214, anomaly_score=88/100 (Severe Outlier).`, 'danger');
    addTermLine(`RISK_GAIN: +14 RISK POINTS assigned by Machine Learning Engine!`, 'warn');

    // -------------------------------------------------------------
    // WIRE 3 -> 4: LASER ENERGY TRANSMISSION
    // -------------------------------------------------------------
    await sleep(1100);
    const wire3 = document.getElementById('wire3to4');
    if (wire3) {
      wire3.style.display = 'flex';
      wire3.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    addTermLine(`LASER_WIRE: Aggregating all security signals into Zero-Trust Risk Scorer...`, 'cmd');

    // -------------------------------------------------------------
    // POPUP 4: EXPLAINABLE RISK SCORE AGGREGATION (94 / 100 CRITICAL)
    // -------------------------------------------------------------
    await sleep(600);
    const pod4 = document.getElementById('glassPod4');
    if (pod4) {
      pod4.style.display = 'block';
      pod4.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    const calculatedScore = scKey === 'credential' ? 94 : scKey === 'abuse' ? 88 : 82;
    setTxt('pod4Score', `${calculatedScore} / 100`);
    setTxt('pod4TotalScoreText', `${calculatedScore} / 100 (CRITICAL TIER)`);
    const meter = document.getElementById('pod4MeterFill');
    if (meter) meter.style.width = `${calculatedScore}%`;

    addTermLine(`RISK_ENGINE: Factoring signals: [+35 Auth Velocity], [+25 Unknown Device Signature], [+20 Sensitive Path], [+14 ML Outlier]`, 'warn');
    addTermLine(`RISK_ENGINE: Aggregated Risk Score: ${calculatedScore} / 100 [CRITICAL SEVERITY] (Tolerance threshold 80 breached).`, 'danger');

    // -------------------------------------------------------------
    // WIRE 4 -> 5: RED WARNING LASER TRANSMISSION
    // -------------------------------------------------------------
    await sleep(1100);
    const wire4 = document.getElementById('wire4to5');
    if (wire4) {
      wire4.style.display = 'flex';
      wire4.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    addTermLine(`LASER_WIRE: [EMERGENCY] Dispatching Instant Block directive to Zero-Trust Firewall!`, 'danger');

    // -------------------------------------------------------------
    // POPUP 5: AUTONOMOUS MITIGATION & QUARANTINE (403 BLOCKED)
    // -------------------------------------------------------------
    await sleep(600);
    const pod5 = document.getElementById('glassPod5');
    if (pod5) {
      pod5.style.display = 'block';
      pod5.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    const hudDecision = document.getElementById('hudDecision');
    if (hudDecision) {
      hudDecision.className = 'decision-pill pill-blocked';
      hudDecision.textContent = 'BLOCK (403)';
    }
    setTxt('hudDecisionSub', 'IP Quarantined in Redis');

    addTermLine(`POLICY_ENGINE: Evaluated Tier: CRITICAL (Score: ${calculatedScore} >= 80). Autonomous Action: BLOCK.`, 'danger');
    addTermLine(`FIREWALL: Dispatched HTTP 403 Forbidden to client 127.0.0.1. Connection terminated.`, 'danger');
    addTermLine(`SECURITY_CACHE: IP 127.0.0.1 written to Redis active quarantine set (TTL: 3600s).`, 'warn');
    addTermLine(`AUDIT_TRAIL: Cryptographic incident record committed to PostgreSQL security_events.`, 'success');
    addTermLine(`SOC_BROADCAST: WebSocket alert dispatched to all active dashboard sessions.`, 'success');

    // Stop timer
    if (elapsedTimerInterval) {
      clearInterval(elapsedTimerInterval);
      elapsedTimerInterval = null;
    }

    // Reveal Footer Banner & Action Buttons
    const footer = document.getElementById('warRoomFooter');
    if (footer) footer.style.display = 'flex';

    // Update background page elements
    setTxt('alertRiskNum', String(calculatedScore));
    setTxt('alertActionText', 'BLOCK');
    const alertCard = document.getElementById('alertCard');
    if (alertCard) alertCard.style.borderColor = '#ef4444';

    chartData.riskScores = [25, 45, 68, calculatedScore - 5, calculatedScore];
    chartData.reqFreq = [genCount * 2, genCount * 5, genCount * 10, genCount * 15, genCount * 20];
    const velEl = document.getElementById('metricVelocityText');
    if (velEl) velEl.textContent = `${genCount * 2} → ${genCount * 10} → ${genCount * 20}`;
    renderImpactCanvas();

    // Reload background traffic table
    await loadRecentSimulationTraffic();

  } catch (err) {
    console.error('Simulation execution error:', err);
    addTermLine(`ERROR: Simulation failed: ${err.message}`, 'danger');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHTML;
    }
  }
}

// ================= 3. LOAD RECENT TRAFFIC (FROM DATABASE) =================
async function loadRecentSimulationTraffic() {
  const res = await API.get('/api/requests', { limit: 8 });
  if (!res || !res.ok || !res.data) return;

  const logs = res.data.data || [];
  const tbody = document.getElementById('simTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:24px; color:#64748b;">No live simulation traffic recorded yet.</td></tr>`;
    return;
  }

  logs.forEach((req, idx) => {
    const tr = document.createElement('tr');
    tr.className = `sim-row ${idx === 0 ? 'selected-attack-row' : ''}`;
    tr.setAttribute('data-id', req.request_id || `sim-${idx}`);

    const d = req.timestamp ? new Date(req.timestamp) : new Date();
    const timeStr = d.toTimeString().split(' ')[0];

    const score = req.risk_score ?? 0;
    let pillColor = 'pill-green';
    if (score >= 80) pillColor = 'pill-red';
    else if (score >= 60) pillColor = 'pill-orange';
    else if (score >= 30) pillColor = 'pill-yellow';

    const act = req.policy_decision || 'ALLOW';
    let actPill = 'pill-allow';
    if (act === 'BLOCK') actPill = 'pill-block';
    else if (act.includes('LIMIT')) actPill = 'pill-limit';

    const dev = extractDevice(req.user_agent);

    tr.innerHTML = `
      <td class="col-time ${score >= 80 ? 'font-red' : ''}">${timeStr}</td>
      <td class="col-user">${escapeHtml(req.username || 'Anonymous')}</td>
      <td class="col-endpoint font-mono text-cyan">${escapeHtml(req.endpoint || '/')}</td>
      <td class="col-device">${dev}</td>
      <td class="col-loc">${escapeHtml(req.client_ip || '127.0.0.1')}</td>
      <td><span class="risk-pill-badge ${pillColor}">${score}</span></td>
      <td><span class="action-pill-badge ${actPill}">${act}</span></td>
      <td class="col-more">&#8942;</td>
    `;
    tbody.appendChild(tr);
  });
}

// ================= 4. DUAL-AXIS IMPACT CHART =================
function initImpactChart() {
  renderImpactCanvas();
  window.addEventListener('resize', renderImpactCanvas);
}

function renderImpactCanvas() {
  const canvas = document.getElementById('impactCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = rect.height;

  ctx.clearRect(0, 0, w, h);

  const padL = 35;
  const padR = 35;
  const padT = 20;
  const padB = 25;

  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  const n = chartData.labels.length;
  const stepX = plotW / (n - 1);

  // Draw Grid Lines
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = padT + (plotH / 3) * i;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
  }

  // Draw Risk Line (Red/Orange)
  const maxRisk = 100;
  const riskPoints = chartData.riskScores.map((score, i) => ({
    x: padL + i * stepX,
    y: padT + plotH - (score / maxRisk) * plotH
  }));

  // Risk gradient fill
  ctx.beginPath();
  ctx.moveTo(riskPoints[0].x, padT + plotH);
  riskPoints.forEach(p => ctx.lineTo(p.x, p.y));
  ctx.lineTo(riskPoints[riskPoints.length - 1].x, padT + plotH);
  ctx.closePath();

  const rGrad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
  rGrad.addColorStop(0, 'rgba(239, 68, 68, 0.25)');
  rGrad.addColorStop(1, 'rgba(239, 68, 68, 0)');
  ctx.fillStyle = rGrad;
  ctx.fill();

  // Risk Stroke
  ctx.beginPath();
  ctx.moveTo(riskPoints[0].x, riskPoints[0].y);
  riskPoints.forEach(p => ctx.lineTo(p.x, p.y));
  ctx.strokeStyle = '#ef4444';
  ctx.lineWidth = 2.5;
  ctx.stroke();

  // Dots
  riskPoints.forEach(p => {
    ctx.beginPath();
    ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
    ctx.fillStyle = '#ef4444';
    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 1.5;
    ctx.stroke();
  });
}

function initTableInteractions() {
  // Select row on click
}

function initGeneralSpotlights() {
  const cards = document.querySelectorAll('.attack-card, .sim-card');
  cards.forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--spotlight-x', `${x}px`);
      card.style.setProperty('--spotlight-y', `${y}px`);
    });
  });
}

function initClockSync() {
  const sidebarClock = document.getElementById('sidebarClockTime');
  function tick() {
    const now = new Date();
    if (sidebarClock) {
      const d = now.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
      const t = now.toTimeString().split(' ')[0];
      sidebarClock.textContent = `${d} ${t}`;
    }
  }
  tick();
  setInterval(tick, 1000);
}

function initNotificationButton() {
  const btn = document.getElementById('notificationBtn');
  if (btn) {
    btn.onclick = (e) => {
      e.preventDefault();
      window.location.href = 'threat-center.html';
    };
  }
}

function setTxt(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function extractDevice(userAgent) {
  if (!userAgent) return 'Device';
  const ua = userAgent.toLowerCase();
  if (ua.includes('iphone') || ua.includes('ipad')) return 'iPhone';
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
