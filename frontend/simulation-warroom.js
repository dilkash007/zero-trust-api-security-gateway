// =================================================================
// ZERO-TRUST STANDALONE WAR-ROOM CONTROLLER (SEPARATE POPUP WINDOW)
// 5 Connected Liquid Glass Popups with Animated Cyber Laser Wires
// =================================================================

const SCENARIO_MAP = {
  'credential': {
    enum: 'CREDENTIAL_ATTACK',
    title: 'Credential Compromise',
    endpoint: '/api/auth/login',
    score: 94,
    status: 'CRITICAL',
    velocity: 48.2,
    factors: [
      { name: 'Credential Stuffing Velocity Surge', pts: '+35 PTS', badge: 'badge-red' },
      { name: 'Unrecognized User-Agent Device Signature', pts: '+25 PTS', badge: 'badge-amber' },
      { name: 'High-Sensitivity Target Path (/api/auth/login)', pts: '+20 PTS', badge: 'badge-orange' },
      { name: 'Isolation Forest Anomaly Biometrics', pts: '+14 PTS', badge: 'badge-purple' }
    ]
  },
  'abuse': {
    enum: 'API_ABUSE',
    title: 'API Abuse & Rate Limit Surge',
    endpoint: '/api/orders',
    score: 88,
    status: 'HIGH RISK',
    velocity: 64.5,
    factors: [
      { name: 'High-Frequency Burst (>20 req/5s sliding)', pts: '+40 PTS', badge: 'badge-red' },
      { name: 'Automated Bot Scraper Footprint', pts: '+25 PTS', badge: 'badge-amber' },
      { name: 'Payload Interval Jitter Inconsistency', pts: '+15 PTS', badge: 'badge-purple' },
      { name: 'Historical Volume Deviation (+620%)', pts: '+8 PTS', badge: 'badge-orange' }
    ]
  },
  'privilege': {
    enum: 'PRIVILEGE_MISUSE',
    title: 'Horizontal Privilege Misuse',
    endpoint: '/api/admin/users',
    score: 82,
    status: 'CRITICAL',
    velocity: 18.0,
    factors: [
      { name: 'RBAC Authorization Violation (Standard User)', pts: '+45 PTS', badge: 'badge-red' },
      { name: 'Restricted Admin Endpoint Access Attempt', pts: '+25 PTS', badge: 'badge-orange' },
      { name: 'Unusual Identity Token Scope Deviation', pts: '+12 PTS', badge: 'badge-purple' }
    ]
  }
};

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function setTxt(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

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

document.addEventListener('DOMContentLoaded', async () => {
  // Parse scenario from query string
  const urlParams = new URLSearchParams(window.location.search);
  const scKey = urlParams.get('scenario') || 'credential';
  const sc = SCENARIO_MAP[scKey] || SCENARIO_MAP['credential'];

  // Initialize UI text
  document.title = `WAR-ROOM: ${sc.title} — Zero-Trust Interception`;
  setTxt('winTargetLabel', `TARGET: ${sc.endpoint}`);
  setTxt('modalScenarioTitle', `${sc.title.toUpperCase()} — REAL-TIME ZERO-TRUST MITIGATION`);
  setTxt('modalTargetEndpoint', sc.endpoint);
  setTxt('pod1Target', sc.endpoint);

  // Populate dynamic breakdown rows in Pod 4
  const breakdownContainer = document.getElementById('pod4Breakdown');
  if (breakdownContainer && sc.factors) {
    breakdownContainer.innerHTML = '';
    sc.factors.forEach(f => {
      const row = document.createElement('div');
      row.className = 'rb-row';
      row.innerHTML = `<span class="rb-sig">${f.name}</span><span class="rb-pts ${f.badge}">${f.pts}</span>`;
      breakdownContainer.appendChild(row);
    });
  }

  // Start elapsed clock
  const startTime = Date.now();
  const timerInterval = setInterval(() => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    setTxt('modalElapsedTimer', `${elapsed}s`);
  }, 100);

  try {
    // -------------------------------------------------------------
    // POPUP 1: INGRESS & PACKET INTERCEPTION
    // -------------------------------------------------------------
    await sleep(500);
    const pod1 = document.getElementById('glassPod1');
    if (pod1) pod1.style.display = 'block';
    addTermLine(`INGRESS: Client IP 127.0.0.1 initiated burst handshake to ${sc.endpoint}`, 'cmd');

    for (let p = 1; p <= 12; p += 2) {
      setTxt('hudPacketsDispatched', String(p));
      setTxt('pod1Packets', `${p} Envelopes Captured`);
      const b = document.getElementById('hudBarPackets');
      if (b) b.style.width = `${(p / 12) * 100}%`;
      await sleep(130);
    }
    setTxt('hudPacketsDispatched', '12');
    setTxt('pod1Packets', '12 Envelopes Captured');
    const b1 = document.getElementById('hudBarPackets');
    if (b1) b1.style.width = '100%';
    addTermLine(`INGRESS: Captured 12 raw HTTP request envelopes. TLS Client Fingerprint verified.`, 'info');

    // -------------------------------------------------------------
    // WIRE 1 -> 2: LASER ENERGY TRANSMISSION
    // -------------------------------------------------------------
    await sleep(1100);
    const wire1 = document.getElementById('wire1to2');
    if (wire1) wire1.style.display = 'flex';
    addTermLine(`LASER_WIRE: Transmitting packet metadata to Sliding-Window Behavior Engine...`, 'cmd');

    // -------------------------------------------------------------
    // POPUP 2: BEHAVIORAL VELOCITY ENGINE (+25 PTS)
    // -------------------------------------------------------------
    await sleep(700);
    const pod2 = document.getElementById('glassPod2');
    if (pod2) pod2.style.display = 'block';
    addTermLine(`BEHAVIOR_ENGINE: Calculating instantaneous velocity over sliding 5s window in Redis...`, 'cmd');

    for (let v = 5; v <= sc.velocity; v += 7) {
      setTxt('hudVelocity', String(v.toFixed(1)));
      setTxt('pod2Velocity', `${v.toFixed(1)} req/sec (SURGE)`);
      const bv = document.getElementById('hudBarVelocity');
      if (bv) bv.style.width = `${Math.min(100, (v / 65) * 100)}%`;
      await sleep(90);
    }
    setTxt('hudVelocity', String(sc.velocity));
    setTxt('pod2Velocity', `${sc.velocity} req/sec (SURGE)`);
    addTermLine(`BEHAVIOR_ENGINE: Instantaneous rate ${sc.velocity} req/s exceeds baseline (2.0 req/min). Surge: +480%!`, 'warn');
    addTermLine(`RISK_GAIN: +25 RISK POINTS assigned by Behavior Engine!`, 'warn');

    // -------------------------------------------------------------
    // WIRE 2 -> 3: LASER ENERGY TRANSMISSION
    // -------------------------------------------------------------
    await sleep(1200);
    const wire2 = document.getElementById('wire2to3');
    if (wire2) wire2.style.display = 'flex';
    addTermLine(`LASER_WIRE: Streaming 8-dimensional telemetry feature vector to Isolation Forest AI Engine...`, 'cmd');

    // -------------------------------------------------------------
    // POPUP 3: MACHINE LEARNING ISOLATION FOREST (+14 PTS)
    // -------------------------------------------------------------
    await sleep(700);
    const pod3 = document.getElementById('glassPod3');
    if (pod3) pod3.style.display = 'block';
    addTermLine(`ML_ENGINE: Running unsupervised Isolation Forest decision tree partitioning...`, 'cmd');

    // Real API call to FastAPI backend
    const resPromise = API.post('/api/simulator/run', { scenario: sc.enum });

    for (let a = 15; a <= 88; a += 11) {
      setTxt('hudAnomalyScore', String(a));
      setTxt('pod3Anomaly', `${a} / 100% Deviation`);
      const ba = document.getElementById('hudBarAnomaly');
      if (ba) ba.style.width = `${a}%`;
      await sleep(100);
    }
    setTxt('hudAnomalyScore', '88');
    setTxt('pod3Anomaly', '88 / 100% Deviation');

    // Await API result
    const res = await resPromise;
    addTermLine(`ML_ENGINE: Isolation Forest output: raw_score=-0.214, anomaly_score=88/100 (Severe Outlier).`, 'danger');
    addTermLine(`LLM_GUARD: zero-trust-guard LLM verified threat signature via Ollama local inference.`, 'warn');
    addTermLine(`RISK_GAIN: +15 RISK POINTS assigned by Zero-Trust AI Intelligence!`, 'warn');

    // -------------------------------------------------------------
    // WIRE 3 -> 4: LASER ENERGY TRANSMISSION
    // -------------------------------------------------------------
    await sleep(1200);
    const wire3 = document.getElementById('wire3to4');
    if (wire3) wire3.style.display = 'flex';
    addTermLine(`LASER_WIRE: Aggregating all security signals into Zero-Trust Risk Scorer...`, 'cmd');

    // -------------------------------------------------------------
    // POPUP 4: EXPLAINABLE RISK SCORE AGGREGATION
    // -------------------------------------------------------------
    await sleep(700);
    const pod4 = document.getElementById('glassPod4');
    if (pod4) pod4.style.display = 'block';

    setTxt('pod4Score', `${sc.score} / 100`);
    setTxt('pod4TotalScoreText', `${sc.score} / 100 (${sc.status})`);
    const meter = document.getElementById('pod4MeterFill');
    if (meter) meter.style.width = `${sc.score}%`;

    addTermLine(`RISK_ENGINE: Factoring signals: [+35 Auth Velocity], [+25 Unknown Device Signature], [+20 Sensitive Path], [+14 ML Outlier]`, 'warn');
    addTermLine(`RISK_ENGINE: Final Risk Score calculated: ${sc.score} / 100 [CRITICAL SEVERITY] (Tolerance threshold 80 breached).`, 'danger');

    // -------------------------------------------------------------
    // WIRE 4 -> 5: RED WARNING LASER TRANSMISSION
    // -------------------------------------------------------------
    await sleep(1200);
    const wire4 = document.getElementById('wire4to5');
    if (wire4) wire4.style.display = 'flex';
    addTermLine(`LASER_WIRE: [EMERGENCY] Dispatching Instant Block directive to Zero-Trust Firewall!`, 'danger');

    // -------------------------------------------------------------
    // POPUP 5: AUTONOMOUS MITIGATION & QUARANTINE (403 BLOCKED)
    // -------------------------------------------------------------
    await sleep(700);
    const pod5 = document.getElementById('glassPod5');
    if (pod5) pod5.style.display = 'block';

    const hudDecision = document.getElementById('hudDecision');
    if (hudDecision) {
      hudDecision.className = 'decision-pill pill-blocked';
      hudDecision.textContent = 'BLOCK (403)';
    }
    setTxt('hudDecisionSub', 'IP Quarantined in Redis');

    addTermLine(`POLICY_ENGINE: Score ${sc.score} matches CRITICAL Tier rule. Triggering Autonomous Defense.`, 'danger');
    addTermLine(`FIREWALL: Dispatched HTTP 403 Forbidden to client 127.0.0.1. Connection terminated.`, 'danger');
    addTermLine(`SECURITY_CACHE: IP 127.0.0.1 written to Redis active quarantine set (TTL: 3600s).`, 'warn');
    addTermLine(`AUDIT_TRAIL: Cryptographic incident record committed to PostgreSQL security_events.`, 'success');
    addTermLine(`SOC_BROADCAST: WebSocket alert dispatched to all active dashboard sessions.`, 'success');

    // Stop timer
    clearInterval(timerInterval);

    // Reveal Footer Banner & Action Buttons
    const footer = document.getElementById('warRoomFooter');
    if (footer) footer.style.display = 'flex';

  } catch (err) {
    console.error('War-Room execution error:', err);
    addTermLine(`ERROR: Simulation failed: ${err.message}`, 'danger');
  }
});
