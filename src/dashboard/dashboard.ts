// ============================================================================
// Dashboard - Inline HTML + API endpoints
// ============================================================================

import * as http from 'http';
import { AntiDDoSShield } from '../core/shield';
import { UnderAttackMode } from '../layers/uam';

let _uam: UnderAttackMode | null = null;
export function setUAM(uam: UnderAttackMode): void { _uam = uam; }

function setJSONHeaders(res: http.ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json');
}

export function handleDashboardAPI(url: string, shield: AntiDDoSShield, res: http.ServerResponse): void {
  setJSONHeaders(res);

  if (url === '/shield-api/metrics') {
    res.writeHead(200);
    res.end(JSON.stringify({
      ...shield.getMetrics(),
      uamActive: _uam?.isActive() ?? false,
    }));
    return;
  }

  if (url === '/shield-api/stats') {
    res.writeHead(200);
    res.end(JSON.stringify(shield.getLayerStats()));
    return;
  }

  if (url.startsWith('/shield-api/events')) {
    const limit = parseInt(new URL('http://x' + url).searchParams.get('limit') ?? '50', 10);
    res.writeHead(200);
    res.end(JSON.stringify(shield.getRecentEvents(Math.min(limit, 200))));
    return;
  }

  if (url === '/shield-api/uam/on') {
    _uam?.activate();
    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, uamActive: true }));
    return;
  }

  if (url === '/shield-api/uam/off') {
    _uam?.deactivate();
    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, uamActive: false }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
}

export function renderDashboard(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Shield Guard Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0b1220;
      --panel: #111a2b;
      --panel-2: #0f1726;
      --border: #21324d;
      --text: #dbe7ff;
      --muted: #8ea3c6;
      --blue: #6cb8ff;
      --green: #50d890;
      --red: #ff6b6b;
      --yellow: #f4c95d;
      --orange: #ff9f43;
      --cyan: #6ef3ff;
    }
    body {
      font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(circle at top, #12213a 0%, var(--bg) 55%);
      color: var(--text);
      min-height: 100vh;
    }
    header {
      padding: 18px 24px;
      border-bottom: 1px solid var(--border);
      background: rgba(10, 18, 32, 0.92);
      backdrop-filter: blur(12px);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      position: sticky;
      top: 0;
    }
    h1 {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 20px;
      letter-spacing: 0.02em;
    }
    .status-row {
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--muted);
      font-size: 12px;
    }
    .dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: var(--green);
      box-shadow: 0 0 0 0 rgba(80, 216, 144, 0.35);
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse {
      0%, 100% { box-shadow: 0 0 0 0 rgba(80, 216, 144, 0.35); }
      60% { box-shadow: 0 0 0 9px rgba(80, 216, 144, 0); }
    }
    main {
      max-width: 1460px;
      margin: 0 auto;
      padding: 24px;
      display: grid;
      gap: 18px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
    }
    .split {
      display: grid;
      grid-template-columns: minmax(360px, 1fr) minmax(360px, 1.4fr);
      gap: 16px;
    }
    .panel {
      background: linear-gradient(180deg, rgba(17, 26, 43, 0.98), rgba(15, 23, 38, 0.98));
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 16px 50px rgba(0, 0, 0, 0.18);
    }
    .title {
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      margin-bottom: 10px;
    }
    .value {
      font-size: 34px;
      font-weight: 800;
      line-height: 1;
    }
    .sub {
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
    }
    .rps { color: var(--blue); }
    .good { color: var(--green); }
    .bad { color: var(--red); }
    .warn { color: var(--yellow); }
    .stack {
      display: grid;
      gap: 12px;
    }
    .pill-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }
    .pill {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
      color: var(--muted);
      background: rgba(255, 255, 255, 0.02);
    }
    .pill.active {
      color: var(--text);
      border-color: rgba(244, 201, 93, 0.4);
      background: rgba(244, 201, 93, 0.12);
    }
    .pill.danger {
      color: #ffd7d7;
      border-color: rgba(255, 107, 107, 0.4);
      background: rgba(255, 107, 107, 0.12);
    }
    .bar-row {
      display: grid;
      gap: 10px;
      margin-top: 12px;
    }
    .bar-label {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      color: var(--muted);
    }
    .track {
      width: 100%;
      height: 8px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.06);
      overflow: hidden;
    }
    .fill {
      height: 100%;
      border-radius: inherit;
      transition: width 0.25s ease;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; }
    tbody tr:last-child td { border-bottom: none; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
    }
    .layer-l3 { color: var(--blue); background: rgba(108, 184, 255, 0.12); }
    .layer-l4 { color: var(--green); background: rgba(80, 216, 144, 0.12); }
    .layer-l7 { color: var(--cyan); background: rgba(110, 243, 255, 0.12); }
    .action-drop, .action-blackhole { color: var(--red); }
    .action-rate_limit { color: var(--yellow); }
    .action-challenge { color: var(--orange); }
    .muted { color: var(--muted); }
    .empty {
      color: var(--muted);
      text-align: center;
      padding: 24px 10px;
      font-size: 13px;
    }
    .warning {
      margin-top: 12px;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid rgba(255, 107, 107, 0.3);
      background: rgba(255, 107, 107, 0.1);
      color: #ffd7d7;
      font-size: 12px;
    }
    footer {
      text-align: center;
      color: var(--muted);
      font-size: 12px;
      padding-bottom: 24px;
    }
    @media (max-width: 980px) {
      .split { grid-template-columns: 1fr; }
      main { padding: 16px; }
      header { padding: 16px; }
    }
  </style>
</head>
<body>
  <header>
    <h1><span>Shield Guard</span></h1>
    <div class="status-row">
      <div class="dot" id="statusDot"></div>
      <span id="lastUpdate">Connecting...</span>
    </div>
  </header>

  <main>
    <section class="grid">
      <article class="panel">
        <div class="title">Current RPS</div>
        <div class="value rps" id="currentRps">--</div>
        <div class="sub" id="totalPackets">Total packets: --</div>
      </article>
      <article class="panel">
        <div class="title">Allowed</div>
        <div class="value good" id="totalAllowed">--</div>
        <div class="sub" id="allowShare">Traffic share: --</div>
      </article>
      <article class="panel">
        <div class="title">Dropped</div>
        <div class="value bad" id="totalDropped">--</div>
        <div class="sub" id="dropShare">Traffic share: --</div>
      </article>
      <article class="panel">
        <div class="title">Rate Limited / Challenged</div>
        <div class="value warn" id="totalRate">--</div>
        <div class="sub" id="challengeShare">Challenges: --</div>
      </article>
    </section>

    <section class="split">
      <article class="panel stack">
        <div>
          <div class="title">Runtime State</div>
          <div class="pill-row">
            <span class="pill" id="pillUam">UAM off</span>
            <span class="pill" id="pillEmergency">Emergency off</span>
            <span class="pill" id="pillBlacklist">Blacklist: --</span>
            <span class="pill" id="pillConns">Connections: --</span>
          </div>
          <div class="warning" id="authWarning" style="display:none">Dashboard protection is disabled. Set a password before exposing this route.</div>
        </div>
        <div>
          <div class="title">Threats By Layer</div>
          <div class="bar-row">
            <div>
              <div class="bar-label"><span>L3</span><span id="l3Threats">--</span></div>
              <div class="track"><div class="fill" id="l3Bar" style="width:0;background:var(--blue)"></div></div>
            </div>
            <div>
              <div class="bar-label"><span>L4</span><span id="l4Threats">--</span></div>
              <div class="track"><div class="fill" id="l4Bar" style="width:0;background:var(--green)"></div></div>
            </div>
            <div>
              <div class="bar-label"><span>L7</span><span id="l7Threats">--</span></div>
              <div class="track"><div class="fill" id="l7Bar" style="width:0;background:var(--cyan)"></div></div>
            </div>
          </div>
        </div>
        <div class="grid">
          <div>
            <div class="title">Peak RPS</div>
            <div class="value" style="font-size:24px" id="peakRps">--</div>
          </div>
          <div>
            <div class="title">Avg Process Time</div>
            <div class="value" style="font-size:24px" id="avgProcessingTime">--</div>
          </div>
          <div>
            <div class="title">Uptime</div>
            <div class="value" style="font-size:24px" id="uptime">--</div>
          </div>
          <div>
            <div class="title">Top Reason Code</div>
            <div class="value" style="font-size:24px" id="topReason">--</div>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="title">Top Attack Reasons</div>
        <table>
          <thead>
            <tr>
              <th>Code</th>
              <th style="text-align:right">Count</th>
            </tr>
          </thead>
          <tbody id="reasonBody">
            <tr><td class="empty" colspan="2">No attack activity yet</td></tr>
          </tbody>
        </table>
      </article>
    </section>

    <section class="split">
      <article class="panel">
        <div class="title">Top Attack Vectors</div>
        <table>
          <thead>
            <tr>
              <th>Layer</th>
              <th>Vector</th>
              <th style="text-align:right">Count</th>
            </tr>
          </thead>
          <tbody id="vectorBody">
            <tr><td class="empty" colspan="3">No attack activity yet</td></tr>
          </tbody>
        </table>
      </article>

      <article class="panel">
        <div class="title">Recent Decisions</div>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>IP</th>
              <th>Action</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody id="eventBody">
            <tr><td class="empty" colspan="4">No recent events</td></tr>
          </tbody>
        </table>
      </article>
    </section>
  </main>

  <footer>Refreshes every 2 seconds</footer>

  <script>
    const authWarning = document.getElementById('authWarning');

    function fmt(n) {
      if (n == null) return '--';
      if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
      if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
      return String(n);
    }

    function fmtPct(part, total) {
      return (((part || 0) / (total || 1)) * 100).toFixed(1) + '%';
    }

    function fmtUptime(ms) {
      const s = Math.floor(ms / 1000);
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      if (h > 0) return h + 'h ' + m + 'm ' + sec + 's';
      if (m > 0) return m + 'm ' + sec + 's';
      return sec + 's';
    }

    function esc(value) {
      return String(value ?? '').replace(/[&<>"]/g, function(ch) {
        return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch];
      });
    }

    function actionClass(action) {
      return 'action-' + String(action || '').toLowerCase();
    }

    function layerClass(layer) {
      return 'layer-' + String(layer || '').toLowerCase();
    }

    async function refresh() {
      try {
        const [metricsRes, eventsRes] = await Promise.all([
          fetch('/shield-api/metrics', { cache: 'no-store' }),
          fetch('/shield-api/events?limit=20', { cache: 'no-store' })
        ]);
        const metrics = await metricsRes.json();
        const events = await eventsRes.json();

        const total = metrics.totalPackets || 1;
        const reasons = Array.isArray(metrics.topReasonCodes) ? metrics.topReasonCodes : [];
        const vectors = Array.isArray(metrics.topAttackVectors) ? metrics.topAttackVectors : [];

        document.getElementById('currentRps').textContent = fmt(Math.round(metrics.currentRPS || 0));
        document.getElementById('totalPackets').textContent = 'Total packets: ' + fmt(metrics.totalPackets || 0);
        document.getElementById('totalAllowed').textContent = fmt(metrics.totalAllowed || 0);
        document.getElementById('totalDropped').textContent = fmt(metrics.totalDropped || 0);
        document.getElementById('totalRate').textContent = fmt(metrics.totalRateLimited || 0);
        document.getElementById('allowShare').textContent = 'Traffic share: ' + fmtPct(metrics.totalAllowed, total);
        document.getElementById('dropShare').textContent = 'Traffic share: ' + fmtPct(metrics.totalDropped, total);
        document.getElementById('challengeShare').textContent = 'Challenges: ' + fmt(metrics.totalChallenged || 0);
        document.getElementById('peakRps').textContent = fmt(Math.round(metrics.peakRPS || 0));
        document.getElementById('avgProcessingTime').textContent = (metrics.avgProcessingTimeUs || 0).toFixed(1) + ' us';
        document.getElementById('uptime').textContent = fmtUptime(metrics.uptimeMs || 0);
        document.getElementById('topReason').textContent = reasons[0] ? esc(reasons[0].code) : '--';

        const layerTotals = metrics.threatsByLayer || { l3: 0, l4: 0, l7: 0 };
        const maxThreat = Math.max(layerTotals.l3 || 0, layerTotals.l4 || 0, layerTotals.l7 || 0, 1);
        document.getElementById('l3Threats').textContent = fmt(layerTotals.l3 || 0);
        document.getElementById('l4Threats').textContent = fmt(layerTotals.l4 || 0);
        document.getElementById('l7Threats').textContent = fmt(layerTotals.l7 || 0);
        document.getElementById('l3Bar').style.width = ((layerTotals.l3 || 0) / maxThreat * 100) + '%';
        document.getElementById('l4Bar').style.width = ((layerTotals.l4 || 0) / maxThreat * 100) + '%';
        document.getElementById('l7Bar').style.width = ((layerTotals.l7 || 0) / maxThreat * 100) + '%';

        const pillUam = document.getElementById('pillUam');
        pillUam.textContent = metrics.uamActive ? 'UAM on' : 'UAM off';
        pillUam.className = 'pill' + (metrics.uamActive ? ' active danger' : '');

        const pillEmergency = document.getElementById('pillEmergency');
        pillEmergency.textContent = metrics.emergencyMode ? 'Emergency on' : 'Emergency off';
        pillEmergency.className = 'pill' + (metrics.emergencyMode ? ' danger' : '');

        document.getElementById('pillBlacklist').textContent = 'Blacklist: ' + fmt(metrics.blacklistedIPs || 0);
        document.getElementById('pillConns').textContent = 'Connections: ' + fmt(metrics.activeConnections || 0);

        const reasonBody = document.getElementById('reasonBody');
        reasonBody.innerHTML = reasons.length
          ? reasons.map(item => '<tr><td>' + esc(item.code) + '</td><td style="text-align:right;font-weight:700">' + fmt(item.count) + '</td></tr>').join('')
          : '<tr><td class="empty" colspan="2">No attack activity yet</td></tr>';

        const vectorBody = document.getElementById('vectorBody');
        vectorBody.innerHTML = vectors.length
          ? vectors.map(item => {
              const parts = String(item.vector || '').split(':');
              const layer = parts.shift() || 'N/A';
              const vector = parts.join(':') || item.vector;
              return '<tr><td><span class="badge ' + layerClass(layer) + '">' + esc(layer) + '</span></td><td>' + esc(vector) + '</td><td style="text-align:right;font-weight:700">' + fmt(item.count) + '</td></tr>';
            }).join('')
          : '<tr><td class="empty" colspan="3">No attack activity yet</td></tr>';

        const eventBody = document.getElementById('eventBody');
        eventBody.innerHTML = Array.isArray(events) && events.length
          ? events.map(event => {
              const action = esc(event.action || 'N/A');
              const reasonCode = event.reasonCode ? ' [' + esc(event.reasonCode) + ']' : '';
              const detail = event.path || event.url || event.reason || '';
              return '<tr>' +
                '<td class="muted">' + esc(new Date(event.ts).toLocaleTimeString()) + '</td>' +
                '<td>' + esc(event.ip || '-') + '</td>' +
                '<td class="' + actionClass(event.action) + '">' + action + '</td>' +
                '<td><div>' + esc(event.reason || '-') + reasonCode + '</div><div class="muted">' + esc(detail) + '</div></td>' +
              '</tr>';
            }).join('')
          : '<tr><td class="empty" colspan="4">No recent events</td></tr>';

        authWarning.style.display = metrics.dashboardAuthEnabled === false ? 'block' : 'none';
        document.getElementById('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
        document.getElementById('statusDot').style.background = '#50d890';
      } catch (_error) {
        document.getElementById('lastUpdate').textContent = 'Connection error';
        document.getElementById('statusDot').style.background = '#ff6b6b';
      }
    }

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>`;
}
