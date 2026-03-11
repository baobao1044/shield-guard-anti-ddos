// ============================================================================
// Dashboard - Inline HTML + API endpoints
// ============================================================================

import * as http from 'http';
import { AntiDDoSShield } from '../core/shield';
import { UnderAttackMode } from '../layers/uam';

// uam is optional - set after server starts
let _uam: UnderAttackMode | null = null;
export function setUAM(uam: UnderAttackMode): void { _uam = uam; }

export function handleDashboardAPI(url: string, shield: AntiDDoSShield, res: http.ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

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
    const limit = parseInt(new URL('http://x' + url).searchParams.get('limit') ?? '50');
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
  <title>Shield Guard - Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #0a0a0f; color: #c9d1d9; min-height: 100vh; }

    header { background: #161b22; border-bottom: 1px solid #21262d; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
    header h1 { font-size: 20px; color: #58a6ff; display: flex; align-items: center; gap: 10px; }
    .status-dot { width: 10px; height: 10px; border-radius: 50%; background: #3fb950; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.4; } }
    .last-update { font-size: 12px; color: #8b949e; }

    main { padding: 24px; max-width: 1400px; margin: 0 auto; }

    .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 16px; }

    .card { background: #161b22; border: 1px solid #21262d; border-radius: 12px; padding: 20px; }
    .card-title { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .card-value { font-size: 32px; font-weight: 700; color: #c9d1d9; }
    .card-sub { font-size: 12px; color: #8b949e; margin-top: 4px; }

    .card.green .card-value { color: #3fb950; }
    .card.red .card-value { color: #f85149; }
    .card.yellow .card-value { color: #d29922; }
    .card.blue .card-value { color: #58a6ff; }

    .threat-bar { display: flex; gap: 4px; margin-top: 16px; align-items: flex-end; height: 40px; }
    .bar-seg { flex: 1; border-radius: 3px 3px 0 0; min-height: 4px; transition: height 0.3s; }

    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 8px 12px; color: #8b949e; border-bottom: 1px solid #21262d; font-weight: 500; }
    td { padding: 8px 12px; border-bottom: 1px solid #161b22; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #1c2128; }

    .badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; }
    .badge-l3 { background: #1f3a5f; color: #58a6ff; }
    .badge-l7 { background: #3a1f5f; color: #c084fc; }
    .badge-l4 { background: #1f3a2f; color: #3fb950; }

    .rps-display { font-size: 48px; font-weight: 800; color: #58a6ff; margin: 8px 0; }
    .emergency { color: #f85149 !important; animation: flash 0.5s infinite; }
    @keyframes flash { 0%,100% { opacity:1; } 50% { opacity:.3; } }

    .layer-stats { display: flex; gap: 16px; margin-top: 12px; }
    .layer-stat { flex: 1; text-align: center; padding: 12px; background: #0d1117; border-radius: 8px; }
    .layer-stat-val { font-size: 22px; font-weight: 700; }
    .layer-stat-lbl { font-size: 11px; color: #8b949e; margin-top: 4px; }

    .progress { background: #21262d; border-radius: 4px; height: 8px; overflow: hidden; margin-top: 8px; }
    .progress-fill { height: 100%; border-radius: 4px; transition: width 0.5s; }

    footer { text-align: center; padding: 20px; color: #484f58; font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <h1>
      <span>🛡️</span>
      Shield Guard
    </h1>
    <div style="display:flex;align-items:center;gap:12px">
      <div class="status-dot" id="statusDot"></div>
      <span class="last-update" id="lastUpdate">Connecting...</span>
    </div>
  </header>

  <main>
    <!-- Top stat cards -->
    <div class="grid-4">
      <div class="card blue">
        <div class="card-title">Current RPS</div>
        <div class="rps-display" id="currentRps">--</div>
        <div class="card-sub" id="totalPackets">Total: --</div>
      </div>
      <div class="card green">
        <div class="card-title">Allowed</div>
        <div class="card-value" id="totalAllowed">--</div>
        <div class="card-sub">
          <div class="progress"><div class="progress-fill" id="allowedBar" style="background:#3fb950;width:0%"></div></div>
        </div>
      </div>
      <div class="card red">
        <div class="card-title">Dropped</div>
        <div class="card-value" id="totalDropped">--</div>
        <div class="card-sub">
          <div class="progress"><div class="progress-fill" id="droppedBar" style="background:#f85149;width:0%"></div></div>
        </div>
      </div>
      <div class="card yellow">
        <div class="card-title">Rate Limited</div>
        <div class="card-value" id="totalRateLimited">--</div>
        <div class="card-sub">
          <div class="progress"><div class="progress-fill" id="rateLimitedBar" style="background:#d29922;width:0%"></div></div>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <!-- Threats by Layer -->
      <div class="card">
        <div class="card-title">Threats by Layer</div>
        <div class="layer-stats">
          <div class="layer-stat">
            <div class="layer-stat-val" style="color:#58a6ff" id="l3Threats">--</div>
            <div class="layer-stat-lbl">L3 Network</div>
          </div>
          <div class="layer-stat">
            <div class="layer-stat-val" style="color:#3fb950" id="l4Threats">--</div>
            <div class="layer-stat-lbl">L4 Transport</div>
          </div>
          <div class="layer-stat">
            <div class="layer-stat-val" style="color:#c084fc" id="l7Threats">--</div>
            <div class="layer-stat-lbl">L7 Application</div>
          </div>
        </div>
        <div style="margin-top:16px">
          <div class="card-title">Processing Time</div>
          <div style="font-size:24px;font-weight:700;color:#d29922" id="avgProcessingTime">-- µs</div>
          <div class="card-sub">Average per request</div>
        </div>
        <div style="margin-top:16px">
          <div class="card-title">Uptime</div>
          <div style="font-size:20px;font-weight:700" id="uptime">--</div>
        </div>
      </div>

      <!-- Top Attack Vectors -->
      <div class="card">
        <div class="card-title">Top Attack Vectors</div>
        <table id="vectorTable">
          <thead>
            <tr>
              <th>Layer</th>
              <th>Vector</th>
              <th style="text-align:right">Count</th>
            </tr>
          </thead>
          <tbody id="vectorBody">
            <tr><td colspan="3" style="color:#484f58;text-align:center;padding:24px">No attacks detected</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </main>

  <footer>Shield Guard — refreshing every 2s</footer>

  <script>
    function fmt(n) {
      if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
      if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
      return n?.toString() ?? '--';
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

    async function refresh() {
      try {
        const r = await fetch('/shield-api/metrics');
        const d = await r.json();

        document.getElementById('currentRps').textContent = Math.round(d.currentRPS);
        document.getElementById('totalPackets').textContent = 'Total: ' + fmt(d.totalPackets);
        document.getElementById('totalAllowed').textContent = fmt(d.totalAllowed);
        document.getElementById('totalDropped').textContent = fmt(d.totalDropped);
        document.getElementById('totalRateLimited').textContent = fmt(d.totalRateLimited);
        document.getElementById('l3Threats').textContent = fmt(d.threatsByLayer.l3);
        document.getElementById('l4Threats').textContent = fmt(d.threatsByLayer.l4);
        document.getElementById('l7Threats').textContent = fmt(d.threatsByLayer.l7);
        document.getElementById('avgProcessingTime').textContent = d.avgProcessingTimeUs.toFixed(1) + ' µs';
        document.getElementById('uptime').textContent = fmtUptime(d.uptimeMs);

        const total = d.totalPackets || 1;
        document.getElementById('allowedBar').style.width = (d.totalAllowed/total*100) + '%';
        document.getElementById('droppedBar').style.width = (d.totalDropped/total*100) + '%';
        document.getElementById('rateLimitedBar').style.width = (d.totalRateLimited/total*100) + '%';

        if (d.topAttackVectors && d.topAttackVectors.length > 0) {
          const rows = d.topAttackVectors.map(v => {
            const [layer, ...rest] = v.vector.split(':');
            const lbl = layer.toLowerCase();
            return '<tr><td><span class="badge badge-' + lbl + '">' + layer + '</span></td><td>' + rest.join(':') + '</td><td style="text-align:right;font-weight:700">' + fmt(v.count) + '</td></tr>';
          }).join('');
          document.getElementById('vectorBody').innerHTML = rows;
        }

        document.getElementById('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
        document.getElementById('statusDot').style.background = '#3fb950';
      } catch(e) {
        document.getElementById('lastUpdate').textContent = 'Connection error';
        document.getElementById('statusDot').style.background = '#f85149';
      }
    }

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>`;
}
