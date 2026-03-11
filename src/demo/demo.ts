// ============================================================================
// Shield Guard - Web Demo / Attack Playground
// ============================================================================

export function renderDemoPage(baseUrl: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Shield Guard — Attack Playground</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;--border:#30363d;
      --text:#c9d1d9;--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;
      --red:#f85149;--yellow:#d29922;--purple:#c084fc;--orange:#fb8500;
    }
    body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}

    /* Header */
    header{background:var(--bg2);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
    .logo{display:flex;align-items:center;gap:10px;font-size:18px;font-weight:700;color:var(--blue)}
    .logo span{font-size:22px}
    .badges{display:flex;gap:8px}
    .badge{padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
    .badge-live{background:#1a3a1a;color:var(--green);border:1px solid #2a5a2a;display:flex;align-items:center;gap:5px}
    .dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite}
    @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(0.8)}}
    .badge-uam-off{background:#1a1a3a;color:var(--muted);border:1px solid var(--border)}
    .badge-uam-on{background:#3a1a1a;color:var(--red);border:1px solid #5a2a2a;animation:flash 1s infinite}
    @keyframes flash{0%,100%{opacity:1}50%{opacity:.6}}

    /* Layout */
    .layout{display:grid;grid-template-columns:380px 1fr;gap:0;height:calc(100vh - 53px)}

    /* Left panel - controls */
    .panel-left{background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;display:flex;flex-direction:column}
    .panel-section{padding:18px;border-bottom:1px solid var(--border)}
    .panel-section:last-child{border-bottom:none}
    .section-title{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}

    /* Attack config */
    .attack-types{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px}
    .attack-btn{padding:10px 8px;border:1px solid var(--border);border-radius:8px;background:var(--bg3);color:var(--text);cursor:pointer;font-size:12px;font-weight:500;text-align:center;transition:all .15s;display:flex;flex-direction:column;align-items:center;gap:4px}
    .attack-btn:hover{border-color:var(--blue);background:#1c2a3a}
    .attack-btn.active{border-color:var(--blue);background:#1c2a3a;color:var(--blue)}
    .attack-btn .icon{font-size:18px}
    .attack-btn.active-selected{border-color:var(--red);background:#2a1c1c;color:var(--red)}

    label{font-size:12px;color:var(--muted);display:block;margin-bottom:5px}
    input[type=range]{width:100%;accent-color:var(--blue);cursor:pointer}
    .range-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
    .range-val{font-size:13px;font-weight:700;color:var(--blue);min-width:50px;text-align:right}

    select{width:100%;padding:8px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;cursor:pointer;margin-bottom:12px}
    select:focus{outline:none;border-color:var(--blue)}

    .start-btn{width:100%;padding:14px;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer;transition:all .15s;display:flex;align-items:center;justify-content:center;gap:8px}
    .start-btn.idle{background:linear-gradient(135deg,#238636,#2ea043);color:#fff}
    .start-btn.idle:hover{background:linear-gradient(135deg,#2ea043,#3fb950);transform:translateY(-1px);box-shadow:0 4px 12px #2ea04340}
    .start-btn.running{background:linear-gradient(135deg,#b91c1c,#dc2626);color:#fff;animation:pulse-btn 1s infinite}
    @keyframes pulse-btn{0%,100%{box-shadow:0 0 0 0 #f8514940}50%{box-shadow:0 0 0 6px #f8514900}}

    /* Stats mini cards */
    .mini-stats{display:grid;grid-template-columns:1fr 1fr;gap:8px}
    .mini-card{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px}
    .mini-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
    .mini-value{font-size:22px;font-weight:800;margin:2px 0}
    .mini-sub{font-size:11px;color:var(--muted)}
    .c-green{color:var(--green)} .c-red{color:var(--red)} .c-blue{color:var(--blue)} .c-yellow{color:var(--yellow)} .c-purple{color:var(--purple)}

    /* Progress bar */
    .prog-row{margin-bottom:10px}
    .prog-label{display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px}
    .prog-track{height:8px;background:var(--bg3);border-radius:4px;overflow:hidden}
    .prog-fill{height:100%;border-radius:4px;transition:width .4s ease}

    /* Right panel - dstat */
    .panel-right{display:flex;flex-direction:column;overflow:hidden}

    /* RPS chart */
    .rps-section{padding:16px 20px;border-bottom:1px solid var(--border);background:var(--bg2)}
    .rps-header{display:flex;align-items:baseline;gap:12px;margin-bottom:10px}
    .rps-big{font-size:48px;font-weight:900;line-height:1;transition:color .3s}
    .rps-label{font-size:13px;color:var(--muted)}
    .rps-peak{font-size:12px;color:var(--muted)}
    #rpsCanvas{width:100%;height:80px;display:block}

    /* Threats */
    .threat-section{padding:14px 20px;border-bottom:1px solid var(--border);display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
    .threat-card{background:var(--bg2);border-radius:8px;padding:12px;text-align:center}
    .threat-val{font-size:26px;font-weight:800}
    .threat-lbl{font-size:11px;color:var(--muted);margin-top:2px}
    .threat-bar{height:3px;border-radius:2px;margin-top:8px;transition:width .4s}

    /* Vectors */
    .vectors-section{padding:14px 20px;border-bottom:1px solid var(--border);flex:0 0 auto}
    .vector-row{display:flex;align-items:center;gap:8px;margin-bottom:6px}
    .vector-layer{font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;min-width:28px;text-align:center}
    .vl-l7{background:#3a1f5f;color:var(--purple)}
    .vl-l3{background:#1f3a5f;color:var(--blue)}
    .vl-l4{background:#1f3a2f;color:var(--green)}
    .vector-name{font-size:12px;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .vector-bar-wrap{width:100px;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden}
    .vector-bar{height:100%;border-radius:3px;transition:width .3s}
    .vector-count{font-size:12px;font-weight:700;min-width:40px;text-align:right}

    /* Feed */
    .feed-section{flex:1;overflow:hidden;display:flex;flex-direction:column}
    .feed-header{padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
    .feed-title{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
    .feed-count{font-size:11px;color:var(--muted)}
    #feed{flex:1;overflow-y:auto;font-family:'Consolas','Courier New',monospace;font-size:11.5px}
    .feed-row{display:flex;gap:8px;padding:5px 20px;border-bottom:1px solid #1a1f26;align-items:center;animation:slideIn .2s ease}
    @keyframes slideIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
    .feed-row:hover{background:var(--bg3)}
    .feed-time{color:var(--muted);flex:0 0 50px}
    .feed-ip{color:var(--blue);flex:0 0 90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .feed-action{flex:0 0 70px;font-weight:700}
    .feed-action.DROP{color:var(--red)}
    .feed-action.CHALLENGE{color:var(--yellow)}
    .feed-action.RATE_LIMIT{color:var(--orange)}
    .feed-action.BLACKHOLE{color:var(--purple)}
    .feed-layer{flex:0 0 30px;color:var(--muted)}
    .feed-reason{flex:1;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .feed-url{flex:0 0 160px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right;font-size:10.5px}

    /* Threat level colors for feed */
    .tl-4{border-left:2px solid var(--red)}
    .tl-3{border-left:2px solid var(--orange)}
    .tl-2{border-left:2px solid var(--yellow)}
    .tl-1{border-left:2px solid var(--blue)}
    .tl-0{border-left:2px solid var(--border)}

    /* Scrollbar */
    ::-webkit-scrollbar{width:5px;height:5px}
    ::-webkit-scrollbar-track{background:var(--bg)}
    ::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

    @media(max-width:900px){
      .layout{grid-template-columns:1fr;grid-template-rows:auto 1fr}
      .panel-left{max-height:50vh}
    }
  </style>
</head>
<body>
<header>
  <div class="logo"><span>🛡️</span> Shield Guard — Attack Playground</div>
  <div class="badges">
    <div class="badge badge-live"><div class="dot"></div> LIVE</div>
    <div class="badge badge-uam-off" id="uamBadge">UAM OFF</div>
  </div>
</header>

<div class="layout">
  <!-- LEFT: Controls -->
  <div class="panel-left">

    <div class="panel-section">
      <div class="section-title">Attack Type</div>
      <div class="attack-types">
        <button class="attack-btn active-selected" data-type="flood" onclick="selectAttack('flood',this)">
          <span class="icon">🌊</span>Flood
        </button>
        <button class="attack-btn" data-type="sqli" onclick="selectAttack('sqli',this)">
          <span class="icon">💉</span>SQLi
        </button>
        <button class="attack-btn" data-type="xss" onclick="selectAttack('xss',this)">
          <span class="icon">🔤</span>XSS
        </button>
        <button class="attack-btn" data-type="path" onclick="selectAttack('path',this)">
          <span class="icon">📁</span>Path Traversal
        </button>
        <button class="attack-btn" data-type="bot" onclick="selectAttack('bot',this)">
          <span class="icon">🤖</span>Bot Sim
        </button>
        <button class="attack-btn" data-type="mixed" onclick="selectAttack('mixed',this)">
          <span class="icon">💥</span>Mixed
        </button>
      </div>

      <div class="range-row">
        <label>Concurrency</label>
        <span class="range-val" id="concLabel">10</span>
      </div>
      <input type="range" min="1" max="100" value="10" id="concRange" oninput="document.getElementById('concLabel').textContent=this.value">

      <div style="margin-top:12px" class="range-row">
        <label>Delay between bursts (ms)</label>
        <span class="range-val" id="delayLabel">50</span>
      </div>
      <input type="range" min="0" max="500" step="10" value="50" id="delayRange" oninput="document.getElementById('delayLabel').textContent=this.value">

      <div style="margin-top:14px">
        <button class="start-btn idle" id="startBtn" onclick="toggleAttack()">
          <span id="startIcon">▶</span> <span id="startLabel">Start Attack</span>
        </button>
      </div>

      <div style="margin-top:10px;font-size:11px;color:var(--muted);text-align:center" id="attackStatus">
        Idle — ready to launch
      </div>
    </div>

    <!-- Mini stats -->
    <div class="panel-section">
      <div class="section-title">Stats</div>
      <div class="mini-stats">
        <div class="mini-card">
          <div class="mini-label">Total</div>
          <div class="mini-value c-blue" id="sTotal">0</div>
          <div class="mini-sub">requests</div>
        </div>
        <div class="mini-card">
          <div class="mini-label">Allowed</div>
          <div class="mini-value c-green" id="sAllowed">0</div>
          <div class="mini-sub" id="sAllowedPct">—</div>
        </div>
        <div class="mini-card">
          <div class="mini-label">Blocked</div>
          <div class="mini-value c-red" id="sBlocked">0</div>
          <div class="mini-sub" id="sBlockedPct">—</div>
        </div>
        <div class="mini-card">
          <div class="mini-label">Rate Limited</div>
          <div class="mini-value c-yellow" id="sRateLimited">0</div>
          <div class="mini-sub">requests</div>
        </div>
      </div>
    </div>

    <!-- Block rate bars -->
    <div class="panel-section">
      <div class="section-title">Block Rate</div>
      <div class="prog-row">
        <div class="prog-label"><span>Allowed</span><span id="pAllowed">0%</span></div>
        <div class="prog-track"><div class="prog-fill" id="pbAllowed" style="background:var(--green);width:0%"></div></div>
      </div>
      <div class="prog-row">
        <div class="prog-label"><span>Dropped</span><span id="pBlocked">0%</span></div>
        <div class="prog-track"><div class="prog-fill" id="pbBlocked" style="background:var(--red);width:0%"></div></div>
      </div>
      <div class="prog-row">
        <div class="prog-label"><span>Rate Limited</span><span id="pRL">0%</span></div>
        <div class="prog-track"><div class="prog-fill" id="pbRL" style="background:var(--yellow);width:0%"></div></div>
      </div>
      <div class="prog-row" style="margin-bottom:0">
        <div class="prog-label"><span>Challenged</span><span id="pChallenge">0%</span></div>
        <div class="prog-track"><div class="prog-fill" id="pbChallenge" style="background:var(--purple);width:0%"></div></div>
      </div>
    </div>

    <!-- Avg processing time -->
    <div class="panel-section">
      <div class="section-title">Performance</div>
      <div style="display:flex;gap:16px">
        <div>
          <div style="font-size:11px;color:var(--muted)">Avg process time</div>
          <div style="font-size:20px;font-weight:700;color:var(--yellow)" id="sAvgTime">0 µs</div>
        </div>
        <div>
          <div style="font-size:11px;color:var(--muted)">Peak RPS</div>
          <div style="font-size:20px;font-weight:700;color:var(--blue)" id="sPeakRPS">0</div>
        </div>
        <div>
          <div style="font-size:11px;color:var(--muted)">Uptime</div>
          <div style="font-size:20px;font-weight:700" id="sUptime">0s</div>
        </div>
      </div>
    </div>

  </div>

  <!-- RIGHT: Live Dstat -->
  <div class="panel-right">

    <!-- RPS -->
    <div class="rps-section">
      <div class="rps-header">
        <div class="rps-big c-blue" id="rpsValue">0</div>
        <div>
          <div class="rps-label">req/sec</div>
          <div class="rps-peak" id="rpsPeak">peak: 0</div>
        </div>
      </div>
      <canvas id="rpsCanvas" height="80"></canvas>
    </div>

    <!-- Threat by layer -->
    <div class="threat-section">
      <div class="threat-card">
        <div class="threat-val c-blue" id="tL3">0</div>
        <div class="threat-lbl">L3 Network</div>
        <div class="threat-bar" style="background:var(--blue)" id="tbL3"></div>
      </div>
      <div class="threat-card">
        <div class="threat-val c-green" id="tL4">0</div>
        <div class="threat-lbl">L4 Transport</div>
        <div class="threat-bar" style="background:var(--green)" id="tbL4"></div>
      </div>
      <div class="threat-card">
        <div class="threat-val c-purple" id="tL7">0</div>
        <div class="threat-lbl">L7 Application</div>
        <div class="threat-bar" style="background:var(--purple)" id="tbL7"></div>
      </div>
    </div>

    <!-- Attack vectors -->
    <div class="vectors-section">
      <div class="section-title" style="margin-bottom:10px">Top Attack Vectors</div>
      <div id="vectors">
        <div style="color:var(--muted);font-size:12px">No attacks detected yet...</div>
      </div>
    </div>

    <!-- Live feed -->
    <div class="feed-section">
      <div class="feed-header">
        <span class="feed-title">Live Block Feed</span>
        <span class="feed-count" id="feedCount">0 events</span>
      </div>
      <div id="feed"></div>
    </div>

  </div>
</div>

<script>
const BASE = '${baseUrl}';
let attackType = 'flood';
let running = false;
let attackTimer = null;
let sentCount = 0;
let feedCount = 0;
let lastEventTs = 0;

// Attack payloads
const PAYLOADS = {
  flood: ['/','/?t='+Date.now(),'/api/data','/health','/home'],
  sqli: [
    "/?id=1'+OR+1=1--",
    "/?q=1;+DROP+TABLE+users--",
    "/?search=admin'--",
    "/?user=1+UNION+SELECT+*+FROM+users",
    "/?id=1'+AND+'1'='1",
  ],
  xss: [
    "/?q=<script>alert(1)</script>",
    "/?name=<img+src=x+onerror=alert(1)>",
    "/?cb=javascript:alert(document.cookie)",
    "/?r=<svg/onload=alert(1)>",
  ],
  path: [
    '/../../../etc/passwd',
    '/..%2F..%2F..%2Fetc%2Fshadow',
    '/./././etc/hosts',
    '/%2e%2e%2fetc%2fpasswd',
    '/.env',
    '/config.php',
  ],
  bot: ['/','/?v='+Date.now(),'/robots.txt','/sitemap.xml'],
  mixed: null, // special: rotate through all
};

const BOT_UAS = [
  'python-requests/2.28.0',
  'Go-http-client/1.1',
  'curl/7.85.0',
  '',  // empty UA
  'sqlmap/1.7',
  'Nikto',
];

function selectAttack(type, el) {
  attackType = type;
  document.querySelectorAll('.attack-btn').forEach(b => b.classList.remove('active-selected'));
  el.classList.add('active-selected');
}

function getPayload() {
  if (attackType === 'mixed') {
    const types = ['flood','sqli','xss','path','bot'];
    const t = types[Math.floor(Math.random()*types.length)];
    const p = PAYLOADS[t];
    return p[Math.floor(Math.random()*p.length)];
  }
  const p = PAYLOADS[attackType];
  return p[Math.floor(Math.random()*p.length)];
}

function toggleAttack() {
  running = !running;
  const btn = document.getElementById('startBtn');
  const icon = document.getElementById('startIcon');
  const label = document.getElementById('startLabel');

  if (running) {
    btn.className = 'start-btn running';
    icon.textContent = '⏹';
    label.textContent = 'Stop Attack';
    launchAttack();
  } else {
    btn.className = 'start-btn idle';
    icon.textContent = '▶';
    label.textContent = 'Start Attack';
    clearTimeout(attackTimer);
    document.getElementById('attackStatus').textContent = 'Stopped';
  }
}

async function launchAttack() {
  if (!running) return;
  const conc = parseInt(document.getElementById('concRange').value);
  const delay = parseInt(document.getElementById('delayRange').value);

  const promises = [];
  for (let i = 0; i < conc; i++) {
    const url = BASE + getPayload();
    const headers = {};
    if (attackType === 'bot') {
      headers['User-Agent'] = BOT_UAS[Math.floor(Math.random()*BOT_UAS.length)];
    }
    promises.push(fetch(url, { headers }).then(() => sentCount++).catch(() => sentCount++));
  }

  await Promise.allSettled(promises);
  document.getElementById('attackStatus').textContent = 'Sent ' + sentCount + ' requests...';

  if (running) {
    attackTimer = setTimeout(launchAttack, delay);
  }
}

// ===== RPS Canvas =====
const rpsHistory = new Array(120).fill(0);
const canvas = document.getElementById('rpsCanvas');
const ctx = canvas.getContext('2d');

function drawChart() {
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth;
  const H = canvas.offsetHeight;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  ctx.scale(dpr, dpr);

  const max = Math.max(...rpsHistory, 1);
  ctx.clearRect(0,0,W,H);

  // Grid lines
  ctx.strokeStyle = '#21262d';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = (H / 4) * i;
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke();
  }

  // Gradient fill
  const grad = ctx.createLinearGradient(0,0,0,H);
  grad.addColorStop(0, 'rgba(88,166,255,0.3)');
  grad.addColorStop(1, 'rgba(88,166,255,0)');
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.moveTo(0, H);
  rpsHistory.forEach((v,i) => {
    const x = (i / (rpsHistory.length-1)) * W;
    const y = H - (v / max) * (H-4);
    i === 0 ? ctx.lineTo(x,y) : ctx.lineTo(x,y);
  });
  ctx.lineTo(W, H);
  ctx.closePath();
  ctx.fill();

  // Line
  ctx.strokeStyle = '#58a6ff';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.beginPath();
  rpsHistory.forEach((v,i) => {
    const x = (i / (rpsHistory.length-1)) * W;
    const y = H - (v / max) * (H-4);
    i === 0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
  });
  ctx.stroke();
}

// ===== Feed =====
const MAX_FEED = 200;
const ACTION_LABEL = { DROP:'DROP', CHALLENGE:'CHALLENGE', RATE_LIMIT:'RATE LMT', BLACKHOLE:'BLACKHOLE' };
const TL_CLASS = ['tl-0','tl-1','tl-2','tl-3','tl-4'];

function appendEvent(ev) {
  const feed = document.getElementById('feed');
  const time = new Date(ev.ts).toLocaleTimeString();
  const detail = ev.path || ev.url || '';
  const reasonCode = ev.reasonCode ? ' [' + ev.reasonCode + ']' : '';
  const row = document.createElement('div');
  row.className = 'feed-row ' + (TL_CLASS[ev.threatLevel] || 'tl-0');
  const action = ev.action.replace('_',' ');
  const aClass = ev.action;
  row.innerHTML =
    '<span class="feed-time">' + time + '</span>' +
    '<span class="feed-ip">' + (ev.ip||'?') + '</span>' +
    '<span class="feed-action ' + aClass + '">' + action + '</span>' +
    '<span class="feed-layer">' + ev.layer + '</span>' +
    '<span class="feed-reason">' + ev.reason + reasonCode + '</span>' +
    '<span class="feed-url" title="' + detail + '">' + detail + '</span>';

  feed.insertBefore(row, feed.firstChild);
  feedCount++;
  document.getElementById('feedCount').textContent = feedCount + ' events';

  // Trim
  while (feed.children.length > MAX_FEED) feed.removeChild(feed.lastChild);
}

// ===== Metrics poll =====
let peakRPS = 0;

async function pollMetrics() {
  try {
    const [mRes, eRes] = await Promise.all([
      fetch(BASE + '/shield-api/metrics'),
      fetch(BASE + '/shield-api/events?limit=50'),
    ]);
    const m = await mRes.json();
    const events = await eRes.json();

    // RPS chart
    const rps = Math.round(m.currentRPS);
    rpsHistory.push(rps);
    rpsHistory.shift();
    if (rps > peakRPS) peakRPS = rps;

    // Update RPS display
    const rpsEl = document.getElementById('rpsValue');
    rpsEl.textContent = rps;
    rpsEl.style.color = rps > 1000 ? 'var(--red)' : rps > 200 ? 'var(--yellow)' : 'var(--blue)';
    document.getElementById('rpsPeak').textContent = 'peak: ' + peakRPS;
    drawChart();

    // UAM badge
    const uamEl = document.getElementById('uamBadge');
    if (m.uamActive) {
      uamEl.className = 'badge badge-uam-on';
      uamEl.textContent = '⚠ UAM ON';
    } else {
      uamEl.className = 'badge badge-uam-off';
      uamEl.textContent = 'UAM OFF';
    }

    // Stats
    document.getElementById('sTotal').textContent = fmt(m.totalPackets);
    document.getElementById('sAllowed').textContent = fmt(m.totalAllowed);
    document.getElementById('sBlocked').textContent = fmt(m.totalDropped);
    document.getElementById('sRateLimited').textContent = fmt(m.totalRateLimited);
    document.getElementById('sAvgTime').textContent = m.avgProcessingTimeUs.toFixed(1) + ' µs';
    document.getElementById('sPeakRPS').textContent = fmt(m.peakRPS);
    document.getElementById('sUptime').textContent = fmtUptime(m.uptimeMs);

    const total = m.totalPackets || 1;
    const ap = (m.totalAllowed/total*100).toFixed(1);
    const dp = (m.totalDropped/total*100).toFixed(1);
    const rp = (m.totalRateLimited/total*100).toFixed(1);
    const cp = (m.totalChallenged/total*100).toFixed(1);
    document.getElementById('sAllowedPct').textContent = ap + '%';
    document.getElementById('sBlockedPct').textContent = dp + '%';
    document.getElementById('pAllowed').textContent = ap + '%';
    document.getElementById('pBlocked').textContent = dp + '%';
    document.getElementById('pRL').textContent = rp + '%';
    document.getElementById('pChallenge').textContent = cp + '%';
    document.getElementById('pbAllowed').style.width = ap + '%';
    document.getElementById('pbBlocked').style.width = dp + '%';
    document.getElementById('pbRL').style.width = rp + '%';
    document.getElementById('pbChallenge').style.width = cp + '%';

    // Layer threats
    const tl = m.threatsByLayer;
    const maxT = Math.max(tl.l3, tl.l4, tl.l7, 1);
    document.getElementById('tL3').textContent = fmt(tl.l3);
    document.getElementById('tL4').textContent = fmt(tl.l4);
    document.getElementById('tL7').textContent = fmt(tl.l7);
    document.getElementById('tbL3').style.width = (tl.l3/maxT*100)+'%';
    document.getElementById('tbL4').style.width = (tl.l4/maxT*100)+'%';
    document.getElementById('tbL7').style.width = (tl.l7/maxT*100)+'%';

    // Attack vectors
    if (m.topAttackVectors && m.topAttackVectors.length > 0) {
      const maxV = m.topAttackVectors[0].count || 1;
      const html = m.topAttackVectors.slice(0,5).map(v => {
        const [layer, ...rest] = v.vector.split(':');
        const name = rest.join(':').trim();
        const pct = (v.count/maxV*100).toFixed(0);
        const lbl = layer.toLowerCase();
        const barColor = lbl==='l7'?'var(--purple)':lbl==='l3'?'var(--blue)':'var(--green)';
        return '<div class="vector-row">' +
          '<span class="vector-layer vl-'+lbl+'">'+layer+'</span>' +
          '<span class="vector-name">'+name+'</span>' +
          '<div class="vector-bar-wrap"><div class="vector-bar" style="width:'+pct+'%;background:'+barColor+'"></div></div>' +
          '<span class="vector-count c-'+lbl+'">'+fmt(v.count)+'</span>' +
          '</div>';
      }).join('');
      document.getElementById('vectors').innerHTML = html;
    } else if (m.topReasonCodes && m.topReasonCodes.length > 0) {
      const maxV = m.topReasonCodes[0].count || 1;
      const html = m.topReasonCodes.slice(0,5).map(v => {
        const pct = (v.count/maxV*100).toFixed(0);
        return '<div class="vector-row">' +
          '<span class="vector-layer vl-l7">RC</span>' +
          '<span class="vector-name">' + v.code + '</span>' +
          '<div class="vector-bar-wrap"><div class="vector-bar" style="width:'+pct+'%;background:var(--orange)"></div></div>' +
          '<span class="vector-count c-yellow">'+fmt(v.count)+'</span>' +
          '</div>';
      }).join('');
      document.getElementById('vectors').innerHTML = html;
    } else {
      document.getElementById('vectors').innerHTML = '<div style="color:var(--muted);font-size:12px">No attacks detected yet...</div>';
    }

    // New events
    const newEvents = events.filter(e => e.ts > lastEventTs);
    if (newEvents.length > 0) {
      lastEventTs = newEvents[0].ts;
      newEvents.forEach(e => appendEvent(e));
    }

  } catch(e) {
    // ignore fetch errors during attack
  }
}

function fmt(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
  if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
  return (n||0).toString();
}

function fmtUptime(ms) {
  const s = Math.floor(ms/1000);
  const h = Math.floor(s/3600);
  const m = Math.floor((s%3600)/60);
  const sec = s%60;
  if (h > 0) return h+'h '+m+'m';
  if (m > 0) return m+'m '+sec+'s';
  return sec+'s';
}

// Init
drawChart();
pollMetrics();
setInterval(pollMetrics, 800);

// Resize handler
window.addEventListener('resize', drawChart);
</script>
</body>
</html>`;
}
