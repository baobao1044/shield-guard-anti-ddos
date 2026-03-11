// ============================================================================
// Terminal Live Stats (dstat) - Real-time attack monitor
// Usage: node shield.js --target ... --port ... --dstat
//        node shield.js --dstat-only --shield-url http://localhost:9994
// ============================================================================

import * as http from 'http';

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const A = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  red:     '\x1b[31m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  blue:    '\x1b[34m',
  magenta: '\x1b[35m',
  cyan:    '\x1b[36m',
  white:   '\x1b[37m',
  gray:    '\x1b[90m',
  bgRed:   '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgBlue:  '\x1b[44m',
  bgYellow:'\x1b[43m',
  clear:   '\x1b[2J\x1b[H',
  home:    '\x1b[H',
  hideCursor: '\x1b[?25l',
  showCursor: '\x1b[?25h',
};

// Box drawing
const B = {
  tl: '╔', tr: '╗', bl: '╚', br: '╝',
  h: '═', v: '║',
  ml: '╠', mr: '╣', mt: '╦', mb: '╩', x: '╬',
  sl: '├', sr: '┤', sh: '─', sv: '│',
};

function c(color: string, text: string): string {
  return `${color}${text}${A.reset}`;
}

function pad(s: string | number, n: number, right = false): string {
  const str = String(s);
  const diff = n - stripAnsi(str).length;
  if (diff <= 0) return str;
  return right ? ' '.repeat(diff) + str : str + ' '.repeat(diff);
}

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function fmt(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K';
  return n.toString();
}

function fmtUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

function fmtTime(ts: number): string {
  return new Date(ts).toTimeString().substring(0, 8);
}

function bar(val: number, max: number, width: number, color: string): string {
  if (max === 0) max = 1;
  const filled = Math.round((val / max) * width);
  const empty = width - filled;
  return c(color, '█'.repeat(Math.max(0, filled))) + c(A.gray, '░'.repeat(Math.max(0, empty)));
}

function threatColor(level: number): string {
  if (level >= 4) return A.bgRed + A.white + A.bold;
  if (level >= 3) return A.red + A.bold;
  if (level >= 2) return A.yellow + A.bold;
  if (level >= 1) return A.cyan;
  return A.gray;
}

function threatLabel(level: number): string {
  const labels = ['NONE    ', 'LOW     ', 'MEDIUM  ', 'HIGH    ', 'CRITICAL'];
  return labels[Math.min(level, 4)];
}

function layerColor(layer: string): string {
  if (layer === 'L3') return A.blue;
  if (layer === 'L4') return A.green;
  if (layer === 'L7') return A.magenta;
  return A.gray;
}

function actionColor(action: string): string {
  if (action === 'DROP' || action === 'BLACKHOLE') return A.red;
  if (action === 'RATE_LIMIT') return A.yellow;
  if (action === 'CHALLENGE') return A.cyan;
  return A.gray;
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

function fetchJSON(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', (c: Buffer) => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON')); }
      });
    }).on('error', reject).setTimeout(2000, function() { this.destroy(); });
  });
}

// ── RPS Sparkline ─────────────────────────────────────────────────────────────

class Sparkline {
  private history: number[] = [];
  private readonly maxPoints: number;

  constructor(maxPoints = 60) {
    this.maxPoints = maxPoints;
  }

  push(val: number): void {
    this.history.push(val);
    if (this.history.length > this.maxPoints) this.history.shift();
  }

  render(width: number): string {
    const CHARS = ' ▁▂▃▄▅▆▇█';
    const data = this.history.slice(-width);
    const max = Math.max(...data, 1);
    return data.map(v => {
      const idx = Math.min(8, Math.floor((v / max) * 8));
      return c(v > max * 0.8 ? A.red : v > max * 0.5 ? A.yellow : A.green, CHARS[idx]);
    }).join('');
  }
}

// ── Main DstatMonitor ─────────────────────────────────────────────────────────

interface Metrics {
  totalPackets: number;
  totalAllowed: number;
  totalDropped: number;
  totalChallenged: number;
  totalRateLimited: number;
  avgProcessingTimeUs: number;
  peakRPS: number;
  currentRPS: number;
  threatsByLayer: { l3: number; l4: number; l7: number };
  topAttackVectors: Array<{ vector: string; count: number }>;
  uptimeMs: number;
  uamActive?: boolean;
}

interface BlockEvent {
  ts: number;
  ip: string;
  layer: string;
  reason: string;
  action: string;
  threatLevel: number;
  url?: string;
}

export class DstatMonitor {
  private readonly shieldUrl: string;
  private readonly refreshMs: number;
  private sparkline = new Sparkline(60);
  private prevMetrics: Metrics | null = null;
  private prevDropped = 0;
  private prevAllowed = 0;
  private blockRate = 0;
  private allowRate = 0;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;
  private cols = 120;
  private rows = 40;

  constructor(shieldUrl: string, refreshMs = 1000) {
    this.shieldUrl = shieldUrl;
    this.refreshMs = refreshMs;
  }

  start(): void {
    // Hide cursor, clear screen
    process.stdout.write(A.hideCursor + A.clear);

    // Handle resize
    process.stdout.on('resize', () => {
      this.cols = process.stdout.columns ?? 120;
      this.rows = process.stdout.rows ?? 40;
    });
    this.cols = process.stdout.columns ?? 120;
    this.rows = process.stdout.rows ?? 40;

    // Restore cursor on exit
    const cleanup = () => {
      process.stdout.write(A.showCursor + A.clear);
      process.exit(0);
    };
    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);

    this.intervalHandle = setInterval(() => this.refresh(), this.refreshMs);
    this.refresh();
  }

  stop(): void {
    if (this.intervalHandle) clearInterval(this.intervalHandle);
    process.stdout.write(A.showCursor);
  }

  private async refresh(): Promise<void> {
    try {
      const [metrics, events] = await Promise.all([
        fetchJSON(`${this.shieldUrl}/shield-api/metrics`) as Promise<Metrics>,
        fetchJSON(`${this.shieldUrl}/shield-api/events?limit=20`) as Promise<BlockEvent[]>,
      ]);

      this.sparkline.push(metrics.currentRPS);

      // Calculate per-second rates
      if (this.prevMetrics) {
        this.blockRate = metrics.totalDropped - this.prevDropped;
        this.allowRate = metrics.totalAllowed - this.prevAllowed;
      }
      this.prevDropped = metrics.totalDropped;
      this.prevAllowed = metrics.totalAllowed;
      this.prevMetrics = metrics;

      this.render(metrics, events);
    } catch {
      process.stdout.write(A.home);
      process.stdout.write(c(A.red, `\n  ⚠ Cannot connect to Shield Guard at ${this.shieldUrl}\n`));
      process.stdout.write(c(A.gray, `  Retrying in ${this.refreshMs / 1000}s...\n`));
    }
  }

  private render(m: Metrics, events: BlockEvent[]): void {
    const W = Math.max(80, Math.min(this.cols, 160));
    const lines: string[] = [];

    const line = (s = '') => lines.push(s);
    const box = (content: string) => `${B.v} ${content} ${B.v}`;

    // ── Header ─────────────────────────────────────────────────────────────

    const title = ` 🛡️  SHIELD GUARD  ${A.gray}─${A.reset} LIVE ATTACK MONITOR `;
    const now = new Date().toLocaleTimeString();
    const uamBadge = m.uamActive
      ? c(A.bgRed + A.white + A.bold, ' UAM ON ')
      : c(A.bgGreen + A.white, ' UAM OFF');
    const headerRight = `${uamBadge}  ${c(A.gray, now)} `;
    const headerPad = W - 4 - stripAnsi(title).length - stripAnsi(headerRight).length;

    line(c(A.cyan, B.tl + B.h.repeat(W - 2) + B.tr));
    line(c(A.cyan, B.v) + c(A.bold + A.cyan, title) + ' '.repeat(Math.max(0, headerPad)) + headerRight + c(A.cyan, B.v));
    line(c(A.cyan, B.ml + B.h.repeat(W - 2) + B.mr));

    // ── RPS + Sparkline ────────────────────────────────────────────────────

    const rpsVal = m.currentRPS;
    const rpsColor = rpsVal > 10000 ? A.red : rpsVal > 1000 ? A.yellow : A.green;
    const rpsStr = c(rpsColor + A.bold, fmt(rpsVal).padStart(8));
    const peakStr = c(A.gray, `peak: ${fmt(m.peakRPS)}`);
    const sparkW = W - 40;
    const spark = this.sparkline.render(sparkW);
    const rpsLine = ` RPS ${rpsStr} /s  ${peakStr}  ${spark}`;
    line(c(A.cyan, B.v) + pad(rpsLine, W - 2) + c(A.cyan, B.v));

    // ── 5 stat boxes ──────────────────────────────────────────────────────

    line(c(A.cyan, B.ml + B.h.repeat(W - 2) + B.mr));

    const colW = Math.floor((W - 7) / 5);
    const stats = [
      { label: 'TOTAL     ', val: fmt(m.totalPackets),     color: A.white },
      { label: 'ALLOWED ✓ ', val: fmt(m.totalAllowed),     color: A.green },
      { label: 'BLOCKED ✗ ', val: fmt(m.totalDropped),     color: A.red   },
      { label: 'RATE LTD ⚡', val: fmt(m.totalRateLimited), color: A.yellow},
      { label: 'CHALLENGED', val: fmt(m.totalChallenged),  color: A.cyan  },
    ];

    const labelRow = stats.map(s => c(A.dim, pad(s.label, colW))).join(c(A.cyan, B.sv));
    const valRow   = stats.map(s => c(s.color + A.bold, pad(s.val, colW, false))).join(c(A.cyan, B.sv));

    line(c(A.cyan, B.v) + ' ' + labelRow + ' ' + c(A.cyan, B.v));
    line(c(A.cyan, B.v) + ' ' + valRow   + ' ' + c(A.cyan, B.v));

    // Rate line
    const rateStr = `  ${c(A.dim, 'Δ/s')}  ${c(A.green, '+' + fmt(this.allowRate))}  ${c(A.red, '-' + fmt(this.blockRate))}  ${c(A.gray, `avg ${m.avgProcessingTimeUs.toFixed(1)}µs`)}  ${c(A.gray, `uptime ${fmtUptime(m.uptimeMs)}`)}`;
    line(c(A.cyan, B.v) + pad(rateStr, W - 2) + c(A.cyan, B.v));

    // ── Threat bars ───────────────────────────────────────────────────────

    line(c(A.cyan, B.ml + B.h.repeat(W - 2) + B.mr));

    const totalThreats = m.threatsByLayer.l3 + m.threatsByLayer.l4 + m.threatsByLayer.l7;
    const barW = Math.floor((W - 30) / 3);
    const threatLine = [
      c(A.blue  + A.bold, ' L3 ') + c(A.blue,   pad(fmt(m.threatsByLayer.l3), 7, true)) + ' ' + bar(m.threatsByLayer.l3, totalThreats, barW, A.blue),
      c(A.green + A.bold, ' L4 ') + c(A.green,  pad(fmt(m.threatsByLayer.l4), 7, true)) + ' ' + bar(m.threatsByLayer.l4, totalThreats, barW, A.green),
      c(A.magenta + A.bold, ' L7 ') + c(A.magenta, pad(fmt(m.threatsByLayer.l7), 7, true)) + ' ' + bar(m.threatsByLayer.l7, totalThreats, barW, A.magenta),
    ].join('  ');

    line(c(A.cyan, B.v) + pad(threatLine, W - 2) + c(A.cyan, B.v));

    // ── Top attack vectors ────────────────────────────────────────────────

    line(c(A.cyan, B.ml + B.h.repeat(W - 2) + B.mr));
    line(c(A.cyan, B.v) + c(A.bold + A.white, ' TOP ATTACK VECTORS') + pad('', W - 21) + c(A.cyan, B.v));

    const maxVec = m.topAttackVectors[0]?.count ?? 1;
    const vecBarW = Math.floor((W - 50) / 2);
    const vecRows = Math.min(5, m.topAttackVectors.length);

    for (let i = 0; i < Math.max(vecRows, 3); i++) {
      const v = m.topAttackVectors[i];
      if (v) {
        const [layer, ...rest] = v.vector.split(':');
        const reason = rest.join(':').substring(0, W - 30);
        const layerTag = c(layerColor(layer) + A.bold, ` [${layer}]`);
        const countStr = c(A.yellow + A.bold, pad(fmt(v.count), 8, true));
        const b = bar(v.count, maxVec, vecBarW, A.red);
        const row = `${layerTag} ${pad(reason, W - 40)} ${countStr} ${b}`;
        line(c(A.cyan, B.v) + pad(row, W - 2) + c(A.cyan, B.v));
      } else {
        line(c(A.cyan, B.v) + pad(c(A.gray, '  —'), W - 2) + c(A.cyan, B.v));
      }
    }

    // ── Live event feed ───────────────────────────────────────────────────

    line(c(A.cyan, B.ml + B.h.repeat(W - 2) + B.mr));

    const feedTitle = ' LIVE BLOCK FEED';
    const feedRows = Math.max(5, this.rows - lines.length - 4);
    line(c(A.cyan, B.v) + c(A.bold + A.white, feedTitle) + pad('', W - feedTitle.length - 2) + c(A.cyan, B.v));

    const visible = events.slice(0, feedRows);

    for (let i = 0; i < feedRows; i++) {
      const ev = visible[i];
      if (ev) {
        const time   = c(A.gray,  fmtTime(ev.ts));
        const ip     = c(A.white + A.bold, pad(ev.ip, 16));
        const layer  = c(layerColor(ev.layer)  + A.bold, pad(ev.layer, 4));
        const act    = c(actionColor(ev.action), pad(ev.action, 11));
        const threat = c(threatColor(ev.threatLevel), threatLabel(ev.threatLevel));
        const url    = ev.url ? c(A.gray, ' ' + ev.url.substring(0, 25)) : '';
        const reason = c(A.dim, ev.reason.substring(0, W - 80));
        const row    = ` ${time}  ${ip} ${layer} ${act} ${threat} ${reason}${url}`;
        line(c(A.cyan, B.v) + pad(row, W - 2) + c(A.cyan, B.v));
      } else {
        line(c(A.cyan, B.v) + pad('', W - 2) + c(A.cyan, B.v));
      }
    }

    // ── Footer ─────────────────────────────────────────────────────────────

    const footer = ` ${c(A.gray, 'q')} quit  ${c(A.gray, 'Ctrl+C')} exit  ${c(A.cyan, this.shieldUrl)}  refresh ${this.refreshMs}ms `;
    line(c(A.cyan, B.bl + B.h.repeat(W - 2) + B.br));
    line(c(A.gray, footer));

    // ── Write to terminal ──────────────────────────────────────────────────

    process.stdout.write(A.home);
    process.stdout.write(lines.join('\n') + '\n');
  }
}

// ── Standalone mode (called from main.ts with --dstat-only) ──────────────────

export function startDstat(shieldUrl: string, refreshMs = 1000): void {
  const monitor = new DstatMonitor(shieldUrl, refreshMs);
  monitor.start();

  // Allow 'q' to quit
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', (key: Buffer) => {
      if (key.toString() === 'q' || key[0] === 3) {
        monitor.stop();
        process.stdout.write(A.showCursor + A.clear);
        process.exit(0);
      }
    });
  }
}
