// ============================================================================
// Terminal Live Stats (dstat) - Real-time attack monitor
// ============================================================================

import * as http from 'http';

const A = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  clear: '\x1b[2J\x1b[H',
  home: '\x1b[H',
  hideCursor: '\x1b[?25l',
  showCursor: '\x1b[?25h',
};

function color(code: string, text: string): string {
  return `${code}${text}${A.reset}`;
}

function stripAnsi(value: string): string {
  return value.replace(/\x1b\[[0-9;]*m/g, '');
}

function pad(value: string | number, width: number, alignRight = false): string {
  const text = String(value);
  const delta = width - stripAnsi(text).length;
  if (delta <= 0) return text;
  return alignRight ? ' '.repeat(delta) + text : text + ' '.repeat(delta);
}

function fmt(value: number): string {
  if (value >= 1_000_000) return (value / 1_000_000).toFixed(1) + 'M';
  if (value >= 1_000) return (value / 1_000).toFixed(1) + 'K';
  return String(Math.round(value));
}

function fmtRate(value: number): string {
  return fmt(Math.max(0, value));
}

function fmtUptime(ms: number): string {
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function formatClock(ts: number): string {
  return new Date(ts).toTimeString().slice(0, 8);
}

function pct(part: number, total: number): string {
  return (((part || 0) / (total || 1)) * 100).toFixed(1) + '%';
}

function hr(char: string, width: number): string {
  return char.repeat(Math.max(0, width));
}

function colorAction(action: string): string {
  switch (action) {
    case 'DROP':
    case 'BLACKHOLE':
      return A.red;
    case 'RATE_LIMIT':
      return A.yellow;
    case 'CHALLENGE':
      return A.cyan;
    default:
      return A.gray;
  }
}

function colorLayer(layer: string): string {
  switch (layer) {
    case 'L3':
      return A.blue;
    case 'L4':
      return A.green;
    case 'L7':
      return A.magenta;
    default:
      return A.gray;
  }
}

function bar(value: number, max: number, width: number, activeColor: string): string {
  const filled = Math.round((Math.max(0, value) / Math.max(1, max)) * width);
  const empty = Math.max(0, width - filled);
  return color(activeColor, '#'.repeat(filled)) + color(A.gray, '.'.repeat(empty));
}

function fetchJSON<T>(url: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer | string) => {
        data += chunk.toString();
      });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data) as T);
        } catch {
          reject(new Error('Invalid JSON'));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(2000, () => {
      req.destroy(new Error('Request timed out'));
    });
  });
}

class Sparkline {
  private readonly history: number[] = [];

  constructor(private readonly maxPoints = 60) {}

  push(value: number): void {
    this.history.push(value);
    if (this.history.length > this.maxPoints) this.history.shift();
  }

  render(width: number): string {
    const chars = ' .:-=+*#%@';
    const data = this.history.slice(-width);
    if (data.length === 0) return ''.padEnd(width, ' ');
    const max = Math.max(...data, 1);

    return data.map((item) => {
      const idx = Math.min(chars.length - 1, Math.floor((item / max) * (chars.length - 1)));
      const glyph = chars[idx];
      if (item > max * 0.85) return color(A.red, glyph);
      if (item > max * 0.55) return color(A.yellow, glyph);
      return color(A.green, glyph);
    }).join('');
  }
}

interface Metrics {
  totalPackets: number;
  totalAllowed: number;
  totalDropped: number;
  totalChallenged: number;
  totalRateLimited: number;
  avgProcessingTimeUs: number;
  peakRPS: number;
  currentRPS: number;
  activeConnections?: number;
  blacklistedIPs?: number;
  emergencyMode?: boolean;
  uamActive?: boolean;
  threatsByLayer: { l3: number; l4: number; l7: number };
  topAttackVectors?: Array<{ vector: string; count: number }>;
  topReasonCodes?: Array<{ code: string; count: number }>;
  uptimeMs: number;
}

interface BlockEvent {
  ts: number;
  ip: string;
  method?: string;
  path?: string;
  layer: string;
  reasonCode?: string;
  reason: string;
  action: string;
  threatLevel: number;
}

export class DstatMonitor {
  private readonly sparkline = new Sparkline(80);
  private prevMetrics: Metrics | null = null;
  private allowRate = 0;
  private dropRate = 0;
  private limitRate = 0;
  private challengeRate = 0;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;
  private cols = 120;
  private rows = 40;

  constructor(
    private readonly shieldUrl: string,
    private readonly refreshMs = 1000,
  ) {}

  start(): void {
    process.stdout.write(A.hideCursor + A.clear);
    this.cols = process.stdout.columns ?? 120;
    this.rows = process.stdout.rows ?? 40;

    process.stdout.on('resize', () => {
      this.cols = process.stdout.columns ?? 120;
      this.rows = process.stdout.rows ?? 40;
    });

    const cleanup = () => {
      this.stop();
      process.stdout.write(A.clear);
      process.exit(0);
    };

    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);

    this.intervalHandle = setInterval(() => void this.refresh(), this.refreshMs);
    void this.refresh();
  }

  stop(): void {
    if (this.intervalHandle) clearInterval(this.intervalHandle);
    process.stdout.write(A.showCursor);
  }

  private async refresh(): Promise<void> {
    try {
      const [metrics, events] = await Promise.all([
        fetchJSON<Metrics>(`${this.shieldUrl}/shield-api/metrics`),
        fetchJSON<BlockEvent[]>(`${this.shieldUrl}/shield-api/events?limit=20`),
      ]);

      this.sparkline.push(metrics.currentRPS || 0);
      if (this.prevMetrics) {
        this.allowRate = metrics.totalAllowed - this.prevMetrics.totalAllowed;
        this.dropRate = metrics.totalDropped - this.prevMetrics.totalDropped;
        this.limitRate = metrics.totalRateLimited - this.prevMetrics.totalRateLimited;
        this.challengeRate = metrics.totalChallenged - this.prevMetrics.totalChallenged;
      }
      this.prevMetrics = metrics;

      this.renderOnline(metrics, events);
    } catch (error) {
      this.renderOffline(error instanceof Error ? error.message : 'Unknown error');
    }
  }

  private renderOnline(metrics: Metrics, events: BlockEvent[]): void {
    const width = Math.max(90, Math.min(this.cols, 160));
    const lines: string[] = [];
    const total = Math.max(1, metrics.totalPackets);
    const reasons = metrics.topReasonCodes ?? [];
    const maxThreat = Math.max(metrics.threatsByLayer.l3, metrics.threatsByLayer.l4, metrics.threatsByLayer.l7, 1);
    const sparkWidth = Math.max(20, width - 55);

    lines.push(color(A.cyan, hr('=', width)));

    const headerLeft = `${color(A.bold + A.cyan, 'SHIELD GUARD')} live monitor`;
    const headerRight = [
      metrics.uamActive ? color(A.yellow, 'UAM ON') : color(A.green, 'UAM OFF'),
      metrics.emergencyMode ? color(A.red, 'EMERGENCY') : color(A.gray, 'steady'),
      color(A.gray, new Date().toLocaleTimeString()),
    ].join('  ');
    lines.push(
      headerLeft +
      ' '.repeat(Math.max(1, width - stripAnsi(headerLeft).length - stripAnsi(headerRight).length)) +
      headerRight,
    );
    lines.push(color(A.cyan, hr('-', width)));

    const rpsValue = color(
      metrics.currentRPS > 1000 ? A.red + A.bold : metrics.currentRPS > 200 ? A.yellow + A.bold : A.green + A.bold,
      pad(fmt(metrics.currentRPS), 8, true),
    );
    lines.push(`RPS ${rpsValue} /s  peak ${fmt(metrics.peakRPS)}  ${this.sparkline.render(sparkWidth)}`);
    lines.push(color(A.cyan, hr('-', width)));

    const summary = [
      `${color(A.blue, 'TOTAL')} ${pad(fmt(metrics.totalPackets), 8, true)}`,
      `${color(A.green, 'ALLOW')} ${pad(fmt(metrics.totalAllowed), 8, true)} (${pct(metrics.totalAllowed, total)})`,
      `${color(A.red, 'DROP ')} ${pad(fmt(metrics.totalDropped), 8, true)} (${pct(metrics.totalDropped, total)})`,
      `${color(A.yellow, 'LIMIT')} ${pad(fmt(metrics.totalRateLimited), 8, true)} (${pct(metrics.totalRateLimited, total)})`,
      `${color(A.cyan, 'CHAL ')} ${pad(fmt(metrics.totalChallenged), 8, true)} (${pct(metrics.totalChallenged, total)})`,
    ];
    lines.push(summary.join('   '));
    lines.push(
      `${color(A.gray, 'Delta/s')} +${fmtRate(this.allowRate)} allow  -${fmtRate(this.dropRate)} drop  ` +
      `${fmtRate(this.limitRate)} limit  ${fmtRate(this.challengeRate)} challenge`,
    );
    lines.push(
      `${color(A.gray, 'Runtime')} conns ${fmt(metrics.activeConnections ?? 0)}  ` +
      `blacklist ${fmt(metrics.blacklistedIPs ?? 0)}  avg ${(metrics.avgProcessingTimeUs || 0).toFixed(1)} us  ` +
      `uptime ${fmtUptime(metrics.uptimeMs)}`,
    );
    lines.push(color(A.cyan, hr('-', width)));

    lines.push(
      `Threats  L3 ${pad(fmt(metrics.threatsByLayer.l3), 6, true)} ${bar(metrics.threatsByLayer.l3, maxThreat, 14, A.blue)}  ` +
      `L4 ${pad(fmt(metrics.threatsByLayer.l4), 6, true)} ${bar(metrics.threatsByLayer.l4, maxThreat, 14, A.green)}  ` +
      `L7 ${pad(fmt(metrics.threatsByLayer.l7), 6, true)} ${bar(metrics.threatsByLayer.l7, maxThreat, 14, A.magenta)}`,
    );
    lines.push(color(A.cyan, hr('-', width)));

    lines.push(color(A.bold + A.white, 'Top reason codes'));
    if (reasons.length === 0) {
      lines.push(color(A.gray, '  none yet'));
    } else {
      for (const entry of reasons.slice(0, 6)) {
        lines.push(`  ${pad(entry.code, Math.max(20, width - 16))} ${pad(fmt(entry.count), 8, true)}`);
      }
    }

    lines.push(color(A.cyan, hr('-', width)));
    lines.push(color(A.bold + A.white, 'Recent events'));

    const feedRows = Math.max(5, Math.min(12, this.rows - lines.length - 3));
    const visibleEvents = events.slice(0, feedRows);
    if (visibleEvents.length === 0) {
      lines.push(color(A.gray, '  no events'));
    } else {
      for (const event of visibleEvents) {
        const stamp = color(A.gray, formatClock(event.ts));
        const layer = color(colorLayer(event.layer) + A.bold, pad(event.layer, 3));
        const action = color(colorAction(event.action), pad(event.action, 10));
        const ip = pad(event.ip, 18);
        const reasonCode = event.reasonCode ? ` ${color(A.cyan, '[' + event.reasonCode + ']')}` : '';
        const detail = event.path ? color(A.gray, ' ' + event.path) : '';
        const remaining = Math.max(10, width - 52);
        const reasonText = (event.reason || '').slice(0, remaining);
        lines.push(`${stamp} ${ip} ${layer} ${action} ${reasonText}${reasonCode}${detail}`);
      }
    }

    lines.push(color(A.cyan, hr('=', width)));
    lines.push(color(A.gray, `${this.shieldUrl}  refresh ${this.refreshMs}ms  press q to quit`));

    process.stdout.write(A.home + A.clear);
    process.stdout.write(lines.join('\n') + '\n');
  }

  private renderOffline(reason: string): void {
    const width = Math.max(70, Math.min(this.cols, 120));
    const lines = [
      color(A.red, hr('=', width)),
      color(A.bold + A.red, 'SHIELD GUARD monitor offline'),
      `Cannot connect to ${this.shieldUrl}`,
      color(A.gray, `Reason: ${reason}`),
      color(A.gray, `Retrying every ${this.refreshMs}ms`),
      color(A.red, hr('=', width)),
    ];
    process.stdout.write(A.home + A.clear);
    process.stdout.write(lines.join('\n') + '\n');
  }
}

export function startDstat(shieldUrl: string, refreshMs = 1000): void {
  const monitor = new DstatMonitor(shieldUrl, refreshMs);
  monitor.start();

  if (process.stdin.isTTY) {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', (key: Buffer) => {
      if (key.toString() === 'q' || key[0] === 3) {
        monitor.stop();
        process.stdout.write(A.clear);
        process.exit(0);
      }
    });
  }
}
