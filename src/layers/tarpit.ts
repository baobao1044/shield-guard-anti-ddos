// ============================================================================
// Honeypot + Tarpit System
// Traps attackers with fake paths and slow-drip responses
// ============================================================================

import * as http from 'http';
import { Logger } from '../utils/logger';
import { LRUCache } from '../utils/data-structures';

const log = new Logger('Tarpit');

export interface TarpitConfig {
  enabled: boolean;
  honeypotPaths: string[];            // Fake paths that auto-blacklist visitors
  tarpitEnabled: boolean;             // Use slow drip instead of instant 403
  tarpitBytesPerSecond: number;       // How slowly to drip response (default: 1 B/s)
  tarpitMaxDurationMs: number;        // Max time to hold connection (default: 60s)
  tarpitResponseSize: number;         // Total junk bytes to send (default: 10KB)
  autoBlacklistOnHoneypot: boolean;   // Auto-block IP after hitting honeypot
  honeypotResponseCode: number;       // HTTP code for honeypot trap (default: 200)
}

export const DEFAULT_TARPIT_CONFIG: TarpitConfig = {
  enabled: true,
  honeypotPaths: [
    '/admin', '/wp-admin', '/wp-login.php', '/wp-config.php',
    '/.env', '/.git/config', '/phpMyAdmin', '/phpmyadmin',
    '/administrator', '/xmlrpc.php', '/config.php',
    '/backup.sql', '/database.sql', '/dump.sql',
    '/cgi-bin/', '/shell', '/cmd', '/eval',
    '/.aws/credentials', '/.ssh/id_rsa',
  ],
  tarpitEnabled: true,
  tarpitBytesPerSecond: 1,
  tarpitMaxDurationMs: 60000,
  tarpitResponseSize: 10240,
  autoBlacklistOnHoneypot: true,
  honeypotResponseCode: 200,
};

export interface HoneypotHit {
  timestamp: number;
  ip: string;
  method: string;
  path: string;
  userAgent: string;
  headers: Record<string, string>;
}

export class TarpitSystem {
  private readonly config: TarpitConfig;
  private honeypotPathSet: Set<string>;

  // Track trapped IPs
  private trappedIPs: LRUCache<{ hitCount: number; firstSeen: number }>;
  private activeTarpits: number = 0;

  // Intel collection
  private recentHits: HoneypotHit[] = [];
  private readonly maxHits = 500;

  private stats = {
    honeypotHits: 0,
    tarpitActivations: 0,
    tarpitBytesServed: 0,
    tarpitTotalTimeMs: 0,
    uniqueTrappedIPs: 0,
    autoBlacklisted: 0,
  };

  // Callback for auto-blacklisting
  private blacklistCallback: ((ip: string) => void) | null = null;

  constructor(config: TarpitConfig) {
    this.config = config;
    this.honeypotPathSet = new Set(config.honeypotPaths.map(p => p.toLowerCase()));
    this.trappedIPs = new LRUCache(100000, 3600000);
  }

  /**
   * Register callback to blacklist IPs (called from shield integration)
   */
  onBlacklist(callback: (ip: string) => void): void {
    this.blacklistCallback = callback;
  }

  /**
   * Check if a request path matches a honeypot
   */
  isHoneypot(url: string): boolean {
    if (!this.config.enabled) return false;
    const path = url.split('?')[0].split('#')[0].toLowerCase();
    for (const hp of this.honeypotPathSet) {
      if (path === hp || path.startsWith(hp + '/')) return true;
    }
    return false;
  }

  /**
   * Handle a honeypot hit - collect intel and optionally tarpit
   */
  handleHoneypotHit(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    ip: string,
  ): void {
    const url = req.url ?? '/';
    const method = req.method ?? 'GET';
    const userAgent = req.headers['user-agent'] ?? '';

    this.stats.honeypotHits++;

    // Collect intelligence
    const hit: HoneypotHit = {
      timestamp: Date.now(),
      ip,
      method,
      path: url,
      userAgent,
      headers: this.sanitizeHeaders(req.headers),
    };

    this.recentHits.push(hit);
    if (this.recentHits.length > this.maxHits) {
      this.recentHits.shift();
    }

    // Track trapped IP
    let trapped = this.trappedIPs.get(ip);
    if (!trapped) {
      trapped = { hitCount: 0, firstSeen: Date.now() };
      this.trappedIPs.set(ip, trapped);
      this.stats.uniqueTrappedIPs++;
    }
    trapped.hitCount++;

    log.warn(`Honeypot hit: ${ip} → ${method} ${url} (UA: ${userAgent.substring(0, 60)})`);

    // Auto-blacklist
    if (this.config.autoBlacklistOnHoneypot && this.blacklistCallback) {
      this.stats.autoBlacklisted++;
      this.blacklistCallback(ip);
    }

    // Tarpit or quick response
    if (this.config.tarpitEnabled) {
      this.serveTarpit(res, ip);
    } else {
      this.serveHoneypotResponse(res);
    }
  }

  /**
   * Serve a tarpit response - send data extremely slowly to waste attacker resources
   */
  private serveTarpit(res: http.ServerResponse, ip: string): void {
    this.stats.tarpitActivations++;
    this.activeTarpits++;

    const startTime = Date.now();
    let bytesSent = 0;

    res.writeHead(this.config.honeypotResponseCode, {
      'Content-Type': 'text/html; charset=utf-8',
      'Transfer-Encoding': 'chunked',
      'Connection': 'keep-alive',
      'X-Powered-By': 'Apache/2.4.41', // Fake header to look like a real server
    });

    const junkChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \n';

    const interval = setInterval(() => {
      if (res.destroyed || res.writableEnded) {
        clearInterval(interval);
        this.activeTarpits = Math.max(0, this.activeTarpits - 1);
        return;
      }

      const elapsed = Date.now() - startTime;

      // Time limit reached
      if (elapsed >= this.config.tarpitMaxDurationMs || bytesSent >= this.config.tarpitResponseSize) {
        clearInterval(interval);
        this.activeTarpits = Math.max(0, this.activeTarpits - 1);
        this.stats.tarpitTotalTimeMs += elapsed;
        try { res.end(); } catch { /* ignore */ }
        return;
      }

      // Drip one byte
      const char = junkChars[Math.floor(Math.random() * junkChars.length)];
      try {
        res.write(char);
        bytesSent++;
        this.stats.tarpitBytesServed++;
      } catch {
        clearInterval(interval);
        this.activeTarpits = Math.max(0, this.activeTarpits - 1);
        this.stats.tarpitTotalTimeMs += elapsed;
      }
    }, Math.max(1, Math.floor(1000 / this.config.tarpitBytesPerSecond)));

    interval.unref();
  }

  private serveHoneypotResponse(res: http.ServerResponse): void {
    res.writeHead(this.config.honeypotResponseCode, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Powered-By': 'Apache/2.4.41',
    });
    // Fake response to make scanner think it found something
    res.end('<html><head><title>Login</title></head><body><form action="/login" method="POST"><input name="user"><input name="pass" type="password"><button>Login</button></form></body></html>');
  }

  private sanitizeHeaders(headers: http.IncomingHttpHeaders): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      if (v) result[k] = (Array.isArray(v) ? v.join(', ') : v).substring(0, 200);
    }
    return result;
  }

  /**
   * Use tarpit response for blocked requests (instead of instant 403)
   */
  serveTarpitForBlocked(res: http.ServerResponse, ip: string, reason: string): void {
    if (!this.config.tarpitEnabled) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('403 Forbidden');
      return;
    }
    this.serveTarpit(res, ip);
  }

  getRecentHits(limit = 50): HoneypotHit[] {
    return this.recentHits.slice(-limit).reverse();
  }

  getStats() {
    return {
      ...this.stats,
      activeTarpits: this.activeTarpits,
    };
  }
}
