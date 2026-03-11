// ============================================================================
// TLS Guard - Handshake Bypass & Abuse Detection
// ============================================================================

import * as tls from 'tls';
import * as net from 'net';
import { Logger } from '../utils/logger';
import { LRUCache, SlidingWindowCounter } from '../utils/data-structures';

const log = new Logger('TLSGuard');

export interface TLSGuardConfig {
  enabled: boolean;
  maxHandshakesPerSecond: number;   // Per IP
  handshakeTimeoutMs: number;       // Max time to complete handshake
  maxFailedHandshakes: number;      // Before blocking IP
  minTLSVersion: string;           // 'TLSv1.2' or 'TLSv1.3'
}

export const DEFAULT_TLS_GUARD_CONFIG: TLSGuardConfig = {
  enabled: true,
  maxHandshakesPerSecond: 10,
  handshakeTimeoutMs: 10000,
  maxFailedHandshakes: 20,
  minTLSVersion: 'TLSv1.2',
};

interface HandshakeTracker {
  pending: number;        // In-progress handshakes
  failed: number;         // Failed handshakes total
  rateCounter: SlidingWindowCounter;
}

export class TLSGuard {
  private readonly config: TLSGuardConfig;
  private readonly trackers: LRUCache<HandshakeTracker>;
  private readonly blockedIPs: LRUCache<boolean>;

  // Metrics
  private stats = {
    handshakesTracked: 0,
    handshakesBlocked: 0,
    handshakeTimeouts: 0,
    weakTLSBlocked: 0,
    failedHandshakes: 0,
  };

  constructor(config: TLSGuardConfig) {
    this.config = config;
    this.trackers = new LRUCache(100000, 300000);
    this.blockedIPs = new LRUCache(50000, 600000); // 10 min block
  }

  /**
   * Hook into an HTTPS/HTTP2 server to track TLS events.
   * Call this right after createServer().
   */
  attach(server: tls.Server): void {
    if (!this.config.enabled) return;

    // Track connection-level TLS handshake
    server.on('connection', (socket: net.Socket) => {
      const ip = socket.remoteAddress ?? '0.0.0.0';

      // Check if already blocked
      if (this.blockedIPs.get(ip)) {
        socket.destroy();
        return;
      }

      const tracker = this.getOrCreateTracker(ip);
      tracker.pending++;
      this.stats.handshakesTracked++;

      // Rate check
      tracker.rateCounter.increment(Date.now());
      const rate = tracker.rateCounter.getRate();
      if (rate > this.config.maxHandshakesPerSecond) {
        this.stats.handshakesBlocked++;
        log.warn(`TLS handshake rate exceeded: ${rate.toFixed(1)}/s from ${ip}`);
        socket.destroy();
        tracker.pending = Math.max(0, tracker.pending - 1);
        return;
      }

      // Handshake timeout: if TLS handshake not completed within timeout, destroy
      const timeout = setTimeout(() => {
        if (!(socket as tls.TLSSocket).authorized && !(socket as tls.TLSSocket).getPeerCertificate) {
          this.stats.handshakeTimeouts++;
          tracker.failed++;
          tracker.pending = Math.max(0, tracker.pending - 1);
          log.debug(`TLS handshake timeout from ${ip}`);
          socket.destroy();

          if (tracker.failed >= this.config.maxFailedHandshakes) {
            this.blockIP(ip, 'Too many failed TLS handshakes');
          }
        }
      }, this.config.handshakeTimeoutMs);
      timeout.unref();

      // Successful handshake
      socket.once('secureConnect', () => {
        clearTimeout(timeout);
        tracker.pending = Math.max(0, tracker.pending - 1);

        const tlsSocket = socket as tls.TLSSocket;
        const protocol = tlsSocket.getProtocol?.() ?? 'unknown';

        // Block weak TLS versions
        if (this.isWeakTLS(protocol)) {
          this.stats.weakTLSBlocked++;
          log.warn(`Weak TLS blocked: ${protocol} from ${ip}`);
          socket.destroy();
          return;
        }
      });

      // Failed handshake
      socket.once('error', () => {
        clearTimeout(timeout);
        this.stats.failedHandshakes++;
        tracker.failed++;
        tracker.pending = Math.max(0, tracker.pending - 1);

        if (tracker.failed >= this.config.maxFailedHandshakes) {
          this.blockIP(ip, 'Too many failed TLS handshakes');
        }
      });

      socket.once('close', () => {
        clearTimeout(timeout);
      });
    });

    // TLS-level errors (malformed ClientHello, etc.)
    server.on('tlsClientError', (err: Error, socket: tls.TLSSocket) => {
      const ip = socket.remoteAddress ?? '0.0.0.0';
      this.stats.failedHandshakes++;

      const tracker = this.getOrCreateTracker(ip);
      tracker.failed++;

      log.debug(`TLS client error from ${ip}`, { error: err.message.substring(0, 60) });

      if (tracker.failed >= this.config.maxFailedHandshakes) {
        this.blockIP(ip, 'TLS client errors');
      }

      socket.destroy();
    });
  }

  isBlocked(ip: string): boolean {
    return this.blockedIPs.get(ip) === true;
  }

  private blockIP(ip: string, reason: string): void {
    this.blockedIPs.set(ip, true);
    log.warn(`IP blocked by TLSGuard: ${ip} — ${reason}`);
  }

  private getOrCreateTracker(ip: string): HandshakeTracker {
    let t = this.trackers.get(ip);
    if (!t) {
      t = { pending: 0, failed: 0, rateCounter: new SlidingWindowCounter(1000) };
      this.trackers.set(ip, t);
    }
    return t;
  }

  private isWeakTLS(protocol: string): boolean {
    const weak = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'];
    if (this.config.minTLSVersion === 'TLSv1.3') {
      return protocol !== 'TLSv1.3';
    }
    return weak.includes(protocol);
  }

  getStats() {
    return { ...this.stats };
  }
}
