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
  maxHandshakesPerSecond: number;
  handshakeTimeoutMs: number;
  maxFailedHandshakes: number;
  minTLSVersion: string;
}

export const DEFAULT_TLS_GUARD_CONFIG: TLSGuardConfig = {
  enabled: true,
  maxHandshakesPerSecond: 10,
  handshakeTimeoutMs: 10000,
  maxFailedHandshakes: 20,
  minTLSVersion: 'TLSv1.2',
};

interface HandshakeTracker {
  pending: number;
  failed: number;
  rateCounter: SlidingWindowCounter;
}

interface SocketState {
  ip: string;
  done: boolean;
  timeout: NodeJS.Timeout;
}

export class TLSGuard {
  private readonly config: TLSGuardConfig;
  private readonly trackers: LRUCache<HandshakeTracker>;
  private readonly blockedIPs: LRUCache<boolean>;
  private readonly socketStates: WeakMap<net.Socket, SocketState>;

  private stats = {
    handshakesTracked: 0,
    handshakesBlocked: 0,
    handshakeTimeouts: 0,
    weakTLSBlocked: 0,
    failedHandshakes: 0,
    activePendingHandshakes: 0,
  };

  constructor(config: TLSGuardConfig) {
    this.config = config;
    this.trackers = new LRUCache<HandshakeTracker>(100000, 300000);
    this.blockedIPs = new LRUCache<boolean>(50000, 600000);
    this.socketStates = new WeakMap();
  }

  attach(server: tls.Server): void {
    if (!this.config.enabled) return;

    server.on('connection', (socket: net.Socket) => {
      const ip = socket.remoteAddress ?? '0.0.0.0';

      if (this.blockedIPs.get(ip)) {
        socket.destroy();
        return;
      }

      const tracker = this.getOrCreateTracker(ip);
      tracker.pending++;
      this.stats.handshakesTracked++;
      this.stats.activePendingHandshakes++;

      tracker.rateCounter.increment(Date.now());
      const rate = tracker.rateCounter.getRate();
      if (rate > this.config.maxHandshakesPerSecond) {
        this.stats.handshakesBlocked++;
        tracker.pending = Math.max(0, tracker.pending - 1);
        this.stats.activePendingHandshakes = Math.max(0, this.stats.activePendingHandshakes - 1);
        log.warn(`TLS handshake rate exceeded: ${rate.toFixed(1)}/s from ${ip}`);
        socket.destroy();
        return;
      }

      const timeout = setTimeout(() => {
        const state = this.socketStates.get(socket);
        if (state && !state.done) {
          state.done = true;
          this.stats.handshakeTimeouts++;
          tracker.pending = Math.max(0, tracker.pending - 1);
          this.stats.activePendingHandshakes = Math.max(0, this.stats.activePendingHandshakes - 1);
          this.registerFailure(ip);
          log.debug(`TLS handshake timeout from ${ip}`);
          socket.destroy();
        }
      }, this.config.handshakeTimeoutMs);
      timeout.unref();

      this.socketStates.set(socket, { ip, done: false, timeout });

      socket.once('error', () => {
        const state = this.socketStates.get(socket);
        if (!state || state.done) return;
        state.done = true;
        clearTimeout(state.timeout);
        tracker.pending = Math.max(0, tracker.pending - 1);
        this.stats.activePendingHandshakes = Math.max(0, this.stats.activePendingHandshakes - 1);
        this.registerFailure(ip);
      });

      socket.once('close', () => {
        const state = this.socketStates.get(socket);
        if (state) clearTimeout(state.timeout);
      });
    });

    server.on('secureConnection', (socket: tls.TLSSocket) => {
      const rawSocket = socket as unknown as net.Socket;
      const state = this.socketStates.get(rawSocket);
      const ip = socket.remoteAddress ?? state?.ip ?? '0.0.0.0';
      if (state && !state.done) {
        state.done = true;
        clearTimeout(state.timeout);
        const tracker = this.getOrCreateTracker(ip);
        tracker.pending = Math.max(0, tracker.pending - 1);
        this.stats.activePendingHandshakes = Math.max(0, this.stats.activePendingHandshakes - 1);
      }

      const protocol = socket.getProtocol?.() ?? 'unknown';
      if (this.isWeakTLS(protocol)) {
        this.stats.weakTLSBlocked++;
        log.warn(`Weak TLS blocked: ${protocol} from ${ip}`);
        socket.destroy();
      }
    });

    server.on('tlsClientError', (err: Error, socket: tls.TLSSocket) => {
      const ip = socket.remoteAddress ?? '0.0.0.0';
      this.registerFailure(ip);

      const tracker = this.getOrCreateTracker(ip);
      if (tracker.pending > 0) {
        tracker.pending = Math.max(0, tracker.pending - 1);
        this.stats.activePendingHandshakes = Math.max(0, this.stats.activePendingHandshakes - 1);
      }

      log.debug(`TLS client error from ${ip}`, { error: err.message.substring(0, 60) });
      socket.destroy();
    });
  }

  isBlocked(ip: string): boolean {
    return this.blockedIPs.get(ip) === true;
  }

  private blockIP(ip: string, reason: string): void {
    this.blockedIPs.set(ip, true);
    log.warn(`IP blocked by TLSGuard: ${ip} - ${reason}`);
  }

  private registerFailure(ip: string): void {
    this.stats.failedHandshakes++;
    const tracker = this.getOrCreateTracker(ip);
    tracker.failed++;
    if (tracker.failed >= this.config.maxFailedHandshakes) {
      this.blockIP(ip, 'Too many failed TLS handshakes');
    }
  }

  private getOrCreateTracker(ip: string): HandshakeTracker {
    let tracker = this.trackers.get(ip);
    if (!tracker) {
      tracker = { pending: 0, failed: 0, rateCounter: new SlidingWindowCounter(1000) };
      this.trackers.set(ip, tracker);
    }
    return tracker;
  }

  private isWeakTLS(protocol: string): boolean {
    const weak = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'];
    if (this.config.minTLSVersion === 'TLSv1.3') {
      return protocol !== 'TLSv1.3';
    }
    return weak.includes(protocol);
  }

  getStats() {
    return {
      ...this.stats,
      blockedIPs: this.blockedIPs.getSize(),
    };
  }

  getBlockedCount(): number {
    return this.blockedIPs.getSize();
  }

  getActivePendingHandshakes(): number {
    return this.stats.activePendingHandshakes;
  }
}
