// ============================================================================
// Slowloris Guard - Connection-Level Slow Attack Detection
// Covers: Slow Headers, Slow Body (Slow POST), Connection Exhaustion
// ============================================================================

import * as http from 'http';
import * as net from 'net';
import { Logger } from '../utils/logger';
import { LRUCache } from '../utils/data-structures';

const log = new Logger('SlowlorisGuard');

export interface SlowlorisConfig {
  enabled: boolean;
  headerTimeoutMs: number;       // Max time to finish sending ALL headers
  bodyTimeoutMs: number;         // Max time to finish sending body after headers done
  minBodyRateBytesPerSec: number;// Min sustained body transfer rate
  maxConnectionsPerIP: number;   // Hard limit on concurrent connections per IP
  maxPendingHeaders: number;     // Max in-progress header-phase connections per IP
  idleTimeoutMs: number;         // Kill idle connection (no bytes received)
}

export const DEFAULT_SLOWLORIS_CONFIG: SlowlorisConfig = {
  enabled: true,
  headerTimeoutMs: 10000,
  bodyTimeoutMs: 30000,
  minBodyRateBytesPerSec: 50,
  maxConnectionsPerIP: 50,
  maxPendingHeaders: 10,
  idleTimeoutMs: 15000,
};

interface ConnState {
  ip: string;
  connectedAt: number;
  lastByteAt: number;
  bytesReceived: number;
  headersDone: boolean;
  headersDoneAt?: number;
  bodyBytesReceived: number;
}

export class SlowlorisGuard {
  private readonly config: SlowlorisConfig;

  // ip → count of active connections
  private connPerIP: LRUCache<number>;
  // ip → count of connections still in header phase
  private pendingHeadersPerIP: LRUCache<number>;

  private stats = {
    slowHeadersKilled: 0,
    slowBodyKilled: 0,
    connLimitKilled: 0,
    idleKilled: 0,
  };

  constructor(config: SlowlorisConfig) {
    this.config = config;
    this.connPerIP = new LRUCache(100000, 120000);
    this.pendingHeadersPerIP = new LRUCache(100000, 60000);
  }

  /**
   * Attach slowloris detection to an HTTP server.
   * Hooks into raw socket connections before HTTP parsing.
   */
  attach(server: http.Server): void {
    if (!this.config.enabled) return;

    server.on('connection', (socket: net.Socket) => {
      const ip = socket.remoteAddress ?? '0.0.0.0';

      // === Per-IP connection limit ===
      const current = (this.connPerIP.get(ip) ?? 0) + 1;
      this.connPerIP.set(ip, current);

      if (current > this.config.maxConnectionsPerIP) {
        this.stats.connLimitKilled++;
        log.debug(`Conn limit from ${ip}: ${current} connections`);
        socket.destroy();
        this.connPerIP.set(ip, current - 1);
        return;
      }

      // Track pending headers count
      const pending = (this.pendingHeadersPerIP.get(ip) ?? 0) + 1;
      this.pendingHeadersPerIP.set(ip, pending);

      if (pending > this.config.maxPendingHeaders) {
        this.stats.slowHeadersKilled++;
        log.debug(`Too many pending header connections from ${ip}: ${pending}`);
        socket.destroy();
        this.connPerIP.set(ip, current - 1);
        this.pendingHeadersPerIP.set(ip, pending - 1);
        return;
      }

      const state: ConnState = {
        ip,
        connectedAt: Date.now(),
        lastByteAt: Date.now(),
        bytesReceived: 0,
        headersDone: false,
        bodyBytesReceived: 0,
      };

      // === Header timeout ===
      const headerTimer = setTimeout(() => {
        if (!state.headersDone) {
          this.stats.slowHeadersKilled++;
          log.debug(`Slow headers from ${ip}: ${Date.now() - state.connectedAt}ms`);
          socket.destroy();
        }
      }, this.config.headerTimeoutMs);
      headerTimer.unref();

      // === Idle timeout (no bytes at all) ===
      let idleTimer = setTimeout(() => {
        this.stats.idleKilled++;
        log.debug(`Idle connection from ${ip}`);
        socket.destroy();
      }, this.config.idleTimeoutMs);
      idleTimer.unref();

      socket.on('data', (chunk: Buffer) => {
        state.bytesReceived += chunk.length;
        state.lastByteAt = Date.now();

        // Reset idle timer on each byte received
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
          this.stats.idleKilled++;
          socket.destroy();
        }, this.config.idleTimeoutMs);
        idleTimer.unref();

        // Detect headers complete: look for \r\n\r\n
        if (!state.headersDone) {
          const raw = chunk.toString('binary');
          if (raw.includes('\r\n\r\n') || raw.includes('\n\n')) {
            state.headersDone = true;
            state.headersDoneAt = Date.now();
            clearTimeout(headerTimer);

            // Update pending headers count
            const p = (this.pendingHeadersPerIP.get(ip) ?? 1) - 1;
            this.pendingHeadersPerIP.set(ip, Math.max(0, p));

            // Start body rate check
            this.startBodyRateCheck(socket, state);
          }
        } else {
          state.bodyBytesReceived += chunk.length;
        }
      });

      socket.on('close', () => {
        clearTimeout(headerTimer);
        clearTimeout(idleTimer);

        const c = (this.connPerIP.get(ip) ?? 1) - 1;
        this.connPerIP.set(ip, Math.max(0, c));

        if (!state.headersDone) {
          const p = (this.pendingHeadersPerIP.get(ip) ?? 1) - 1;
          this.pendingHeadersPerIP.set(ip, Math.max(0, p));
        }
      });

      socket.on('error', () => { /* handled by close */ });
    });
  }

  private startBodyRateCheck(socket: net.Socket, state: ConnState): void {
    const CHECK_INTERVAL = 2000;
    const CHECKS = Math.floor(this.config.bodyTimeoutMs / CHECK_INTERVAL);
    let checks = 0;
    let lastBytes = state.bodyBytesReceived;

    const interval = setInterval(() => {
      checks++;
      if (socket.destroyed) { clearInterval(interval); return; }

      const newBytes = state.bodyBytesReceived - lastBytes;
      lastBytes = state.bodyBytesReceived;

      const rateBytesPerSec = (newBytes / CHECK_INTERVAL) * 1000;

      // If body is being sent very slowly
      if (!socket.destroyed && checks > 1 && rateBytesPerSec < this.config.minBodyRateBytesPerSec && newBytes > 0) {
        this.stats.slowBodyKilled++;
        log.debug(`Slow POST from ${state.ip}: ${rateBytesPerSec.toFixed(1)} B/s`);
        clearInterval(interval);
        socket.destroy();
        return;
      }

      // Body timeout reached
      if (checks >= CHECKS) {
        clearInterval(interval);
      }
    }, CHECK_INTERVAL);
    interval.unref();
  }

  getStats() {
    return { ...this.stats };
  }
}
