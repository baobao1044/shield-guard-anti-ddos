// ============================================================================
// HTTP/2 Server with Rapid Reset Attack Detection (CVE-2023-44487)
// ============================================================================

import * as http2 from 'http2';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { AntiDDoSShield } from '../core/shield';
import { HTTPRequest, Action, ServerConfig } from '../core/types';
import { Logger } from '../utils/logger';
import { LRUCache, SlidingWindowCounter } from '../utils/data-structures';
import { UnderAttackMode } from '../layers/uam';
import { TLSGuard, DEFAULT_TLS_GUARD_CONFIG } from '../layers/tls-guard';
import { renderDashboard, handleDashboardAPI } from '../dashboard/dashboard';
import httpProxy from 'http-proxy';

const log = new Logger('HTTP2');

interface SessionState {
  ip: string;
  streamCount: number;
  activeStreams: number;
  resetCount: number;
  resetRateCounter: SlidingWindowCounter;
  streamRateCounter: SlidingWindowCounter;
  blocked: boolean;
  createdAt: number;
}

export interface Http2Config {
  enabled: boolean;
  port: number;         // usually 443 when HTTPS
  maxResetPerSec: number;      // RST_STREAM rate limit per session
  maxStreamsPerSec: number;    // Max new streams per second
  maxConcurrentStreams: number; // HTTP/2 server setting
}

export const DEFAULT_HTTP2_CONFIG: Http2Config = {
  enabled: false,
  port: 443,
  maxResetPerSec: 20,
  maxStreamsPerSec: 200,
  maxConcurrentStreams: 100,
};

function getTLSOptions(config: ServerConfig): { cert: Buffer | string; key: Buffer | string } {
  if (config.tls?.cert && config.tls?.key) {
    return {
      cert: fs.readFileSync(config.tls.cert),
      key: fs.readFileSync(config.tls.key),
    };
  }
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const selfsigned = require('selfsigned');
  const pems = selfsigned.generate([{ name: 'commonName', value: 'shield-guard' }], {
    days: 365, keySize: 2048,
  });
  return { cert: pems.cert, key: pems.private };
}

function parseCookies(h: string = ''): Record<string, string> {
  const r: Record<string, string> = {};
  for (const p of h.split(';')) {
    const [k, ...v] = p.trim().split('=');
    if (k) r[k.trim()] = v.join('=').trim();
  }
  return r;
}

function checkDashboardAuth(headers: http2.IncomingHttpHeaders, password?: string): boolean {
  if (!password) return true;
  const auth = headers['authorization'];
  if (!auth || !auth.startsWith('Basic ')) return false;
  const [, pass] = Buffer.from(auth.slice(6), 'base64').toString().split(':', 2);
  const expected = crypto.createHash('sha256').update(password).digest();
  const provided = crypto.createHash('sha256').update(pass ?? '').digest();
  try { return crypto.timingSafeEqual(expected, provided); } catch { return false; }
}

export function createHttp2Server(
  config: ServerConfig,
  http2Config: Http2Config,
  shield: AntiDDoSShield,
  uam: UnderAttackMode,
): void {
  const tls = getTLSOptions(config);

  const proxy = httpProxy.createProxyServer({
    target: config.target,
    changeOrigin: true,
    timeout: 30000,
  });

  proxy.on('error', (err, _req, res) => {
    log.error('Proxy error', { message: err.message });
    if ('writeHead' in res && typeof (res as { writeHead?: unknown }).writeHead === 'function') {
      (res as { writeHead: (n: number) => void; end: (s: string) => void }).writeHead(502);
      (res as { end: (s: string) => void }).end('Bad Gateway');
    }
  });

  // Per-IP reset tracking (across sessions)
  const ipResetCounters = new LRUCache<SlidingWindowCounter>(100000, 60000);
  const ipStreamCounters = new LRUCache<SlidingWindowCounter>(100000, 60000);
  const blockedIPs = new LRUCache<boolean>(100000, 300000); // 5 min block

  const server = http2.createSecureServer({
    ...tls,
    settings: {
      maxConcurrentStreams: http2Config.maxConcurrentStreams,
    },
    allowHTTP1: true, // Fallback for HTTP/1.1 clients
  });
  const tlsGuard = new TLSGuard({
    ...DEFAULT_TLS_GUARD_CONFIG,
    ...config.tlsGuard,
  });
  tlsGuard.attach(server);

  server.on('session', (session) => {
    const state: SessionState = {
      ip: (session.socket.remoteAddress ?? '0.0.0.0'),
      streamCount: 0,
      activeStreams: 0,
      resetCount: 0,
      resetRateCounter: new SlidingWindowCounter(1000),
      streamRateCounter: new SlidingWindowCounter(1000),
      blocked: false,
      createdAt: Date.now(),
    };

    // === Per-IP block check ===
    if (blockedIPs.get(state.ip) || tlsGuard.isBlocked(state.ip)) {
      log.warn(`Blocked IP ${state.ip} tried HTTP/2 connection`);
      session.destroy();
      return;
    }

    session.on('stream', (stream, headers) => {
      state.streamCount++;
      state.activeStreams++;
      state.streamRateCounter.increment(Date.now());

      let ipStreamCounter = ipStreamCounters.get(state.ip);
      if (!ipStreamCounter) {
        ipStreamCounter = new SlidingWindowCounter(1000);
        ipStreamCounters.set(state.ip, ipStreamCounter);
      }
      ipStreamCounter.increment(Date.now());

      const sessionStreamRate = state.streamRateCounter.getRate();
      const ipStreamRate = ipStreamCounter.getRate();
      if (sessionStreamRate > http2Config.maxStreamsPerSec || ipStreamRate > http2Config.maxStreamsPerSec * 2) {
        blockedIPs.set(state.ip, true);
        stream.respond({ ':status': 429 });
        stream.end('Too Many Streams');
        session.destroy();
        return;
      }

      const streamCreatedAt = Date.now();

      // Rapid Reset: track RST_STREAM events
      stream.on('aborted', () => {
        state.activeStreams = Math.max(0, state.activeStreams - 1);
        const elapsed = Date.now() - streamCreatedAt;

        // Fast RST (< 100ms after creation) = likely rapid reset attack
        if (elapsed < 100) {
          state.resetCount++;
          state.resetRateCounter.increment(Date.now());

          // Per-IP tracking
          let ipCounter = ipResetCounters.get(state.ip);
          if (!ipCounter) {
            ipCounter = new SlidingWindowCounter(1000);
            ipResetCounters.set(state.ip, ipCounter);
          }
          ipCounter.increment(Date.now());
          const ipResetRate = ipCounter.getRate();

          const sessionResetRate = state.resetRateCounter.getRate();

          if (sessionResetRate > http2Config.maxResetPerSec || ipResetRate > http2Config.maxResetPerSec * 2) {
            state.blocked = true;
            blockedIPs.set(state.ip, true);
            log.warn(`HTTP/2 Rapid Reset attack detected - blocked ${state.ip}`, {
              sessionResets: state.resetCount,
              rate: sessionResetRate.toFixed(1),
            });
            session.destroy();
          }
        }
      });

      if (state.blocked) {
        stream.respond({ ':status': 403 });
        stream.end('Blocked');
        return;
      }

      stream.on('close', () => {
        state.activeStreams = Math.max(0, state.activeStreams - 1);
      });

      // === Build req-like object for shield ===
      const method = (headers[':method'] ?? 'GET').toUpperCase();
      const path = headers[':path'] ?? '/';
      const ip = state.ip;

      const plainHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(headers)) {
        if (!k.startsWith(':') && v) {
          plainHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
        }
      }

      // === Internal endpoints ===
      if (path === '/shield-health') {
        stream.respond({ ':status': 200, 'content-type': 'application/json' });
        stream.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
        return;
      }

      if (path.startsWith('/shield-dashboard') || path.startsWith('/shield-api/')) {
        if (!checkDashboardAuth(headers, config.dashboardPassword)) {
          stream.respond({
            ':status': 401,
            'www-authenticate': 'Basic realm="Shield Guard Dashboard"',
          });
          stream.end('Unauthorized');
          return;
        }
        if (path.startsWith('/shield-api/')) {
          // Fake http.ServerResponse compatible object for handleDashboardAPI
          let body = '';
          const fakeRes = {
            writeHead: (code: number, h?: Record<string, string>) => {
              stream.respond({ ':status': code, ...(h ?? {}) });
            },
            end: (data: string) => { body = data; stream.end(data); },
            setHeader: (_k: string, _v: string) => { /* noop */ },
          } as unknown as import('http').ServerResponse;
          handleDashboardAPI(path, shield, fakeRes);
          void body;
          return;
        }
        stream.respond({ ':status': 200, 'content-type': 'text/html; charset=utf-8' });
        stream.end(renderDashboard());
        return;
      }

      // === UAM check ===
      if (uam.isActive() && !uam.isExempt(path)) {
        if (!uam.isCleared(plainHeaders['cookie'], ip)) {
          if (path === '/_sg_uam_verify' && method === 'POST') {
            // Handle PoW verification
            let body = '';
            stream.on('data', (chunk: Buffer) => { body += chunk.toString(); });
            stream.on('end', () => {
              try {
                const { nonce, solution } = JSON.parse(body);
                if (uam.verifySolution(nonce, solution, ip)) {
                  const cookie = uam.generateClearanceCookie(ip);
                  stream.respond({ ':status': 200, 'set-cookie': cookie, 'content-type': 'application/json' });
                  stream.end(JSON.stringify({ ok: true }));
                } else {
                  stream.respond({ ':status': 403 });
                  stream.end(JSON.stringify({ ok: false }));
                }
              } catch {
                stream.respond({ ':status': 400 });
                stream.end(JSON.stringify({ ok: false }));
              }
            });
            return;
          }

          const nonce = uam.issueChallenge(ip);
          stream.respond({ ':status': 200, 'content-type': 'text/html; charset=utf-8' });
          stream.end(uam.renderPage(nonce));
          return;
        }
      }

      // === Shield processing ===
      let decodedPath = path;
      try { decodedPath = decodeURIComponent(path); } catch { /* keep raw */ }

      const httpReq: HTTPRequest = {
        ip,
        method,
        url: decodedPath,
        headers: plainHeaders,
        userAgent: plainHeaders['user-agent'],
        timestamp: Date.now(),
      };

      const result = shield.processHTTPRequest(httpReq);

      if (result.action === Action.ALLOW) {
        // Use HTTP/1.1 proxy (http-proxy doesn't support H2 upstream well)
        // Convert stream to req/res for http-proxy
        const fakeReq = Object.assign(stream, {
          url: path,
          method,
          headers: { ...headers, ...plainHeaders },
        });
        const fakeRes = {
          writeHead: (code: number, h?: Record<string, string>) => {
            stream.respond({ ':status': code, ...(h ?? {}) });
          },
          write: (chunk: Buffer | string) => stream.write(chunk),
          end: (chunk?: Buffer | string) => { if (chunk) stream.write(chunk); stream.end(); },
          on: stream.on.bind(stream),
          setHeader: (_k: string, _v: string) => {},
          getHeader: () => undefined,
          removeHeader: () => {},
        };
        proxy.web(fakeReq as unknown as import('http').IncomingMessage,
          fakeRes as unknown as import('http').ServerResponse);
        return;
      }

      if (result.action === Action.RATE_LIMIT) {
        stream.respond({ ':status': 429, 'retry-after': '1', 'x-shield-reason': result.reason });
        stream.end('Too Many Requests');
        return;
      }

      stream.respond({ ':status': 403, 'x-shield-reason': result.reason });
      stream.end('Forbidden');
    });

    session.on('error', (err) => {
      log.debug('Session error', { ip: state.ip, message: err.message });
    });
  });

  server.listen(http2Config.port, () => {
    log.success(`HTTP/2+TLS listening on port ${http2Config.port} (Rapid Reset protection active)`);
  });
}
