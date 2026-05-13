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
import { DEFAULT_ZERO_TRUST_CONFIG, ZeroTrustGateway } from './mtls-gateway';

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
  port: number;
  maxResetPerSec: number;
  maxStreamsPerSec: number;
  maxConcurrentStreams: number;
}

export const DEFAULT_HTTP2_CONFIG: Http2Config = {
  enabled: false,
  port: 443,
  maxResetPerSec: 20,
  maxStreamsPerSec: 200,
  maxConcurrentStreams: 100,
};

function getTLSOptions(config: ServerConfig): { cert: Buffer | string; key: Buffer | string; requestCert: boolean; rejectUnauthorized: boolean } {
  if (config.tls?.cert && config.tls?.key) {
    return {
      cert: fs.readFileSync(config.tls.cert),
      key: fs.readFileSync(config.tls.key),
      requestCert: !!config.zeroTrust?.enabled && !!config.zeroTrust.mtls.enabled,
      rejectUnauthorized: false,
    };
  }
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const selfsigned = require('selfsigned');
  const pems = selfsigned.generate([{ name: 'commonName', value: 'shield-guard' }], {
    days: 365, keySize: 2048,
  });
  return {
    cert: pems.cert,
    key: pems.private,
    requestCert: !!config.zeroTrust?.enabled && !!config.zeroTrust.mtls.enabled,
    rejectUnauthorized: false,
  };
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

function getPeerCertificate(session: http2.ServerHttp2Session) {
  const tlsSocket = session.socket as http2.ServerHttp2Session['socket'] & {
    getPeerCertificate?: () => { subject?: { CN?: string }; fingerprint256?: string };
    authorized?: boolean;
  };
  if (typeof tlsSocket.getPeerCertificate !== 'function') {
    return undefined;
  }
  const certificate = tlsSocket.getPeerCertificate();
  if (!certificate || Object.keys(certificate).length === 0) {
    return undefined;
  }
  return {
    subject: certificate.subject,
    fingerprint256: certificate.fingerprint256,
    valid: true,
  };
}

function respondAuthFailure(stream: http2.ServerHttp2Stream, statusCode: number, reason: string): void {
  stream.respond({ ':status': statusCode, 'x-shield-reason': reason });
  stream.end(reason);
}

export function createHttp2Server(
  config: ServerConfig,
  http2Config: Http2Config,
  shield: AntiDDoSShield,
  uam: UnderAttackMode,
): void {
  const tls = getTLSOptions(config);
  const zeroTrust = new ZeroTrustGateway({
    ...DEFAULT_ZERO_TRUST_CONFIG,
    ...config.zeroTrust,
    jwt: {
      ...DEFAULT_ZERO_TRUST_CONFIG.jwt,
      ...config.zeroTrust?.jwt,
      publicKeys: config.zeroTrust?.jwt?.publicKeys ?? DEFAULT_ZERO_TRUST_CONFIG.jwt.publicKeys,
    },
    apiKeys: {
      ...DEFAULT_ZERO_TRUST_CONFIG.apiKeys,
      ...config.zeroTrust?.apiKeys,
      keys: config.zeroTrust?.apiKeys?.keys ?? DEFAULT_ZERO_TRUST_CONFIG.apiKeys.keys,
    },
    mtls: {
      ...DEFAULT_ZERO_TRUST_CONFIG.mtls,
      ...config.zeroTrust?.mtls,
    },
  });

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

  const ipResetCounters = new LRUCache<SlidingWindowCounter>(100000, 60000);
  const ipStreamCounters = new LRUCache<SlidingWindowCounter>(100000, 60000);
  const blockedIPs = new LRUCache<boolean>(100000, 300000);

  const server = http2.createSecureServer({
    ...tls,
    settings: {
      maxConcurrentStreams: http2Config.maxConcurrentStreams,
    },
    allowHTTP1: true,
  });
  const tlsGuard = new TLSGuard({
    ...DEFAULT_TLS_GUARD_CONFIG,
    ...config.tlsGuard,
  });
  tlsGuard.attach(server);

  server.on('session', (session) => {
    const state: SessionState = {
      ip: session.socket.remoteAddress ?? '0.0.0.0',
      streamCount: 0,
      activeStreams: 0,
      resetCount: 0,
      resetRateCounter: new SlidingWindowCounter(1000),
      streamRateCounter: new SlidingWindowCounter(1000),
      blocked: false,
      createdAt: Date.now(),
    };

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
      stream.on('aborted', () => {
        state.activeStreams = Math.max(0, state.activeStreams - 1);
        const elapsed = Date.now() - streamCreatedAt;
        if (elapsed < 100) {
          state.resetCount++;
          state.resetRateCounter.increment(Date.now());

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

      const method = String(headers[':method'] ?? 'GET').toUpperCase();
      const path = String(headers[':path'] ?? '/');
      const ip = state.ip;

      const plainHeaders: Record<string, string> = {};
      for (const [key, value] of Object.entries(headers)) {
        if (!key.startsWith(':') && value) {
          plainHeaders[key] = Array.isArray(value) ? value.join(', ') : String(value);
        }
      }

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
          const fakeRes = {
            writeHead: (code: number, h?: Record<string, string>) => {
              stream.respond({ ':status': code, ...(h ?? {}) });
            },
            end: (data: string) => { stream.end(data); },
            setHeader: () => undefined,
          } as unknown as import('http').ServerResponse;
          handleDashboardAPI(path, shield, fakeRes);
          return;
        }
        stream.respond({ ':status': 200, 'content-type': 'text/html; charset=utf-8' });
        stream.end(renderDashboard());
        return;
      }

      if (uam.isActive() && !uam.isExempt(path)) {
        if (!uam.isCleared(plainHeaders.cookie, ip)) {
          if (path === '/_sg_uam_verify' && method === 'POST') {
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

      void (async () => {
        const authResult = await zeroTrust.authenticate({
          headers: plainHeaders,
          requestPath: path,
          clientCert: getPeerCertificate(session),
          isTls: true,
        });
        if (!authResult.allowed) {
          respondAuthFailure(stream, authResult.statusCode, authResult.reason ?? 'Access denied');
          return;
        }

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
            setHeader: () => undefined,
            getHeader: () => undefined,
            removeHeader: () => undefined,
          };
          proxy.web(
            fakeReq as unknown as import('http').IncomingMessage,
            fakeRes as unknown as import('http').ServerResponse,
          );
          return;
        }

        if (result.action === Action.RATE_LIMIT) {
          stream.respond({ ':status': 429, 'retry-after': '1', 'x-shield-reason': result.reason });
          stream.end('Too Many Requests');
          return;
        }

        stream.respond({ ':status': 403, 'x-shield-reason': result.reason });
        stream.end('Forbidden');
      })().catch((error: Error) => {
        log.error('Unhandled HTTP/2 request processing failure', {
          message: error.message,
          path,
          method,
          ip,
        });
        if (!stream.closed) {
          stream.respond({ ':status': 500 });
          stream.end('Internal Server Error');
        }
      });
    });

    session.on('error', (err) => {
      log.debug('Session error', { ip: state.ip, message: err.message });
    });
  });

  server.listen(http2Config.port, () => {
    log.success(`HTTP/2+TLS listening on port ${http2Config.port} (Rapid Reset protection active)`);
  });
}
