// ============================================================================
// Reverse Proxy Server - HTTP + HTTPS with full L7 protection
// ============================================================================

import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as net from 'net';
import httpProxy from 'http-proxy';
import { AntiDDoSShield } from '../core/shield';
import { HTTPRequest, Action, ServerConfig } from '../core/types';
import { Logger } from '../utils/logger';
import { renderDashboard, handleDashboardAPI, setUAM } from '../dashboard/dashboard';
import { renderDemoPage } from '../demo/demo';
import { UnderAttackMode, DEFAULT_UAM_CONFIG } from '../layers/uam';
import { SlowlorisGuard, DEFAULT_SLOWLORIS_CONFIG } from '../layers/slowloris-guard';
import { TLSGuard, DEFAULT_TLS_GUARD_CONFIG } from '../layers/tls-guard';

const log = new Logger('Proxy');
const MAX_BODY_INSPECTION_BYTES = 1024 * 1024;

type BufferedRequest = http.IncomingMessage & {
  shieldGuardBufferedBody?: Buffer;
};

export { UnderAttackMode };

function normalizeIPAddress(ip: string | undefined): string {
  if (!ip) return '0.0.0.0';
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function isTrustedProxy(config: ServerConfig, remoteIP: string): boolean {
  const trusted = config.trustedProxies?.map(normalizeIPAddress) ?? [];
  return trusted.includes(remoteIP);
}

export function getClientIP(req: http.IncomingMessage, config: ServerConfig): string {
  const remoteIP = normalizeIPAddress(req.socket?.remoteAddress);
  const forwarded = req.headers['x-forwarded-for'];
  if (config.trustForwardedHeaders && forwarded && isTrustedProxy(config, remoteIP)) {
    const candidate = normalizeIPAddress((Array.isArray(forwarded) ? forwarded[0] : forwarded).split(',')[0].trim());
    if (net.isIP(candidate)) {
      return candidate;
    }
  }
  return remoteIP;
}

function getTLSOptions(config: ServerConfig): https.ServerOptions {
  if (config.tls?.cert && config.tls?.key) {
    return {
      cert: fs.readFileSync(config.tls.cert),
      key: fs.readFileSync(config.tls.key),
    };
  }
  log.warn('No TLS cert provided, generating self-signed certificate');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const selfsigned = require('selfsigned');
  const pems = selfsigned.generate([{ name: 'commonName', value: 'shield-guard' }], {
    days: 365, keySize: 2048,
  });
  return { cert: pems.cert, key: pems.private };
}

function checkDashboardAuth(req: http.IncomingMessage, password?: string): boolean {
  if (!password) return true;
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Basic ')) return false;
  const b64 = authHeader.slice(6);
  const [, pass] = Buffer.from(b64, 'base64').toString('utf8').split(':', 2);
  const expected = crypto.createHash('sha256').update(password).digest();
  const provided = crypto.createHash('sha256').update(pass ?? '').digest();
  try { return crypto.timingSafeEqual(expected, provided); } catch { return false; }
}

function normalizeHeaders(req: http.IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v) headers[k] = Array.isArray(v) ? v.join(', ') : v;
  }
  return headers;
}

function hasRequestBody(method: string, headers: Record<string, string>): boolean {
  const contentLength = Number.parseInt(headers['content-length'] ?? '', 10);
  if (Number.isFinite(contentLength) && contentLength > 0) return true;
  return (headers['transfer-encoding'] ?? '').toLowerCase().includes('chunked')
    || !['GET', 'HEAD'].includes(method);
}

function shouldInspectBody(method: string, headers: Record<string, string>, maxInspectionBytes: number): boolean {
  if (!hasRequestBody(method, headers)) return false;
  const transferEncoding = (headers['transfer-encoding'] ?? '').toLowerCase();
  if (transferEncoding.includes('chunked')) return false;

  const contentLength = Number.parseInt(headers['content-length'] ?? '', 10);
  return Number.isFinite(contentLength) && contentLength <= maxInspectionBytes;
}

function readInspectableBody(req: http.IncomingMessage, maxInspectionBytes: number): Promise<{ bodyBuffer: Buffer; bodyText: string }> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bodySize = 0;
    let finished = false;

    req.on('data', (chunk: Buffer) => {
      if (finished) return;
      bodySize += chunk.length;
      if (bodySize > maxInspectionBytes) {
        finished = true;
        reject(new Error('Request body exceeded inspection limit'));
        return;
      }
      if (finished) {
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (finished) return;
      finished = true;
      const bodyBuffer = Buffer.concat(chunks);
      resolve({
        bodyBuffer,
        bodyText: bodyBuffer.toString('utf8'),
      });
    });
    req.on('error', (error) => {
      if (finished) return;
      finished = true;
      reject(error);
    });
  });
}

function buildHTTPRequest(ip: string, method: string, url: string, headers: Record<string, string>, bodyText?: string, bodyBuffer?: Buffer): HTTPRequest {
  let decodedUrl = url;
  try { decodedUrl = decodeURIComponent(url); } catch { /* keep raw */ }
  const contentLength = bodyBuffer?.length ?? (Number.parseInt(headers['content-length'] ?? '0', 10) || undefined);

  return {
    ip,
    method,
    url: decodedUrl,
    rawUrl: url,
    headers,
    body: bodyText || undefined,
    contentLength,
    bodySize: bodyBuffer?.length ?? contentLength,
    hasBody: typeof contentLength === 'number' ? contentLength > 0 : false,
    userAgent: headers['user-agent'],
    timestamp: Date.now(),
  };
}

export function createProxyServer(
  config: ServerConfig,
  shield: AntiDDoSShield,
): { uam: UnderAttackMode } {
  // === Initialize protection modules ===

  const uam = new UnderAttackMode({
    ...DEFAULT_UAM_CONFIG,
    ...config.uam,
  });
  setUAM(uam);

  const slowloris = new SlowlorisGuard({
    ...DEFAULT_SLOWLORIS_CONFIG,
    ...config.slowloris,
  });

  const tlsGuard = new TLSGuard({
    ...DEFAULT_TLS_GUARD_CONFIG,
    ...config.tlsGuard,
  });

  // === Proxy ===

  const proxy = httpProxy.createProxyServer({
    target: config.target,
    changeOrigin: true,
    selfHandleResponse: false,
    timeout: 30000,
  });

  proxy.on('proxyReq', (proxyReq, incomingReq) => {
    const bufferedBody = (incomingReq as BufferedRequest).shieldGuardBufferedBody;
    if (!bufferedBody) return;
    proxyReq.removeHeader('transfer-encoding');
    proxyReq.setHeader('content-length', bufferedBody.length);
    proxyReq.write(bufferedBody);
  });

  proxy.on('error', (err, _req, res) => {
    log.error('Proxy error', { message: err.message });
    if (res instanceof http.ServerResponse && !res.headersSent) {
      res.writeHead(502);
      res.end('Bad Gateway');
    }
  });

  let activeConnections = 0;
  const trackConnections = (server: http.Server | https.Server) => {
    server.on('connection', (socket) => {
      activeConnections++;
      shield.setRuntimeStats({ activeConnections });

      socket.once('close', () => {
        activeConnections = Math.max(0, activeConnections - 1);
        shield.setRuntimeStats({ activeConnections });
      });
    });
  };

  // === Core request handler ===

  function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const ip = getClientIP(req, config);
    const url = req.url ?? '/';
    const method = req.method ?? 'GET';

    // === Internal endpoints (always bypass shield) ===

    if (url.startsWith('/shield-demo')) {
      const baseUrl = `${req.headers['x-forwarded-proto'] ?? 'http'}://${req.headers['host'] ?? `localhost:${config.port}`}`;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(renderDemoPage(baseUrl));
      return;
    }

    if (url === '/shield-health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        uptime: process.uptime(),
        uam: uam.isActive(),
      }));
      return;
    }

    if (url.startsWith('/shield-dashboard') || url.startsWith('/shield-api/')) {
      if (!checkDashboardAuth(req, config.dashboardPassword)) {
        res.writeHead(401, {
          'WWW-Authenticate': 'Basic realm="Shield Guard Dashboard"',
          'Content-Type': 'text/plain',
        });
        res.end('Unauthorized');
        return;
      }
      if (url.startsWith('/shield-api/')) {
        handleDashboardAPI(url, shield, res);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(renderDashboard());
      return;
    }

    // === UAM: Under Attack Mode ===

    if (uam.isActive() && !uam.isExempt(url)) {
      const cookieHeader = req.headers['cookie'];

      // UAM verify endpoint: POST /_sg_uam_verify with {nonce, solution}
      if (url === '/_sg_uam_verify' && method === 'POST') {
        let body = '';
        req.on('data', (c: Buffer) => { body += c.toString(); });
        req.on('end', () => {
          try {
            const { nonce, solution } = JSON.parse(body);
            if (uam.verifySolution(nonce, solution, ip)) {
              const cookie = uam.generateClearanceCookie(ip);
              res.writeHead(200, {
                'Content-Type': 'application/json',
                'Set-Cookie': cookie,
              });
              res.end(JSON.stringify({ ok: true }));
            } else {
              res.writeHead(403, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ ok: false, error: 'Invalid solution' }));
            }
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false }));
          }
        });
        return;
      }

      // Check clearance cookie
      if (!uam.isCleared(cookieHeader, ip)) {
        const nonce = uam.issueChallenge(ip);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(uam.renderPage(nonce));
        return;
      }
    }

    // === Build HTTPRequest for shield ===

    const headers = normalizeHeaders(req);
    const processRequest = (bodyText?: string, bodyBuffer?: Buffer) => {
      const httpReq = buildHTTPRequest(ip, method, url, headers, bodyText, bodyBuffer);

      const result = shield.processHTTPRequest(httpReq);

      // Auto-activate UAM if adaptive mode detects critical threat
      if (shield.getCurrentRPS() > (config.uam?.autoActivateThreshold ?? DEFAULT_UAM_CONFIG.autoActivateThreshold)) {
        uam.activate();
      }

      if (result.action === Action.ALLOW) {
        if (bodyBuffer) {
          const bufferedReq = req as BufferedRequest;
          bufferedReq.shieldGuardBufferedBody = bodyBuffer;
        }
        proxy.web(req, res);
        return;
      }

      if (result.action === Action.RATE_LIMIT) {
        res.writeHead(429, {
          'Content-Type': 'text/plain',
          'Retry-After': '1',
          'X-Shield-Reason': result.reason,
        });
        res.end('429 Too Many Requests\n\nYou have been rate limited by Shield Guard.');
        return;
      }

      if (result.action === Action.CHALLENGE) {
        // Upgrade to UAM challenge instead of simple math
        const nonce = uam.issueChallenge(ip);
        uam.activate(); // bot detected → activate UAM
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(uam.renderPage(nonce));
        return;
      }

      // DROP / BLACKHOLE
      res.writeHead(403, {
        'Content-Type': 'text/plain',
        'X-Shield-Reason': result.reason,
      });
      res.end('403 Forbidden\n\nYour request was blocked by Shield Guard.');
    };

    const maxInspectionBytes = config.shield?.l7?.httpFloodProtection?.requestSizeLimit ?? MAX_BODY_INSPECTION_BYTES;
    if (!shouldInspectBody(method, headers, maxInspectionBytes)) {
      processRequest();
      return;
    }

    readInspectableBody(req, maxInspectionBytes)
      .then(({ bodyBuffer, bodyText }) => processRequest(bodyText, bodyBuffer))
      .catch((err: Error) => {
        if (err.message === 'Request body exceeded inspection limit') {
          res.writeHead(413, {
            'Content-Type': 'text/plain',
            'X-Shield-Reason': err.message,
          });
          res.end('413 Payload Too Large\n\nShield Guard inspection limit exceeded.');
          return;
        }
        log.warn('Failed to inspect request body, falling back to metadata-only classification', {
          message: err.message,
          method,
          url,
          ip,
        });
        processRequest();
      });
  }

  // === Start HTTP server ===

  const httpServer = http.createServer(handleRequest);
  trackConnections(httpServer);
  slowloris.attach(httpServer); // hook slowloris detection at socket level
  httpServer.listen(config.port, () => {
    log.success(`HTTP  listening on port ${config.port}`);
  });

  // === Start HTTPS server ===

  if (config.httpsPort) {
    const tlsOpts = getTLSOptions(config);
    const httpsServer = https.createServer(tlsOpts, handleRequest);
    trackConnections(httpsServer);

    // Hook TLS guard for handshake tracking
    tlsGuard.attach(httpsServer);
    // Hook slowloris on HTTPS too
    slowloris.attach(httpsServer as unknown as http.Server);

    httpsServer.listen(config.httpsPort, () => {
      log.success(`HTTPS listening on port ${config.httpsPort} (TLS guard active)`);
    });
  }

  return { uam };
}
