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
import { TarpitSystem, DEFAULT_TARPIT_CONFIG } from '../layers/tarpit';
import { JA3Fingerprinter, DEFAULT_JA3_CONFIG } from '../layers/ja3-fingerprint';
import { WSStream, DEFAULT_WS_CONFIG } from '../stats/ws-stream';
import { DEFAULT_ZERO_TRUST_CONFIG, ZeroTrustGateway } from './mtls-gateway';

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

function getPeerCertificate(socket: http.IncomingMessage['socket']) {
  const tlsSocket = socket as http.IncomingMessage['socket'] & {
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
      requestCert: config.zeroTrust?.enabled && config.zeroTrust.mtls.enabled,
      rejectUnauthorized: false,
    };
  }
  log.warn('No TLS cert provided, generating self-signed certificate');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const selfsigned = require('selfsigned');
  const pems = selfsigned.generate([{ name: 'commonName', value: 'shield-guard' }], {
    days: 365, keySize: 2048,
  });
  return {
    cert: pems.cert,
    key: pems.private,
    requestCert: config.zeroTrust?.enabled && config.zeroTrust.mtls.enabled,
    rejectUnauthorized: false,
  };
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

function respondAuthFailure(res: http.ServerResponse, statusCode: number, reason: string): void {
  res.writeHead(statusCode, {
    'Content-Type': 'text/plain',
    'X-Shield-Reason': reason,
  });
  res.end(`${statusCode} Access Denied\n\n${reason}`);
}

export function createProxyServer(
  config: ServerConfig,
  shield: AntiDDoSShield,
): { uam: UnderAttackMode } {
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

  const tarpit = new TarpitSystem({
    ...DEFAULT_TARPIT_CONFIG,
    ...config.tarpit,
  });
  tarpit.onBlacklist((ip) => shield.blacklistIP(ip));

  const ja3 = new JA3Fingerprinter({
    ...DEFAULT_JA3_CONFIG,
    ...config.ja3,
  });

  const wsStream = new WSStream({
    ...DEFAULT_WS_CONFIG,
    ...config.wsStream,
  });

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

  function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const ip = getClientIP(req, config);
    const url = req.url ?? '/';
    const method = req.method ?? 'GET';

    if (tarpit.isHoneypot(url)) {
      tarpit.handleHoneypotHit(req, res, ip);
      return;
    }

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

    if (uam.isActive() && !uam.isExempt(url)) {
      const cookieHeader = req.headers['cookie'];
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

      if (!uam.isCleared(cookieHeader, ip)) {
        const nonce = uam.issueChallenge(ip);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(uam.renderPage(nonce));
        return;
      }
    }

    const headers = normalizeHeaders(req);

    const processRequest = async (bodyText?: string, bodyBuffer?: Buffer) => {
      const authResult = await zeroTrust.authenticate({
        headers,
        requestPath: url,
        clientCert: getPeerCertificate(req.socket),
        isTls: (req.socket as { encrypted?: boolean }).encrypted === true,
      });

      if (!authResult.allowed) {
        respondAuthFailure(res, authResult.statusCode, authResult.reason ?? 'Access denied');
        return;
      }

      const httpReq = buildHTTPRequest(ip, method, url, headers, bodyText, bodyBuffer);
      const result = shield.processHTTPRequest(httpReq);

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
        const nonce = uam.issueChallenge(ip);
        uam.activate();
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(uam.renderPage(nonce));
        return;
      }

      res.writeHead(403, {
        'Content-Type': 'text/plain',
        'X-Shield-Reason': result.reason,
      });
      res.end('403 Forbidden\n\nYour request was blocked by Shield Guard.');
    };

    const maxInspectionBytes = config.shield?.l7?.httpFloodProtection?.requestSizeLimit ?? MAX_BODY_INSPECTION_BYTES;
    if (!shouldInspectBody(method, headers, maxInspectionBytes)) {
      void processRequest().catch((error: Error) => {
        log.error('Unhandled request processing failure', { message: error.message, method, url, ip });
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('500 Internal Server Error');
        }
      });
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
        void processRequest().catch((error: Error) => {
          log.error('Unhandled request processing failure', { message: error.message, method, url, ip });
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('500 Internal Server Error');
          }
        });
      });
  }

  const httpServer = http.createServer(handleRequest);
  trackConnections(httpServer);
  slowloris.attach(httpServer);
  wsStream.attach(httpServer, shield);
  httpServer.listen(config.port, () => {
    log.success(`HTTP  listening on port ${config.port}`);
  });

  if (config.httpsPort) {
    const tlsOpts = getTLSOptions(config);
    const httpsServer = https.createServer(tlsOpts, handleRequest);
    trackConnections(httpsServer);
    tlsGuard.attach(httpsServer);
    httpsServer.on('secureConnection', (socket) => {
      ja3.extractFingerprint(socket);
    });
    slowloris.attach(httpsServer as unknown as http.Server);
    httpsServer.listen(config.httpsPort, () => {
      log.success(`HTTPS listening on port ${config.httpsPort} (TLS guard active)`);
    });
  }

  return { uam };
}
