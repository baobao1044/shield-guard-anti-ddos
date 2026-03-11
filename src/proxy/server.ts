// ============================================================================
// Reverse Proxy Server - HTTP + HTTPS with full L7 protection
// ============================================================================

import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as crypto from 'crypto';
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

export { UnderAttackMode };

export function getClientIP(req: http.IncomingMessage): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return (Array.isArray(forwarded) ? forwarded[0] : forwarded).split(',')[0].trim();
  }
  return req.socket?.remoteAddress ?? '0.0.0.0';
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

  proxy.on('error', (err, _req, res) => {
    log.error('Proxy error', { message: err.message });
    if (res instanceof http.ServerResponse && !res.headersSent) {
      res.writeHead(502);
      res.end('Bad Gateway');
    }
  });

  // === Core request handler ===

  function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const ip = getClientIP(req);
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

    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (v) headers[k] = Array.isArray(v) ? v.join(', ') : v;
    }

    let body = '';
    let bodySize = 0;
    const MAX_BODY_READ = 1024 * 1024;

    const processRequest = () => {
      let decodedUrl = url;
      try { decodedUrl = decodeURIComponent(url); } catch { /* keep raw */ }

      const httpReq: HTTPRequest = {
        ip,
        method,
        url: decodedUrl,
        headers,
        body: body || undefined,
        contentLength: parseInt(headers['content-length'] ?? '0') || bodySize,
        userAgent: headers['user-agent'],
        timestamp: Date.now(),
      };

      const result = shield.processHTTPRequest(httpReq);

      // Auto-activate UAM if adaptive mode detects critical threat
      if (shield.getMetrics().currentRPS > (config.uam?.autoActivateThreshold ?? DEFAULT_UAM_CONFIG.autoActivateThreshold)) {
        uam.activate();
      }

      if (result.action === Action.ALLOW) {
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

    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      req.on('data', (chunk: Buffer) => {
        bodySize += chunk.length;
        if (bodySize <= MAX_BODY_READ) {
          body += chunk.toString('utf8', 0, Math.min(chunk.length, MAX_BODY_READ - (bodySize - chunk.length)));
        }
      });
      req.on('end', processRequest);
      req.on('error', () => processRequest());
    } else {
      processRequest();
    }
  }

  // === Start HTTP server ===

  const httpServer = http.createServer(handleRequest);
  slowloris.attach(httpServer); // hook slowloris detection at socket level
  httpServer.listen(config.port, () => {
    log.success(`HTTP  listening on port ${config.port}`);
  });

  // === Start HTTPS server ===

  if (config.httpsPort) {
    const tlsOpts = getTLSOptions(config);
    const httpsServer = https.createServer(tlsOpts, handleRequest);

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
