// ============================================================================
// Under Attack Mode (UAM) - Proof-of-Work JS Challenge
// Like Cloudflare's "I'm Under Attack Mode"
// ============================================================================

import * as crypto from 'crypto';
import { Logger } from '../utils/logger';
import { LRUCache } from '../utils/data-structures';

const log = new Logger('UAM');

export interface UAMConfig {
  enabled: boolean;
  difficulty: number;        // Leading zeros required in SHA256 hash (4 = ~65536 attempts avg)
  cookieTTLSeconds: number;  // How long the cleared cookie lasts
  autoActivateThreshold: number; // RPS to auto-activate UAM
  exemptPaths: string[];     // Paths that skip UAM (e.g. /api/webhook)
}

export const DEFAULT_UAM_CONFIG: UAMConfig = {
  enabled: false,
  difficulty: 4,
  cookieTTLSeconds: 3600,
  autoActivateThreshold: 5000,
  exemptPaths: ['/shield-health', '/favicon.ico', '/shield-demo', '/shield-api/'],
};

const COOKIE_NAME = '_sg_cleared';

export class UnderAttackMode {
  private readonly config: UAMConfig;
  private readonly hmacSecret: string;
  private active: boolean;

  // Track pending challenges: nonce → {ip, issuedAt}
  private pendingChallenges: LRUCache<{ ip: string; issuedAt: number }>;

  constructor(config: UAMConfig) {
    this.config = config;
    this.active = config.enabled;
    this.hmacSecret = crypto.randomBytes(32).toString('hex');
    this.pendingChallenges = new LRUCache(100000, 120000); // 2 min TTL
    if (this.active) log.warn('Under Attack Mode is ACTIVE');
  }

  isActive(): boolean { return this.active; }

  activate(): void {
    if (!this.active) {
      this.active = true;
      log.warn('Under Attack Mode ACTIVATED');
    }
  }

  deactivate(): void {
    if (this.active) {
      this.active = false;
      log.info('Under Attack Mode deactivated');
    }
  }

  // Check if this path is exempt from UAM
  isExempt(url: string): boolean {
    const path = url.split('?')[0];
    return this.config.exemptPaths.some(p => path.startsWith(p));
  }

  // Validate the clearance cookie from request headers
  isCleared(cookieHeader: string | undefined, ip: string): boolean {
    if (!cookieHeader) return false;

    const cookies = parseCookies(cookieHeader);
    const token = cookies[COOKIE_NAME];
    if (!token) return false;

    return this.verifyToken(token, ip);
  }

  // Verify HMAC-signed clearance token
  verifyToken(token: string, ip: string): boolean {
    try {
      const decoded = Buffer.from(token, 'base64url').toString('utf8');
      const [ip2, ts, sig] = decoded.split('|');

      if (ip2 !== ip) return false;

      const now = Date.now();
      const issued = parseInt(ts);
      if (isNaN(issued) || now - issued > this.config.cookieTTLSeconds * 1000) return false;

      const expected = this.sign(`${ip2}|${ts}`);
      return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
    } catch {
      return false;
    }
  }

  // Issue a new challenge nonce
  issueChallenge(ip: string): string {
    const nonce = crypto.randomBytes(16).toString('hex');
    this.pendingChallenges.set(nonce, { ip, issuedAt: Date.now() });
    return nonce;
  }

  // Verify PoW solution: SHA256(nonce + ':' + solution) starts with N zero hex chars
  verifySolution(nonce: string, solution: string, ip: string): boolean {
    const pending = this.pendingChallenges.get(nonce);
    if (!pending) return false;
    if (pending.ip !== ip) return false;

    const hash = crypto
      .createHash('sha256')
      .update(`${nonce}:${solution}`)
      .digest('hex');

    const required = '0'.repeat(this.config.difficulty);
    if (!hash.startsWith(required)) return false;

    this.pendingChallenges.delete(nonce);
    return true;
  }

  // Generate a clearance cookie value after passing the challenge
  generateClearanceCookie(ip: string): string {
    const ts = Date.now().toString();
    const payload = `${ip}|${ts}`;
    const sig = this.sign(payload);
    const token = Buffer.from(`${payload}|${sig}`).toString('base64url');
    return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${this.config.cookieTTLSeconds}`;
  }

  private sign(data: string): string {
    return crypto.createHmac('sha256', this.hmacSecret).update(data).digest('hex').substring(0, 32);
  }

  // Render the UAM challenge HTML page
  renderPage(nonce: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Checking your browser... | Shield Guard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #0a0a0f; color: #c9d1d9; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { text-align: center; max-width: 480px; padding: 40px 24px; }
    .logo { font-size: 56px; margin-bottom: 24px; animation: spin 2s linear infinite; display: inline-block; }
    @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    h1 { font-size: 22px; color: #58a6ff; margin-bottom: 8px; }
    p { color: #8b949e; font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
    .progress-wrap { background: #21262d; border-radius: 8px; height: 8px; overflow: hidden; margin-bottom: 16px; }
    .progress-bar { height: 100%; background: linear-gradient(90deg, #58a6ff, #3fb950); border-radius: 8px; width: 0%; transition: width 0.1s; }
    .status { font-size: 13px; color: #8b949e; min-height: 20px; }
    .status.done { color: #3fb950; }
    .status.error { color: #f85149; }
    .footer { margin-top: 32px; font-size: 12px; color: #484f58; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">🛡️</div>
    <h1>Checking your browser...</h1>
    <p>This site is protected by <strong>Shield Guard</strong>.<br>
    Completing a brief security check before you continue.</p>
    <div class="progress-wrap"><div class="progress-bar" id="bar"></div></div>
    <div class="status" id="status">Initializing security check...</div>
    <div class="footer">Shield Guard &bull; Under Attack Mode Active</div>
  </div>

  <script>
  (async function() {
    const nonce = ${JSON.stringify(nonce)};
    const difficulty = ${this.config.difficulty};
    const prefix = '0'.repeat(difficulty);
    const status = document.getElementById('status');
    const bar = document.getElementById('bar');

    // Proof-of-Work: find solution s.t. SHA256(nonce + ':' + solution) starts with prefix
    async function sha256hex(str) {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Chunk work into async batches to keep UI responsive
    async function solve() {
      status.textContent = 'Running security check...';
      let i = 0;
      const BATCH = 500;
      while (true) {
        for (let j = 0; j < BATCH; j++) {
          const hash = await sha256hex(nonce + ':' + i);
          if (hash.startsWith(prefix)) {
            return i.toString();
          }
          i++;
        }
        // Update progress (rough estimate based on difficulty)
        const estimated = Math.pow(16, difficulty);
        const pct = Math.min(95, (i / estimated) * 100);
        bar.style.width = pct + '%';
        status.textContent = 'Verifying... (' + i.toLocaleString() + ' attempts)';
        await new Promise(r => setTimeout(r, 0)); // yield to UI
      }
    }

    try {
      const solution = await solve();
      status.textContent = 'Verification complete! Redirecting...';
      bar.style.width = '100%';

      const res = await fetch('/_sg_uam_verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nonce, solution })
      });

      if (res.ok) {
        status.className = 'status done';
        status.textContent = '✓ Security check passed. Loading page...';
        setTimeout(() => location.reload(), 300);
      } else {
        throw new Error('Verification failed');
      }
    } catch(e) {
      status.className = 'status error';
      status.textContent = 'Error: ' + e.message + '. Please refresh.';
    }
  })();
  </script>
</body>
</html>`;
  }
}

function parseCookies(cookieHeader: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of cookieHeader.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) result[k.trim()] = v.join('=').trim();
  }
  return result;
}
