// ============================================================================
// Request Correlation Engine
// Detects coordinated attacks from multiple IPs using behavior signatures
// ============================================================================

import { Logger } from '../utils/logger';
import { SlidingWindowCounter, LRUCache } from '../utils/data-structures';
import * as crypto from 'crypto';

const log = new Logger('CorrelationEngine');

export interface CorrelationConfig {
  enabled: boolean;
  signatureWindowMs: number;        // Time window for correlating requests (default: 10s)
  minIPsForCorrelation: number;     // Min distinct IPs with same signature (default: 5)
  maxTrackedSignatures: number;     // Max signatures to track (LRU, default: 10000)
  botScoreBoost: number;            // Extra bot score for correlated IPs (default: 30)
  autoBlockThreshold: number;       // Auto-block if this many IPs share signature (default: 20)
}

export const DEFAULT_CORRELATION_CONFIG: CorrelationConfig = {
  enabled: true,
  signatureWindowMs: 10000,
  minIPsForCorrelation: 5,
  maxTrackedSignatures: 10000,
  botScoreBoost: 30,
  autoBlockThreshold: 20,
};

interface SignatureState {
  ips: Set<string>;
  count: number;
  firstSeen: number;
  lastSeen: number;
  rateCounter: SlidingWindowCounter;
}

export interface CorrelationAlert {
  timestamp: number;
  signature: string;
  signatureHuman: string;
  distinctIPs: number;
  totalRequests: number;
  sampleIPs: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export class CorrelationEngine {
  private readonly config: CorrelationConfig;

  // signature → tracking state
  private signatures: LRUCache<SignatureState>;

  // IP → set of signatures it has used
  private ipSignatures: LRUCache<Set<string>>;

  // Flagged IPs (correlated)
  private flaggedIPs: LRUCache<{ boost: number; signatures: string[] }>;

  // Recent alerts
  private alerts: CorrelationAlert[] = [];
  private readonly maxAlerts = 200;

  private stats = {
    signaturesTracked: 0,
    correlationsDetected: 0,
    ipsCorrelated: 0,
    autoBlockTriggered: 0,
  };

  // Callback for auto-blocking
  private blockCallback: ((ip: string) => void) | null = null;

  constructor(config: CorrelationConfig) {
    this.config = config;
    this.signatures = new LRUCache(config.maxTrackedSignatures, config.signatureWindowMs * 3);
    this.ipSignatures = new LRUCache(100000, 300000);
    this.flaggedIPs = new LRUCache(100000, 600000);
  }

  onAutoBlock(callback: (ip: string) => void): void {
    this.blockCallback = callback;
  }

  /**
   * Record a request and check for coordinated patterns
   */
  recordRequest(
    ip: string,
    method: string,
    path: string,
    headerKeys: string[],
    userAgent: string,
  ): number {
    if (!this.config.enabled) return 0;

    const signature = this.computeSignature(method, path, headerKeys, userAgent);

    // Update signature tracking
    let state = this.signatures.get(signature);
    if (!state) {
      state = {
        ips: new Set(),
        count: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        rateCounter: new SlidingWindowCounter(this.config.signatureWindowMs),
      };
      this.signatures.set(signature, state);
      this.stats.signaturesTracked++;
    }

    state.ips.add(ip);
    state.count++;
    state.lastSeen = Date.now();
    state.rateCounter.increment();

    // Track which signatures this IP uses
    let ipSigs = this.ipSignatures.get(ip);
    if (!ipSigs) {
      ipSigs = new Set();
      this.ipSignatures.set(ip, ipSigs);
    }
    ipSigs.add(signature);

    // Check for correlation
    if (state.ips.size >= this.config.minIPsForCorrelation) {
      return this.handleCorrelation(signature, state, ip);
    }

    // Return any existing boost for this IP
    const flagged = this.flaggedIPs.get(ip);
    return flagged ? flagged.boost : 0;
  }

  /**
   * Handle detected correlation
   */
  private handleCorrelation(signature: string, state: SignatureState, triggerIP: string): number {
    const severity = this.getSeverity(state.ips.size);

    // Only flag each IP once per signature
    const flagged = this.flaggedIPs.get(triggerIP);
    if (flagged && flagged.signatures.includes(signature)) {
      return flagged.boost;
    }

    this.stats.correlationsDetected++;

    // Flag all IPs in this correlation
    for (const ip of state.ips) {
      let ipFlag = this.flaggedIPs.get(ip);
      if (!ipFlag) {
        ipFlag = { boost: 0, signatures: [] };
        this.flaggedIPs.set(ip, ipFlag);
        this.stats.ipsCorrelated++;
      }
      if (!ipFlag.signatures.includes(signature)) {
        ipFlag.signatures.push(signature);
        ipFlag.boost = Math.min(100, ipFlag.boost + this.config.botScoreBoost);
      }
    }

    // Create alert
    const alert: CorrelationAlert = {
      timestamp: Date.now(),
      signature,
      signatureHuman: this.humanizeSignature(signature),
      distinctIPs: state.ips.size,
      totalRequests: state.count,
      sampleIPs: Array.from(state.ips).slice(0, 5),
      severity,
    };
    this.alerts.push(alert);
    if (this.alerts.length > this.maxAlerts) this.alerts.shift();

    log.warn(`Coordinated attack detected: ${state.ips.size} IPs, signature: ${alert.signatureHuman}, severity: ${severity}`);

    // Auto-block if threshold reached
    if (state.ips.size >= this.config.autoBlockThreshold && this.blockCallback) {
      this.stats.autoBlockTriggered++;
      for (const ip of state.ips) {
        this.blockCallback(ip);
      }
    }

    const current = this.flaggedIPs.get(triggerIP);
    return current ? current.boost : this.config.botScoreBoost;
  }

  /**
   * Compute behavior signature hash
   */
  private computeSignature(
    method: string,
    path: string,
    headerKeys: string[],
    userAgent: string,
  ): string {
    // Normalize path: strip query, generalize dynamic segments
    const normalizedPath = path. split('?')[0].split('#')[0]
      .replace(/\/\d+/g, '/:id')              // /user/123 → /user/:id
      .replace(/\/[0-9a-f]{24,}/gi, '/:hash') // MongoDB IDs, UUIDs
      .replace(/\/[0-9a-f-]{36}/gi, '/:uuid');

    // Sort header keys (order shouldn't matter)
    const sortedHeaders = headerKeys
      .map(h => h.toLowerCase())
      .filter(h => !['cookie', 'date', 'x-request-id', 'x-correlation-id'].includes(h))
      .sort()
      .join(',');

    // Extract UA family (not full string, just the engine)
    const uaFamily = this.extractUAFamily(userAgent);

    const raw = `${method}|${normalizedPath}|${sortedHeaders}|${uaFamily}`;
    return crypto.createHash('md5').update(raw).digest('hex').substring(0, 12);
  }

  private extractUAFamily(ua: string): string {
    const lower = ua.toLowerCase();
    if (lower.includes('chrome') && !lower.includes('edge')) return 'chrome';
    if (lower.includes('firefox')) return 'firefox';
    if (lower.includes('safari') && !lower.includes('chrome')) return 'safari';
    if (lower.includes('edge')) return 'edge';
    if (lower.includes('python')) return 'python';
    if (lower.includes('go-http')) return 'go';
    if (lower.includes('curl')) return 'curl';
    if (lower.includes('wget')) return 'wget';
    if (lower.includes('java')) return 'java';
    if (lower.includes('node')) return 'node';
    if (lower.includes('php')) return 'php';
    if (lower.includes('ruby')) return 'ruby';
    if (lower.includes('perl')) return 'perl';
    if (ua.trim() === '') return 'empty';
    return 'other';
  }

  private humanizeSignature(sig: string): string {
    // Try to find the signature state for human-readable description
    return `sig:${sig}`;
  }

  private getSeverity(ipCount: number): CorrelationAlert['severity'] {
    if (ipCount >= 50) return 'critical';
    if (ipCount >= 20) return 'high';
    if (ipCount >= 10) return 'medium';
    return 'low';
  }

  /**
   * Get bot score boost for a specific IP
   */
  getBotScoreBoost(ip: string): number {
    const flagged = this.flaggedIPs.get(ip);
    return flagged ? flagged.boost : 0;
  }

  getRecentAlerts(limit = 50): CorrelationAlert[] {
    return this.alerts.slice(-limit).reverse();
  }

  getStats() {
    return { ...this.stats };
  }
}
