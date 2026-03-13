// ============================================================================
// Circuit Breaker — Protects backend from cascade failure
// States: CLOSED (normal) → OPEN (backend down) → HALF_OPEN (testing)
// ============================================================================

import * as http from 'http';
import { Logger } from '../utils/logger';
import { SlidingWindowCounter } from '../utils/data-structures';

const log = new Logger('CircuitBreaker');

export interface CircuitBreakerConfig {
  enabled: boolean;
  failureThreshold: number;        // Failures before opening (default: 5)
  failureWindowMs: number;         // Window for counting failures (default: 10s)
  resetTimeoutMs: number;          // Time before trying half-open (default: 30s)
  halfOpenMaxRequests: number;     // Max requests in half-open state (default: 3)
  timeoutMs: number;               // Request timeout threshold (default: 10s)
  errorRateThreshold: number;      // Error rate to trip (0-1, default: 0.5)
}

export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  enabled: true,
  failureThreshold: 5,
  failureWindowMs: 10000,
  resetTimeoutMs: 30000,
  halfOpenMaxRequests: 3,
  timeoutMs: 10000,
  errorRateThreshold: 0.5,
};

type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export class CircuitBreaker {
  private readonly config: CircuitBreakerConfig;
  private state: CircuitState = 'CLOSED';
  private failureCounter: SlidingWindowCounter;
  private successCounter: SlidingWindowCounter;
  private halfOpenRequests = 0;
  private lastOpenTime = 0;
  private resetTimer: ReturnType<typeof setTimeout> | null = null;

  private stats = {
    totalRequests: 0,
    failures: 0,
    successes: 0,
    rejected: 0,
    stateChanges: 0,
    currentState: 'CLOSED' as CircuitState,
    lastStateChange: 0,
    avgResponseTimeMs: 0,
  };

  constructor(config: CircuitBreakerConfig) {
    this.config = config;
    this.failureCounter = new SlidingWindowCounter(config.failureWindowMs);
    this.successCounter = new SlidingWindowCounter(config.failureWindowMs);

    if (config.enabled) {
      log.info('Circuit Breaker initialized', {
        failureThreshold: config.failureThreshold,
        resetTimeout: `${config.resetTimeoutMs / 1000}s`,
      });
    }
  }

  /**
   * Check if request should be allowed through
   */
  canPass(): boolean {
    if (!this.config.enabled) return true;

    switch (this.state) {
      case 'CLOSED':
        return true;

      case 'OPEN':
        // Check if reset timeout has elapsed
        if (Date.now() - this.lastOpenTime >= this.config.resetTimeoutMs) {
          this.transitionTo('HALF_OPEN');
          return true;
        }
        this.stats.rejected++;
        return false;

      case 'HALF_OPEN':
        if (this.halfOpenRequests < this.config.halfOpenMaxRequests) {
          this.halfOpenRequests++;
          return true;
        }
        this.stats.rejected++;
        return false;
    }
  }

  /**
   * Record a successful backend response
   */
  recordSuccess(responseTimeMs: number): void {
    if (!this.config.enabled) return;

    this.stats.successes++;
    this.stats.totalRequests++;
    this.stats.avgResponseTimeMs = this.stats.avgResponseTimeMs * 0.9 + responseTimeMs * 0.1;
    this.successCounter.increment();

    if (this.state === 'HALF_OPEN') {
      // Backend is recovering, close the circuit
      this.transitionTo('CLOSED');
    }
  }

  /**
   * Record a backend failure (timeout, 5xx, connection error)
   */
  recordFailure(): void {
    if (!this.config.enabled) return;

    this.stats.failures++;
    this.stats.totalRequests++;
    this.failureCounter.increment();

    if (this.state === 'HALF_OPEN') {
      // Still failing, re-open
      this.transitionTo('OPEN');
      return;
    }

    if (this.state === 'CLOSED') {
      const failures = this.failureCounter.getCount();
      const total = failures + this.successCounter.getCount();

      // Check absolute threshold
      if (failures >= this.config.failureThreshold) {
        this.transitionTo('OPEN');
        return;
      }

      // Check error rate threshold
      if (total >= 10 && failures / total >= this.config.errorRateThreshold) {
        this.transitionTo('OPEN');
      }
    }
  }

  /**
   * Send a 503 response when circuit is open
   */
  rejectRequest(res: http.ServerResponse): void {
    res.writeHead(503, {
      'Content-Type': 'text/html; charset=utf-8',
      'Retry-After': String(Math.ceil(this.config.resetTimeoutMs / 1000)),
      'X-Shield-Circuit': this.state,
    });
    res.end(`<!DOCTYPE html><html><head><title>Service Temporarily Unavailable</title>
<meta http-equiv="refresh" content="${Math.ceil(this.config.resetTimeoutMs / 1000)}">
<style>body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0a0a0a;color:#e0e0e0}
.c{text-align:center;max-width:500px;padding:40px}.icon{font-size:64px;margin-bottom:20px}
h1{margin:0 0 10px;font-size:24px}p{color:#888;line-height:1.6}.retry{margin-top:20px;color:#666;font-size:14px}</style></head>
<body><div class="c"><div class="icon">⚡</div><h1>Service Temporarily Unavailable</h1>
<p>Shield Guard has detected backend instability and temporarily suspended traffic to protect the service.</p>
<p class="retry">Automatic retry in ${Math.ceil(this.config.resetTimeoutMs / 1000)} seconds...</p></div></body></html>`);
  }

  private transitionTo(newState: CircuitState): void {
    const oldState = this.state;
    this.state = newState;
    this.stats.currentState = newState;
    this.stats.stateChanges++;
    this.stats.lastStateChange = Date.now();

    if (newState === 'OPEN') {
      this.lastOpenTime = Date.now();
      this.halfOpenRequests = 0;
      log.error(`Circuit OPENED — backend failures exceeded threshold (${oldState} → OPEN)`);
    } else if (newState === 'HALF_OPEN') {
      this.halfOpenRequests = 0;
      log.warn('Circuit HALF-OPEN — testing backend recovery');
    } else if (newState === 'CLOSED') {
      this.halfOpenRequests = 0;
      log.info(`Circuit CLOSED — backend recovered (${oldState} → CLOSED)`);
    }
  }

  getState(): CircuitState { return this.state; }
  getStats() { return { ...this.stats }; }
}

// ============================================================================
// Traffic Shaper — Intelligent bandwidth allocation per client class
// ============================================================================

export interface TrafficShaperConfig {
  enabled: boolean;
  classes: {
    premium: { rateLimit: number; burstSize: number };
    normal: { rateLimit: number; burstSize: number };
    suspicious: { rateLimit: number; burstSize: number };
    bot: { rateLimit: number; burstSize: number };
  };
  premiumHeaders: string[];      // Headers that identify premium clients
  premiumIPs: string[];          // IPs classified as premium
}

export const DEFAULT_TRAFFIC_SHAPER_CONFIG: TrafficShaperConfig = {
  enabled: true,
  classes: {
    premium: { rateLimit: 1000, burstSize: 2000 },
    normal: { rateLimit: 200, burstSize: 500 },
    suspicious: { rateLimit: 20, burstSize: 30 },
    bot: { rateLimit: 5, burstSize: 10 },
  },
  premiumHeaders: ['x-api-key', 'authorization'],
  premiumIPs: [],
};

import { TokenBucket, LRUCache } from '../utils/data-structures';

export type ClientClass = 'premium' | 'normal' | 'suspicious' | 'bot';

export class TrafficShaper {
  private readonly config: TrafficShaperConfig;
  private buckets: LRUCache<TokenBucket>;
  private ipClasses: LRUCache<ClientClass>;
  private premiumIPs: Set<string>;

  private stats = {
    totalShaped: 0,
    premiumAllowed: 0,
    normalAllowed: 0,
    suspiciousThrottled: 0,
    botThrottled: 0,
  };

  constructor(config: TrafficShaperConfig) {
    this.config = config;
    this.buckets = new LRUCache(100000, 120000);
    this.ipClasses = new LRUCache(100000, 300000);
    this.premiumIPs = new Set(config.premiumIPs);
  }

  /**
   * Classify a client and check if they should be throttled
   */
  shouldThrottle(
    ip: string,
    headers: Record<string, string>,
    botScore: number,
  ): { throttled: boolean; clientClass: ClientClass; retryAfterMs: number } {
    if (!this.config.enabled) {
      return { throttled: false, clientClass: 'normal', retryAfterMs: 0 };
    }

    const clientClass = this.classifyClient(ip, headers, botScore);
    this.ipClasses.set(ip, clientClass);

    const classConfig = this.config.classes[clientClass];
    const bucketKey = `${ip}:${clientClass}`;

    let bucket = this.buckets.get(bucketKey);
    if (!bucket) {
      bucket = new TokenBucket(classConfig.burstSize, classConfig.rateLimit);
      this.buckets.set(bucketKey, bucket);
    }

    this.stats.totalShaped++;

    if (bucket.consume(1)) {
      switch (clientClass) {
        case 'premium': this.stats.premiumAllowed++; break;
        case 'normal': this.stats.normalAllowed++; break;
      }
      return { throttled: false, clientClass, retryAfterMs: 0 };
    }

    switch (clientClass) {
      case 'suspicious': this.stats.suspiciousThrottled++; break;
      case 'bot': this.stats.botThrottled++; break;
    }

    const retryMs = clientClass === 'bot' ? 10000 : clientClass === 'suspicious' ? 5000 : 1000;
    return { throttled: true, clientClass, retryAfterMs: retryMs };
  }

  private classifyClient(ip: string, headers: Record<string, string>, botScore: number): ClientClass {
    // Priority 1: Premium by IP
    if (this.premiumIPs.has(ip)) return 'premium';

    // Priority 2: Premium by header
    for (const h of this.config.premiumHeaders) {
      if (headers[h]) return 'premium';
    }

    // Priority 3: Bot score based
    if (botScore >= 70) return 'bot';
    if (botScore >= 40) return 'suspicious';

    return 'normal';
  }

  /**
   * Escalate an IP to a different class
   */
  escalateIP(ip: string, newClass: ClientClass): void {
    this.ipClasses.set(ip, newClass);
  }

  getClientClass(ip: string): ClientClass {
    return this.ipClasses.get(ip) || 'normal';
  }

  getStats() {
    return { ...this.stats };
  }
}
