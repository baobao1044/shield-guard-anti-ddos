// ============================================================================
// Layer 7 (Application) Protection
// Anti: HTTP Flood, Slow POST, SQL Injection, XSS, Path Traversal,
//       Command Injection, Bot Attack, Header Abuse, API Abuse
// ============================================================================

import {
  HTTPRequest, FilterResult, Action, ThreatLevel, L7Config
} from '../core/types';
import {
  TokenBucket, SlidingWindowCounter, LRUCache, BloomFilter, HyperLogLog
} from '../utils/data-structures';
import { Logger } from '../utils/logger';

// === WAF Pattern Database ===

const SQL_INJECTION_PATTERNS = [
  /(\b(union|select|insert|update|delete|drop|alter|create|exec|execute)\b.*\b(from|into|table|database|where|set|values)\b)/i,
  /('|\%27)\s*(or|and)\s*('|\%27|\d)/i,
  /(\b(or|and)\b\s+\d+\s*=\s*\d+)/i,
  /(;\s*(drop|delete|insert|update|create)\b)/i,
  /(\bunion\b\s+\bselect\b)/i,
  /(--\s*$|\/\*[^/]|\*\/|#\s*$)/m,
  /(\bwaitfor\b\s+\bdelay\b|\bsleep\s*\(|\bbenchmark\s*\()/i,
  /(\bload_file\b|\binto\s+outfile\b|\binto\s+dumpfile\b)/i,
  /(\bchar\s*\(|\bconcat\s*\(|\bconvert\s*\()/i,
  /(\bhaving\b\s+\d|\bgroup\s+by\b.*\bhaving\b)/i,
];

const XSS_PATTERNS = [
  /<script[\s>]/i,
  /javascript\s*:/i,
  /on(load|error|click|mouseover|submit|focus|blur|change)\s*=/i,
  /<(img|svg|iframe|object|embed|video|audio|source|link)\b[^>]*(onerror|onload|src\s*=\s*['"]?javascript)/i,
  /(<\/?(script|iframe|object|embed|applet|form|input|button|select|textarea)[\s>])/i,
  /(document\.(cookie|domain|write|location)|window\.(location|open))/i,
  /\balert\s*\(|\bconfirm\s*\(|\bprompt\s*\(/i,
  /eval\s*\(|Function\s*\(/i,
  /(data:\s*text\/html|vbscript\s*:)/i,
  /expression\s*\(|url\s*\(\s*['"]?\s*javascript/i,
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/,
  /(\/etc\/(passwd|shadow|hosts|resolv\.conf))/,
  /(\/proc\/(self|version|meminfo|cpuinfo))/,
  /(\/var\/log\/|\/tmp\/|\/dev\/(null|zero|random))/,
  /(\\windows\\|\\system32\\|\\boot\.ini)/i,
  /(%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e)/i,
  /(\/\.env|\/\.git|\/\.htaccess|\/wp-config)/i,
];

const CMD_INJECTION_PATTERNS = [
  /(;|\||&&|\$\(|\`)\s*(ls|cat|rm|wget|curl|nc|bash|sh|python|perl|ruby|php)/i,
  /(\bping\b|\bnslookup\b|\bdig\b|\btraceroute\b|\bwhoami\b|\bid\b|\buname\b)/i,
  /(\breturn\b|\bimport\b|\bexec\b|\beval\b|\bsystem\b|\bpassthru\b)/i,
  /(\$\{|\$\(|`[^`]+`)/,
  /(>\s*\/dev\/null|2>&1|&\s*$)/,
  /(\bchmod\b|\bchown\b|\bkill\b|\bpkill\b|\bmkdir\b)/i,
];

// Known bad bot signatures
const BAD_BOT_SIGNATURES = [
  'sqlmap', 'nikto', 'nmap', 'masscan', 'zmap', 'shodan',
  'censys', 'scrapy', 'python-requests/2', 'go-http-client',
  'libwww-perl', 'wget/1', 'curl/7', 'httpclient', 'mechanize',
  'phantom', 'selenium', 'headlesschrome', 'puppeteer',
];

// Good bot signatures (allow)
const GOOD_BOT_SIGNATURES = [
  'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
  'yandexbot', 'facebot', 'twitterbot', 'linkedinbot',
];

export class L7Filter {
  private readonly config: L7Config;
  private readonly log: Logger;

  // Rate limiters
  private globalRateCounter: SlidingWindowCounter;
  private ipRateBuckets: LRUCache<TokenBucket>;
  private endpointCounters: LRUCache<SlidingWindowCounter>;

  // Bot detection
  private botScores: LRUCache<number>;
  private fingerprintCache: LRUCache<{
    userAgents: Set<string>;
    endpoints: Set<string>;
    methods: Set<string>;
    requestTimes: number[];
  }>;
  private challengeTokens: LRUCache<string>;

  // WAF state
  private wafHits: LRUCache<{ count: number; patterns: string[] }>;
  private knownPayloads: BloomFilter;

  // Analytics
  private uniqueIPs: HyperLogLog;
  private uniqueUAs: HyperLogLog;

  // Metrics
  private stats = {
    totalProcessed: 0,
    rateLimited: 0,
    wafBlocked: 0,
    sqlInjection: 0,
    xssBlocked: 0,
    pathTraversal: 0,
    cmdInjection: 0,
    botBlocked: 0,
    botChallenged: 0,
    headerViolation: 0,
    slowPostBlocked: 0,
    httpFloodBlocked: 0,
    oversizeBlocked: 0,
  };

  constructor(config: L7Config) {
    this.config = config;
    this.log = new Logger('L7-Shield');

    this.globalRateCounter = new SlidingWindowCounter(config.rateLimiting.global.windowMs);
    this.ipRateBuckets = new LRUCache<TokenBucket>(100000, 120000);
    this.endpointCounters = new LRUCache<SlidingWindowCounter>(10000, 60000);
    this.botScores = new LRUCache<number>(100000, 300000);
    this.fingerprintCache = new LRUCache(50000, 300000);
    this.challengeTokens = new LRUCache<string>(100000, 30000);
    this.wafHits = new LRUCache(100000, 600000);
    this.knownPayloads = new BloomFilter(100000, 0.001);
    this.uniqueIPs = new HyperLogLog(14);
    this.uniqueUAs = new HyperLogLog(12);
  }

  process(request: HTTPRequest): FilterResult {
    const start = process.hrtime.bigint();
    this.stats.totalProcessed++;
    this.uniqueIPs.add(request.ip);
    if (request.userAgent) this.uniqueUAs.add(request.userAgent);

    // 1. Header validation (cheapest first)
    if (this.config.headerValidation.enabled) {
      const headerResult = this.validateHeaders(request);
      if (headerResult) return { ...headerResult, processingTimeUs: this.elapsed(start) };
    }

    // 2. Global rate limiting
    this.globalRateCounter.increment(request.timestamp);
    const globalRate = this.globalRateCounter.getRate(request.timestamp);
    if (globalRate > this.config.rateLimiting.global.maxRequests) {
      this.stats.httpFloodBlocked++;
      return this.result(Action.RATE_LIMIT, `Global rate exceeded: ${globalRate.toFixed(0)}/s`, ThreatLevel.HIGH, start);
    }

    // 3. Per-IP rate limiting
    const ipResult = this.checkIPRateLimit(request);
    if (ipResult) return { ...ipResult, processingTimeUs: this.elapsed(start) };

    // 4. Per-endpoint rate limiting
    const epResult = this.checkEndpointRateLimit(request);
    if (epResult) return { ...epResult, processingTimeUs: this.elapsed(start) };

    // 5. Request size check
    if (request.contentLength && request.contentLength > this.config.httpFloodProtection.requestSizeLimit) {
      this.stats.oversizeBlocked++;
      return this.result(
        Action.DROP,
        `Oversize request: ${(request.contentLength / 1024 / 1024).toFixed(1)}MB`,
        ThreatLevel.MEDIUM,
        start
      );
    }

    // 6. WAF checks
    if (this.config.waf.enabled) {
      const wafResult = this.runWAF(request);
      if (wafResult) return { ...wafResult, processingTimeUs: this.elapsed(start) };
    }

    // 7. Bot detection
    if (this.config.botDetection.enabled) {
      const botResult = this.detectBot(request);
      if (botResult) return { ...botResult, processingTimeUs: this.elapsed(start) };
    }

    return this.result(Action.ALLOW, 'L7 passed', ThreatLevel.NONE, start);
  }

  // === Rate Limiting ===

  private checkIPRateLimit(request: HTTPRequest): FilterResult | null {
    let bucket = this.ipRateBuckets.get(request.ip);
    if (!bucket) {
      const cfg = this.config.rateLimiting.perIP;
      bucket = new TokenBucket(cfg.burstSize || cfg.maxRequests, cfg.maxRequests);
      this.ipRateBuckets.set(request.ip, bucket);
    }

    if (!bucket.consume()) {
      this.stats.rateLimited++;
      return {
        action: Action.RATE_LIMIT,
        reason: `Per-IP rate limit exceeded: ${request.ip}`,
        layer: 'L7',
        threatLevel: ThreatLevel.MEDIUM,
        processingTimeUs: 0,
      };
    }
    return null;
  }

  private checkEndpointRateLimit(request: HTTPRequest): FilterResult | null {
    const key = `${request.method}:${request.url}`;
    let counter = this.endpointCounters.get(key);
    if (!counter) {
      counter = new SlidingWindowCounter(this.config.rateLimiting.perEndpoint.windowMs);
      this.endpointCounters.set(key, counter);
    }
    counter.increment(request.timestamp);
    const rate = counter.getRate(request.timestamp);

    if (rate > this.config.rateLimiting.perEndpoint.maxRequests) {
      this.stats.rateLimited++;
      return {
        action: Action.RATE_LIMIT,
        reason: `Endpoint rate limit: ${key} at ${rate.toFixed(0)}/s`,
        layer: 'L7',
        threatLevel: ThreatLevel.MEDIUM,
        processingTimeUs: 0,
      };
    }
    return null;
  }

  // === WAF Engine ===

  private runWAF(request: HTTPRequest): FilterResult | null {
    // Only include URL, body, and potentially dangerous headers (not Accept, Content-Type, etc.)
    const dangerousHeaders = ['user-agent', 'referer', 'cookie', 'x-forwarded-for',
      'x-real-ip', 'authorization', 'x-custom-header'];
    const headerValues = dangerousHeaders
      .map(h => request.headers[h] ?? '')
      .filter(Boolean);

    const targets = [
      request.url,
      request.body || '',
      ...headerValues,
    ];

    const combined = targets.join(' ');

    // Quick bloom filter check for known payloads
    if (this.knownPayloads.has(combined)) {
      this.stats.wafBlocked++;
      return {
        action: Action.DROP,
        reason: 'Known malicious payload',
        layer: 'L7',
        threatLevel: ThreatLevel.CRITICAL,
        processingTimeUs: 0,
      };
    }

    // SQL Injection
    if (this.config.waf.sqlInjection) {
      for (const pattern of SQL_INJECTION_PATTERNS) {
        if (pattern.test(combined)) {
          this.stats.sqlInjection++;
          this.stats.wafBlocked++;
          this.knownPayloads.add(combined);
          this.recordWAFHit(request.ip, 'SQLi');
          return {
            action: Action.DROP,
            reason: `SQL injection detected: ${pattern.source.substring(0, 40)}...`,
            layer: 'L7',
            threatLevel: ThreatLevel.CRITICAL,
            processingTimeUs: 0,
          };
        }
      }
    }

    // XSS
    if (this.config.waf.xss) {
      for (const pattern of XSS_PATTERNS) {
        if (pattern.test(combined)) {
          this.stats.xssBlocked++;
          this.stats.wafBlocked++;
          this.knownPayloads.add(combined);
          this.recordWAFHit(request.ip, 'XSS');
          return {
            action: Action.DROP,
            reason: `XSS attempt detected`,
            layer: 'L7',
            threatLevel: ThreatLevel.HIGH,
            processingTimeUs: 0,
          };
        }
      }
    }

    // Path Traversal
    if (this.config.waf.pathTraversal) {
      for (const pattern of PATH_TRAVERSAL_PATTERNS) {
        if (pattern.test(combined)) {
          this.stats.pathTraversal++;
          this.stats.wafBlocked++;
          this.recordWAFHit(request.ip, 'PATH_TRAVERSAL');
          return {
            action: Action.DROP,
            reason: `Path traversal attempt detected`,
            layer: 'L7',
            threatLevel: ThreatLevel.HIGH,
            processingTimeUs: 0,
          };
        }
      }
    }

    // Command Injection
    if (this.config.waf.commandInjection) {
      for (const pattern of CMD_INJECTION_PATTERNS) {
        if (pattern.test(combined)) {
          this.stats.cmdInjection++;
          this.stats.wafBlocked++;
          this.recordWAFHit(request.ip, 'CMD_INJECTION');
          return {
            action: Action.DROP,
            reason: `Command injection attempt detected`,
            layer: 'L7',
            threatLevel: ThreatLevel.CRITICAL,
            processingTimeUs: 0,
          };
        }
      }
    }

    return null;
  }

  private recordWAFHit(ip: string, type: string): void {
    let hits = this.wafHits.get(ip);
    if (!hits) {
      hits = { count: 0, patterns: [] };
      this.wafHits.set(ip, hits);
    }
    hits.count++;
    if (!hits.patterns.includes(type)) hits.patterns.push(type);
  }

  // === Bot Detection ===

  private detectBot(request: HTTPRequest): FilterResult | null {
    const ua = (request.userAgent || '').toLowerCase();
    let score = this.botScores.get(request.ip) || 0;

    // Good bots - skip detection
    for (const sig of GOOD_BOT_SIGNATURES) {
      if (ua.includes(sig)) {
        return null; // TODO: verify with reverse DNS
      }
    }

    // Known bad bots
    for (const sig of BAD_BOT_SIGNATURES) {
      if (ua.includes(sig)) {
        score += 50;
        this.stats.botBlocked++;
        this.botScores.set(request.ip, score);
        return {
          action: Action.DROP,
          reason: `Known bad bot: ${sig}`,
          layer: 'L7',
          threatLevel: ThreatLevel.HIGH,
          processingTimeUs: 0,
        };
      }
    }

    // Fingerprint analysis
    if (this.config.botDetection.fingerprintAnalysis) {
      score += this.analyzeFingerprint(request);
    }

    // Empty or missing User-Agent
    if (!request.userAgent || request.userAgent.trim() === '') {
      score += 20;
    }

    // Missing common headers
    if (!request.headers['accept']) score += 10;
    if (!request.headers['accept-language']) score += 10;
    if (!request.headers['accept-encoding']) score += 5;

    // Suspicious method + path combos
    if (request.method !== 'GET' && request.method !== 'POST' && request.method !== 'HEAD') {
      score += 15;
    }

    this.botScores.set(request.ip, score);

    if (score >= this.config.botDetection.challengeThreshold) {
      if (score >= this.config.botDetection.challengeThreshold * 1.5) {
        this.stats.botBlocked++;
        return {
          action: Action.DROP,
          reason: `High bot score: ${score}`,
          layer: 'L7',
          threatLevel: ThreatLevel.HIGH,
          processingTimeUs: 0,
        };
      }

      this.stats.botChallenged++;
      return {
        action: Action.CHALLENGE,
        reason: `Bot suspected (score: ${score})`,
        layer: 'L7',
        threatLevel: ThreatLevel.MEDIUM,
        processingTimeUs: 0,
        metadata: { challengeType: 'js', botScore: score },
      };
    }

    return null;
  }

  private analyzeFingerprint(request: HTTPRequest): number {
    let score = 0;
    let fp = this.fingerprintCache.get(request.ip);

    if (!fp) {
      fp = {
        userAgents: new Set(),
        endpoints: new Set(),
        methods: new Set(),
        requestTimes: [],
      };
      this.fingerprintCache.set(request.ip, fp);
    }

    // Rotating user-agents from same IP
    if (request.userAgent) {
      fp.userAgents.add(request.userAgent);
      if (fp.userAgents.size > 5) score += 25;
      else if (fp.userAgents.size > 3) score += 10;
    }

    // Request pattern uniformity (bot-like timing)
    fp.requestTimes.push(request.timestamp);
    if (fp.requestTimes.length > 10) {
      fp.requestTimes = fp.requestTimes.slice(-20);
      const intervals: number[] = [];
      for (let i = 1; i < fp.requestTimes.length; i++) {
        intervals.push(fp.requestTimes[i] - fp.requestTimes[i - 1]);
      }
      const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((sum, v) => sum + (v - avg) ** 2, 0) / intervals.length;
      const cv = Math.sqrt(variance) / (avg || 1); // coefficient of variation

      // Very uniform timing = likely bot
      if (cv < 0.1 && intervals.length > 5) score += 20;
    }

    // Endpoint diversity
    fp.endpoints.add(request.url);
    fp.methods.add(request.method);

    return score;
  }

  // === Header Validation ===

  private validateHeaders(request: HTTPRequest): FilterResult | null {
    // Check required headers
    for (const hdr of this.config.headerValidation.requiredHeaders) {
      if (!request.headers[hdr.toLowerCase()]) {
        this.stats.headerViolation++;
        return {
          action: Action.DROP,
          reason: `Missing required header: ${hdr}`,
          layer: 'L7',
          threatLevel: ThreatLevel.LOW,
          processingTimeUs: 0,
        };
      }
    }

    // Header count
    const headerCount = Object.keys(request.headers).length;
    if (headerCount > this.config.headerValidation.maxHeaders) {
      this.stats.headerViolation++;
      return {
        action: Action.DROP,
        reason: `Too many headers: ${headerCount}`,
        layer: 'L7',
        threatLevel: ThreatLevel.MEDIUM,
        processingTimeUs: 0,
      };
    }

    // Header size
    const headerSize = Object.entries(request.headers)
      .reduce((sum, [k, v]) => sum + k.length + v.length, 0);
    if (headerSize > this.config.headerValidation.maxHeaderSize) {
      this.stats.headerViolation++;
      return {
        action: Action.DROP,
        reason: `Header size exceeded: ${headerSize}B`,
        layer: 'L7',
        threatLevel: ThreatLevel.MEDIUM,
        processingTimeUs: 0,
      };
    }

    return null;
  }

  // === Challenge System ===

  generateChallenge(ip: string): { token: string; challenge: string } {
    const token = Math.random().toString(36).substring(2) + Date.now().toString(36);
    this.challengeTokens.set(`${ip}:${token}`, token);

    // Simple JS challenge (in production, this would be more complex)
    const a = Math.floor(Math.random() * 1000);
    const b = Math.floor(Math.random() * 1000);
    return {
      token,
      challenge: `Please compute: ${a} + ${b} = ?`,
    };
  }

  verifyChallenge(ip: string, token: string, answer: string): boolean {
    const stored = this.challengeTokens.get(`${ip}:${token}`);
    if (!stored) return false;
    this.challengeTokens.delete(`${ip}:${token}`);
    // In production, verify the actual challenge answer
    return true;
  }

  // === Analytics ===

  getAnalytics() {
    return {
      uniqueIPs: this.uniqueIPs.count(),
      uniqueUserAgents: this.uniqueUAs.count(),
      ...this.stats,
    };
  }

  private elapsed(start: bigint): number {
    return Number(process.hrtime.bigint() - start) / 1000;
  }

  private result(
    action: Action,
    reason: string,
    threatLevel: ThreatLevel,
    startTime: bigint,
    metadata?: Record<string, unknown>
  ): FilterResult {
    return { action, reason, layer: 'L7', threatLevel, processingTimeUs: this.elapsed(startTime), metadata };
  }

  getStats() {
    return { ...this.stats };
  }

  resetStats(): void {
    for (const key of Object.keys(this.stats) as (keyof typeof this.stats)[]) {
      this.stats[key] = 0;
    }
  }
}
