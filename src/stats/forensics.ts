// ============================================================================
// Request Forensics — Capture, analyze, and replay blocked requests
// ============================================================================

import { CircularBuffer } from '../utils/data-structures';
import { Logger } from '../utils/logger';

const log = new Logger('Forensics');

export interface ForensicsConfig {
  enabled: boolean;
  maxCaptures: number;           // Ring buffer size (default: 10000)
  captureBody: boolean;          // Include request body in capture
  maxBodyBytes: number;          // Max body bytes to capture (default: 4096)
  minThreatLevel: number;        // Min threat level to capture (0-4, default: 1)
}

export const DEFAULT_FORENSICS_CONFIG: ForensicsConfig = {
  enabled: true,
  maxCaptures: 10000,
  captureBody: true,
  maxBodyBytes: 4096,
  minThreatLevel: 1,
};

export interface CapturedRequest {
  id: string;
  timestamp: number;
  ip: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  filterResult: {
    action: string;
    reason: string;
    layer: string;
    threatLevel: number;
  };
  geoCountry?: string;
  userAgent?: string;
  responseTimeUs?: number;
}

export class RequestForensics {
  private readonly config: ForensicsConfig;
  private captures: CircularBuffer<CapturedRequest>;
  private captureIndex = 0;

  private stats = {
    totalCaptured: 0,
    byLayer: {} as Record<string, number>,
    byThreatLevel: [0, 0, 0, 0, 0] as number[],
    topReasons: new Map<string, number>(),
  };

  constructor(config: ForensicsConfig) {
    this.config = config;
    this.captures = new CircularBuffer(config.maxCaptures);
  }

  /**
   * Capture a blocked/flagged request for forensic analysis
   */
  capture(
    ip: string,
    method: string,
    url: string,
    headers: Record<string, string>,
    body: string | undefined,
    filterResult: CapturedRequest['filterResult'],
    geoCountry?: string,
  ): void {
    if (!this.config.enabled) return;
    if (filterResult.threatLevel < this.config.minThreatLevel) return;

    const captured: CapturedRequest = {
      id: `cap_${++this.captureIndex}`,
      timestamp: Date.now(),
      ip,
      method,
      url: url.substring(0, 2000),
      headers: this.sanitizeHeaders(headers),
      filterResult,
      userAgent: headers['user-agent']?.substring(0, 200),
      geoCountry,
    };

    if (this.config.captureBody && body) {
      captured.body = body.substring(0, this.config.maxBodyBytes);
    }

    this.captures.push(captured);
    this.stats.totalCaptured++;

    // Track by layer
    this.stats.byLayer[filterResult.layer] = (this.stats.byLayer[filterResult.layer] || 0) + 1;

    // Track by threat level
    if (filterResult.threatLevel >= 0 && filterResult.threatLevel <= 4) {
      this.stats.byThreatLevel[filterResult.threatLevel]++;
    }

    // Track top reasons
    const reason = filterResult.reason.split(':')[0].trim();
    this.stats.topReasons.set(reason, (this.stats.topReasons.get(reason) || 0) + 1);
    if (this.stats.topReasons.size > 100) {
      // Trim to top 50
      const sorted = [...this.stats.topReasons.entries()].sort((a, b) => b[1] - a[1]).slice(0, 50);
      this.stats.topReasons = new Map(sorted);
    }
  }

  /**
   * Get recent captures (for dashboard/API)
   */
  getCaptures(count: number = 50, filter?: { layer?: string; ip?: string; minThreat?: number }): CapturedRequest[] {
    const all = this.captures.toArray();
    let results = all;

    if (filter) {
      if (filter.layer) results = results.filter(c => c.filterResult.layer === filter.layer);
      if (filter.ip) results = results.filter(c => c.ip === filter.ip);
      if (filter.minThreat !== undefined) results = results.filter(c => c.filterResult.threatLevel >= filter.minThreat!);
    }

    return results.slice(-count);
  }

  /**
   * Export captures as HAR (HTTP Archive) format
   */
  exportHAR(captures?: CapturedRequest[]): object {
    const items = captures || this.captures.toArray();

    return {
      log: {
        version: '1.2',
        creator: { name: 'Shield Guard Forensics', version: '1.0' },
        entries: items.map(c => ({
          startedDateTime: new Date(c.timestamp).toISOString(),
          request: {
            method: c.method,
            url: c.url,
            httpVersion: 'HTTP/1.1',
            headers: Object.entries(c.headers).map(([name, value]) => ({ name, value })),
            queryString: [],
            bodySize: c.body?.length || 0,
            postData: c.body ? { mimeType: c.headers['content-type'] || 'text/plain', text: c.body } : undefined,
          },
          response: {
            status: c.filterResult.action === 'DROP' ? 403 : c.filterResult.action === 'CHALLENGE' ? 429 : 200,
            statusText: c.filterResult.reason,
            headers: [],
            content: { size: 0, mimeType: 'text/html' },
            bodySize: 0,
          },
          cache: {},
          timings: { send: 0, wait: c.responseTimeUs ? c.responseTimeUs / 1000 : 0, receive: 0 },
          _shieldGuard: {
            ip: c.ip,
            layer: c.filterResult.layer,
            threatLevel: c.filterResult.threatLevel,
            geoCountry: c.geoCountry,
          },
        })),
      },
    };
  }

  /**
   * Get forensics summary stats
   */
  getForensicsSummary() {
    const topReasons = [...this.stats.topReasons.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([reason, count]) => ({ reason, count }));

    return {
      totalCaptured: this.stats.totalCaptured,
      bufferSize: this.captures.toArray().length,
      maxCaptures: this.config.maxCaptures,
      byLayer: { ...this.stats.byLayer },
      byThreatLevel: {
        none: this.stats.byThreatLevel[0],
        low: this.stats.byThreatLevel[1],
        medium: this.stats.byThreatLevel[2],
        high: this.stats.byThreatLevel[3],
        critical: this.stats.byThreatLevel[4],
      },
      topReasons,
    };
  }

  private sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
    const safe: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      const key = k.toLowerCase();
      if (key === 'cookie' || key === 'authorization') {
        safe[key] = '[REDACTED]';
      } else {
        safe[key] = typeof v === 'string' ? v.substring(0, 500) : String(v);
      }
    }
    return safe;
  }

  getStats() {
    return {
      totalCaptured: this.stats.totalCaptured,
      bufferUsed: this.captures.toArray().length,
      topLayers: { ...this.stats.byLayer },
    };
  }
}
