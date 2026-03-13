// ============================================================================
// Threat Intelligence Feed — Pull blocklists from public threat intel sources
// ============================================================================

import * as https from 'https';
import * as http from 'http';
import { Logger } from '../utils/logger';

const log = new Logger('ThreatIntel');

export interface ThreatIntelConfig {
  enabled: boolean;
  feeds: ThreatFeed[];
  refreshIntervalMs: number;     // How often to refresh feeds (default: 1h)
  maxEntries: number;            // Max IPs to store (default: 100,000)
}

export interface ThreatFeed {
  name: string;
  url: string;
  format: 'plain' | 'json' | 'csv';
  jsonPath?: string;             // JSON path for IP extraction
  enabled: boolean;
}

export const DEFAULT_THREAT_INTEL_CONFIG: ThreatIntelConfig = {
  enabled: false,
  feeds: [
    { name: 'Emerging Threats', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', format: 'plain', enabled: true },
    { name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop.txt', format: 'plain', enabled: true },
    { name: 'Feodo Tracker', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', format: 'plain', enabled: true },
  ],
  refreshIntervalMs: 3600000,
  maxEntries: 100000,
};

const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

export class ThreatIntelFeed {
  private readonly config: ThreatIntelConfig;
  private maliciousIPs: Set<string> = new Set();
  private cidrRanges: Array<{ network: number; mask: number; feed: string }> = [];
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private blacklistCallback: ((ip: string) => void) | null = null;

  private stats = {
    totalIPs: 0,
    totalCIDRs: 0,
    lastRefresh: 0,
    feedsLoaded: 0,
    feedErrors: 0,
    lookups: 0,
    hits: 0,
  };

  constructor(config: ThreatIntelConfig) {
    this.config = config;
  }

  /**
   * Start the feed refresh loop
   */
  start(): void {
    if (!this.config.enabled) return;

    // Initial load
    this.refreshAll();

    // Periodic refresh
    this.refreshTimer = setInterval(() => this.refreshAll(), this.config.refreshIntervalMs);
    this.refreshTimer.unref();

    log.info('Threat intel feed started', {
      feeds: this.config.feeds.filter(f => f.enabled).length,
      refreshInterval: `${this.config.refreshIntervalMs / 60000}m`,
    });
  }

  /**
   * Set callback for auto-blacklisting via L3
   */
  onBlacklist(cb: (ip: string) => void): void {
    this.blacklistCallback = cb;
  }

  /**
   * Check if an IP is in any threat intel feed
   */
  isKnownThreat(ip: string): { isThreat: boolean; source?: string } {
    this.stats.lookups++;

    // Exact match
    if (this.maliciousIPs.has(ip)) {
      this.stats.hits++;
      return { isThreat: true, source: 'exact' };
    }

    // CIDR match
    const ipNum = this.ipToNumber(ip);
    if (ipNum !== null) {
      for (const range of this.cidrRanges) {
        if ((ipNum & range.mask) === range.network) {
          this.stats.hits++;
          return { isThreat: true, source: range.feed };
        }
      }
    }

    return { isThreat: false };
  }

  private async refreshAll(): Promise<void> {
    const enabledFeeds = this.config.feeds.filter(f => f.enabled);
    let loaded = 0;

    for (const feed of enabledFeeds) {
      try {
        const data = await this.fetchFeed(feed.url);
        const ips = this.parseFeed(data, feed);
        let added = 0;

        for (const entry of ips) {
          if (this.maliciousIPs.size >= this.config.maxEntries) break;

          if (entry.includes('/')) {
            const cidr = this.parseCIDR(entry);
            if (cidr) {
              this.cidrRanges.push({ ...cidr, feed: feed.name });
            }
          } else {
            this.maliciousIPs.add(entry);
            added++;
          }
        }

        loaded++;
        log.debug(`Loaded ${added} IPs from ${feed.name}`);
      } catch (e) {
        this.stats.feedErrors++;
        log.warn(`Failed to load feed: ${feed.name}`);
      }
    }

    this.stats.totalIPs = this.maliciousIPs.size;
    this.stats.totalCIDRs = this.cidrRanges.length;
    this.stats.lastRefresh = Date.now();
    this.stats.feedsLoaded = loaded;

    log.info(`Threat intel refreshed: ${this.maliciousIPs.size} IPs, ${this.cidrRanges.length} CIDRs from ${loaded} feeds`);
  }

  private fetchFeed(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const client = url.startsWith('https') ? https : http;
      const req = client.get(url, { timeout: 15000 }, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}`));
          res.resume();
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
  }

  private parseFeed(data: string, feed: ThreatFeed): string[] {
    const ips: string[] = [];

    if (feed.format === 'plain') {
      for (const line of data.split('\n')) {
        const trimmed = line.trim().split(/[;\s#]/)[0].trim();
        if (trimmed && IP_REGEX.test(trimmed)) {
          ips.push(trimmed);
        }
      }
    } else if (feed.format === 'csv') {
      for (const line of data.split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue;
        const firstCol = line.split(',')[0].trim().replace(/"/g, '');
        if (IP_REGEX.test(firstCol)) ips.push(firstCol);
      }
    }

    return ips;
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  }

  private parseCIDR(cidr: string): { network: number; mask: number } | null {
    const [ip, bits] = cidr.split('/');
    const network = this.ipToNumber(ip);
    const prefixLen = parseInt(bits);
    if (network === null || isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return null;
    const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
    return { network: (network & mask) >>> 0, mask };
  }

  stop(): void {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
  }

  getStats() { return { ...this.stats }; }
}
