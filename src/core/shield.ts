// ============================================================================
// Anti-DDoS Shield Engine - Main Orchestrator
// Combines L3 + L4 + L7 with adaptive threat response
// ============================================================================

import {
  PacketInfo, HTTPRequest, FilterResult, Action, ThreatLevel,
  ShieldConfig, ShieldMetrics, Protocol
} from './types';
import { DEFAULT_CONFIG } from './config';
import { L3Filter } from '../layers/l3-filter';
import { L4Filter } from '../layers/l4-filter';
import { L7Filter } from '../layers/l7-filter';
import { SlidingWindowCounter, CircularBuffer } from '../utils/data-structures';
import { Logger } from '../utils/logger';

export interface BlockEvent {
  ts: number;
  ip: string;
  method?: string;
  path?: string;
  layer: string;
  reasonCode: string;
  reason: string;
  action: string;
  threatLevel: ThreatLevel;
  source?: string;
}

export class AntiDDoSShield {
  private readonly config: ShieldConfig;
  private readonly log: Logger;

  // Protection layers
  readonly l3: L3Filter;
  readonly l4: L4Filter;
  readonly l7: L7Filter;

  // Global metrics
  private totalPackets: number = 0;
  private totalAllowed: number = 0;
  private totalDropped: number = 0;
  private totalChallenged: number = 0;
  private totalRateLimited: number = 0;
  private processingTimes: CircularBuffer<number>;
  private rpsCounter: SlidingWindowCounter;
  private startTime: number;

  // Threat tracking
  private threatsByLayer = { l3: 0, l4: 0, l7: 0 };
  private attackVectors: Map<string, number> = new Map();
  private reasonCodes: Map<string, number> = new Map();

  // Live event feed (last 200 blocked events)
  private recentEvents: CircularBuffer<BlockEvent>;
  private peakRPS: number = 0;

  // Adaptive mode state
  private emergencyMode: boolean = false;
  private adaptiveThreshold: number;

  // Whitelist
  private whitelist: Set<string>;
  private runtimeStats = {
    activeConnections: 0,
  };

  constructor(config?: Partial<ShieldConfig>) {
    this.config = this.mergeConfig(config);
    this.log = new Logger('Shield', this.config.global.logLevel);

    this.l3 = new L3Filter(this.config.l3);
    this.l4 = new L4Filter(this.config.l4);
    this.l7 = new L7Filter(this.config.l7);

    this.processingTimes = new CircularBuffer<number>(10000);
    this.recentEvents = new CircularBuffer<BlockEvent>(200);
    this.rpsCounter = new SlidingWindowCounter(1000);
    this.startTime = Date.now();
    this.adaptiveThreshold = this.config.global.emergencyThreshold;
    this.whitelist = new Set(this.config.global.whitelistIPs);

    this.log.info('Anti-DDoS Shield initialized', {
      l3: this.config.l3.enabled,
      l4: this.config.l4.enabled,
      l7: this.config.l7.enabled,
      adaptive: this.config.global.adaptiveMode,
    });
  }

  /**
   * Process a network packet through L3 → L4 pipeline
   */
  processPacket(packet: PacketInfo): FilterResult {
    this.totalPackets++;
    this.rpsCounter.increment(packet.timestamp);

    // Whitelist bypass
    if (this.whitelist.has(packet.srcIP)) {
      return {
        action: Action.ALLOW,
        reason: 'Whitelisted IP',
        layer: 'L3',
        threatLevel: ThreatLevel.NONE,
        processingTimeUs: 0,
      };
    }

    // Emergency mode - only allow whitelist
    if (this.emergencyMode) {
      this.totalDropped++;
      return {
        action: Action.DROP,
        reason: 'Emergency mode active',
        layer: 'L3',
        threatLevel: ThreatLevel.CRITICAL,
        processingTimeUs: 0,
      };
    }

    // L3 Processing
    if (this.config.l3.enabled) {
      const l3Result = this.l3.process(packet);
      if (l3Result.action !== Action.ALLOW) {
        this.recordResult(l3Result, packet.srcIP);
        return l3Result;
      }
    }

    // L4 Processing
    if (this.config.l4.enabled) {
      const l4Result = this.l4.process(packet);
      if (l4Result.action !== Action.ALLOW) {
        this.recordResult(l4Result, packet.srcIP);
        return l4Result;
      }
    }

    // Check for adaptive mode trigger
    if (this.config.global.adaptiveMode) {
      this.checkAdaptive();
    }

    this.totalAllowed++;
    this.processingTimes.push(0);
    return {
      action: Action.ALLOW,
      reason: 'Packet passed all filters',
      layer: 'L4',
      threatLevel: ThreatLevel.NONE,
      processingTimeUs: 0,
    };
  }

  /**
   * Process an HTTP request through L3 → L4 → L7 pipeline
   */
  processHTTPRequest(request: HTTPRequest): FilterResult {
    this.totalPackets++;
    this.rpsCounter.increment(request.timestamp);

    // Whitelist bypass
    if (this.whitelist.has(request.ip)) {
      return {
        action: Action.ALLOW,
        reason: 'Whitelisted IP',
        layer: 'L7',
        threatLevel: ThreatLevel.NONE,
        processingTimeUs: 0,
      };
    }

    if (this.emergencyMode) {
      this.totalDropped++;
      return {
        action: Action.DROP,
        reason: 'Emergency mode active',
        layer: 'L7',
        threatLevel: ThreatLevel.CRITICAL,
        processingTimeUs: 0,
      };
    }

    // L3 check on IP
    if (this.config.l3.enabled) {
      const l3Packet: PacketInfo = {
        srcIP: request.ip,
        dstIP: '0.0.0.0',
        srcPort: 0,
        dstPort: 80,
        protocol: Protocol.HTTP,
        size: request.contentLength || 0,
        timestamp: request.timestamp,
      };
      const l3Result = this.l3.process(l3Packet);
      if (l3Result.action !== Action.ALLOW) {
        this.recordResult(l3Result, request.ip, request.method, request.url);
        return l3Result;
      }
    }

    // L7 Processing
    if (this.config.l7.enabled) {
      const l7Result = this.l7.process(request);
      if (l7Result.action !== Action.ALLOW) {
        this.recordResult(l7Result, request.ip, request.method, request.url);
        return l7Result;
      }
    }

    if (this.config.global.adaptiveMode) {
      this.checkAdaptive();
    }

    this.totalAllowed++;
    return {
      action: Action.ALLOW,
      reason: 'Request passed all filters',
      layer: 'L7',
      threatLevel: ThreatLevel.NONE,
      processingTimeUs: 0,
    };
  }

  // === Adaptive Defense ===

  private checkAdaptive(): void {
    const currentRPS = this.rpsCounter.getRate();

    if (currentRPS > this.adaptiveThreshold && !this.emergencyMode) {
      this.emergencyMode = true;
      this.log.error(`EMERGENCY MODE ACTIVATED - RPS: ${currentRPS.toFixed(0)}`);

      // Auto-recover after 30s
      setTimeout(() => {
        this.emergencyMode = false;
        this.log.info('Emergency mode deactivated');
      }, 30000).unref();
    }
  }

  // === IP Management ===

  addToWhitelist(ip: string): void {
    this.whitelist.add(ip);
  }

  removeFromWhitelist(ip: string): void {
    this.whitelist.delete(ip);
  }

  blacklistIP(ip: string): void {
    this.l3.addToBlacklist(ip);
  }

  setRuntimeStats(stats: Partial<typeof this.runtimeStats>): void {
    this.runtimeStats = { ...this.runtimeStats, ...stats };
  }

  getCurrentRPS(): number {
    const currentRPS = this.rpsCounter.getRate();
    if (currentRPS > this.peakRPS) {
      this.peakRPS = currentRPS;
    }
    return currentRPS;
  }

  // === Metrics ===

  private recordResult(result: FilterResult, ip?: string, method?: string, path?: string): void {
    this.processingTimes.push(result.processingTimeUs);

    switch (result.action) {
      case Action.DROP:
      case Action.BLACKHOLE:
        this.totalDropped++;
        break;
      case Action.CHALLENGE:
        this.totalChallenged++;
        break;
      case Action.RATE_LIMIT:
        this.totalRateLimited++;
        break;
    }

    if (result.threatLevel > ThreatLevel.NONE) {
      const layerKey = result.layer.toLowerCase();
      if (layerKey === 'l3' || layerKey === 'l4' || layerKey === 'l7') {
        this.threatsByLayer[layerKey]++;
      }
    }

    // Track attack vectors
    const vector = `${result.layer}:${result.reason.split(':')[0].trim()}`;
    this.attackVectors.set(vector, (this.attackVectors.get(vector) || 0) + 1);
    const reasonCode = this.getReasonCode(result);
    this.reasonCodes.set(reasonCode, (this.reasonCodes.get(reasonCode) || 0) + 1);

    // Push to live event feed
    if (result.action !== Action.ALLOW && ip) {
      this.recentEvents.push({
        ts: Date.now(),
        ip,
        method,
        path,
        layer: result.layer,
        reasonCode,
        reason: result.reason,
        action: result.action,
        threatLevel: result.threatLevel,
        source: typeof result.metadata?.source === 'string' ? result.metadata.source : undefined,
      });
    }
  }

  private getReasonCode(result: FilterResult): string {
    const explicit = result.metadata?.reasonCode;
    if (typeof explicit === 'string' && explicit.trim() !== '') {
      return explicit.trim().toUpperCase();
    }

    return `${result.layer}_${result.reason}`
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 80) || 'UNKNOWN';
  }

  getMetrics(): ShieldMetrics {
    const times = this.processingTimes.toArray();
    const avgTime = times.length > 0
      ? times.reduce((a, b) => a + b, 0) / times.length : 0;

    // Top attack vectors
    const topVectors = Array.from(this.attackVectors.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([vector, count]) => ({ vector, count }));
    const topReasonCodes = Array.from(this.reasonCodes.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([code, count]) => ({ code, count }));

    return {
      totalPackets: this.totalPackets,
      totalAllowed: this.totalAllowed,
      totalDropped: this.totalDropped,
      totalChallenged: this.totalChallenged,
      totalRateLimited: this.totalRateLimited,
      avgProcessingTimeUs: avgTime,
      peakRPS: this.peakRPS,
      currentRPS: this.getCurrentRPS(),
      activeConnections: Math.max(this.runtimeStats.activeConnections, this.l4.getActiveConnectionCount()),
      blacklistedIPs: this.l3.getBlacklistSize(),
      emergencyMode: this.emergencyMode,
      threatsByLayer: { ...this.threatsByLayer },
      topAttackVectors: topVectors,
      topReasonCodes,
      uptimeMs: Date.now() - this.startTime,
    };
  }

  getRecentEvents(limit = 50): BlockEvent[] {
    const all = this.recentEvents.toArray();
    return all.slice(-limit).reverse(); // newest first
  }

  getLayerStats() {
    return {
      l3: this.l3.getStats(),
      l4: this.l4.getStats(),
      l7: this.l7.getStats(),
    };
  }

  resetMetrics(): void {
    this.totalPackets = 0;
    this.totalAllowed = 0;
    this.totalDropped = 0;
    this.totalChallenged = 0;
    this.totalRateLimited = 0;
    this.threatsByLayer = { l3: 0, l4: 0, l7: 0 };
    this.attackVectors.clear();
    this.reasonCodes.clear();
    this.l3.resetStats();
    this.l4.resetStats();
    this.l7.resetStats();
  }

  // === Config Merge ===

  private mergeConfig(partial?: Partial<ShieldConfig>): ShieldConfig {
    if (!partial) return { ...DEFAULT_CONFIG };
    return {
      l3: { ...DEFAULT_CONFIG.l3, ...partial.l3 },
      l4: { ...DEFAULT_CONFIG.l4, ...partial.l4 },
      l7: { ...DEFAULT_CONFIG.l7, ...partial.l7 },
      global: { ...DEFAULT_CONFIG.global, ...partial.global },
    } as ShieldConfig;
  }
}
