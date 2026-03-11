// ============================================================================
// Layer 4 (Transport) Protection
// Anti: SYN Flood, UDP Flood, ACK Flood, RST Flood, Port Scan,
//       Slowloris, Connection Exhaustion, UDP Amplification
// ============================================================================

import {
  PacketInfo, FilterResult, Action, ThreatLevel,
  L4Config, Protocol, ConnectionState
} from '../core/types';
import {
  TokenBucket, SlidingWindowCounter, LRUCache, CircularBuffer
} from '../utils/data-structures';
import { Logger } from '../utils/logger';
import * as crypto from 'crypto';

export class L4Filter {
  private readonly config: L4Config;
  private readonly log: Logger;

  // Connection tracking
  private connections: LRUCache<ConnectionState>;
  private connectionsPerIP: LRUCache<number>;
  private totalConnections: number = 0;

  // SYN flood protection
  private synCounters: LRUCache<SlidingWindowCounter>;
  private halfOpenCount: number = 0;
  private synCookieSecret: string;

  // UDP flood protection
  private udpBuckets: LRUCache<TokenBucket>;
  private udpResponseRatio: LRUCache<{ requests: number; responses: number }>;

  // Port scan detection
  private portHistory: LRUCache<Set<number>>;

  // Slowloris detection
  private slowConnections: LRUCache<{
    startTime: number;
    bytesReceived: number;
    headersComplete: boolean;
  }>;

  // ACK/RST flood tracking
  private ackCounters: LRUCache<SlidingWindowCounter>;
  private rstCounters: LRUCache<SlidingWindowCounter>;

  // Pattern analysis
  private recentPackets: CircularBuffer<{ ip: string; port: number; ts: number }>;

  // Metrics
  private stats = {
    totalProcessed: 0,
    synFloodBlocked: 0,
    udpFloodBlocked: 0,
    ackFloodBlocked: 0,
    rstFloodBlocked: 0,
    portScanDetected: 0,
    connectionLimitHit: 0,
    slowlorisDetected: 0,
    amplificationBlocked: 0,
    synCookiesIssued: 0,
    invalidStateDropped: 0,
  };

  constructor(config: L4Config) {
    this.config = config;
    this.log = new Logger('L4-Shield');

    this.connections = new LRUCache<ConnectionState>(config.connectionLimits.maxTotal, config.connectionLimits.idleTimeoutMs);
    this.connectionsPerIP = new LRUCache<number>(100000, 300000);
    this.synCounters = new LRUCache<SlidingWindowCounter>(100000, 60000);
    this.udpBuckets = new LRUCache<TokenBucket>(50000, 60000);
    this.udpResponseRatio = new LRUCache(50000, 60000);
    this.portHistory = new LRUCache<Set<number>>(50000, config.portScanDetection.windowMs);
    this.slowConnections = new LRUCache(50000, 120000);
    this.ackCounters = new LRUCache<SlidingWindowCounter>(50000, 30000);
    this.rstCounters = new LRUCache<SlidingWindowCounter>(50000, 30000);
    this.recentPackets = new CircularBuffer(10000);
    this.synCookieSecret = crypto.randomBytes(32).toString('hex');

    // Rotate SYN cookie secret every 60s
    setInterval(() => {
      this.synCookieSecret = crypto.randomBytes(32).toString('hex');
    }, 60000).unref();
  }

  process(packet: PacketInfo): FilterResult {
    const start = process.hrtime.bigint();
    this.stats.totalProcessed++;
    this.recentPackets.push({ ip: packet.srcIP, port: packet.dstPort, ts: packet.timestamp });

    // Route by protocol
    if (packet.protocol === Protocol.TCP) {
      return this.processTCP(packet, start);
    } else if (packet.protocol === Protocol.UDP) {
      return this.processUDP(packet, start);
    }

    return this.result(Action.ALLOW, 'L4 passed (non-TCP/UDP)', ThreatLevel.NONE, start);
  }

  // === TCP Processing ===

  private processTCP(packet: PacketInfo, start: bigint): FilterResult {
    const flags = packet.flags;
    if (!flags) {
      return this.result(Action.ALLOW, 'No TCP flags', ThreatLevel.NONE, start);
    }

    // 1. Connection limit check
    const connCheck = this.checkConnectionLimits(packet);
    if (connCheck) return { ...connCheck, processingTimeUs: this.elapsed(start) };

    // 2. Port scan detection
    if (this.config.portScanDetection.enabled) {
      const scanResult = this.detectPortScan(packet);
      if (scanResult) return { ...scanResult, processingTimeUs: this.elapsed(start) };
    }

    // 3. SYN processing
    if (flags.syn && !flags.ack) {
      return this.processSYN(packet, start);
    }

    // 4. ACK flood detection
    if (flags.ack && !flags.syn && !flags.fin && !flags.rst) {
      return this.processACK(packet, start);
    }

    // 5. RST flood detection
    if (flags.rst) {
      return this.processRST(packet, start);
    }

    // 6. FIN handling
    if (flags.fin) {
      this.closeConnection(packet);
    }

    // 7. Christmas tree / null packet detection (all or no flags)
    if (flags.syn && flags.fin && flags.rst && flags.psh && flags.urg) {
      this.stats.invalidStateDropped++;
      return this.result(Action.DROP, 'Christmas tree packet', ThreatLevel.HIGH, start);
    }

    if (!flags.syn && !flags.ack && !flags.fin && !flags.rst && !flags.psh && !flags.urg) {
      this.stats.invalidStateDropped++;
      return this.result(Action.DROP, 'Null packet', ThreatLevel.MEDIUM, start);
    }

    return this.result(Action.ALLOW, 'L4-TCP passed', ThreatLevel.NONE, start);
  }

  private processSYN(packet: PacketInfo, start: bigint): FilterResult {
    if (!this.config.synFloodProtection.enabled) {
      return this.result(Action.ALLOW, 'SYN protection disabled', ThreatLevel.NONE, start);
    }

    // Track SYN rate per IP
    const counter = this.getOrCreateSynCounter(packet.srcIP);
    counter.increment(packet.timestamp);
    const synRate = counter.getRate(packet.timestamp);

    // Check global half-open limit
    if (this.halfOpenCount >= this.config.synFloodProtection.maxHalfOpen) {
      this.stats.synFloodBlocked++;

      // Use SYN cookies if enabled
      if (this.config.synFloodProtection.synCookies) {
        this.stats.synCookiesIssued++;
        const cookie = this.generateSynCookie(packet);
        return this.result(
          Action.CHALLENGE,
          `SYN cookie issued (half-open: ${this.halfOpenCount})`,
          ThreatLevel.HIGH,
          start,
          { synCookie: cookie }
        );
      }

      return this.result(Action.DROP, `Half-open limit reached: ${this.halfOpenCount}`, ThreatLevel.HIGH, start);
    }

    // Check per-IP SYN rate
    if (synRate > this.config.synFloodProtection.maxSynRate) {
      this.stats.synFloodBlocked++;
      return this.result(
        Action.DROP,
        `SYN rate exceeded: ${synRate.toFixed(0)}/s from ${packet.srcIP}`,
        ThreatLevel.HIGH,
        start
      );
    }

    // Track half-open connection
    this.halfOpenCount++;
    const connKey = `${packet.srcIP}:${packet.srcPort}-${packet.dstPort}`;
    this.connections.set(connKey, {
      ip: packet.srcIP,
      port: packet.srcPort,
      state: 'HALF_OPEN',
      createdAt: packet.timestamp,
      lastActivity: packet.timestamp,
      bytesIn: packet.size,
      bytesOut: 0,
      requests: 1,
    });

    // Auto-expire half-open connections
    setTimeout(() => {
      const conn = this.connections.get(connKey);
      if (conn && conn.state === 'HALF_OPEN') {
        this.connections.delete(connKey);
        this.halfOpenCount = Math.max(0, this.halfOpenCount - 1);
      }
    }, 5000).unref();

    return this.result(Action.ALLOW, 'SYN accepted', ThreatLevel.NONE, start);
  }

  private processACK(packet: PacketInfo, start: bigint): FilterResult {
    const counter = this.getOrCreateCounter(this.ackCounters, packet.srcIP);
    counter.increment(packet.timestamp);
    const ackRate = counter.getRate(packet.timestamp);

    // ACK flood: high rate of ACKs without established connections
    if (ackRate > 2000) {
      const connKey = `${packet.srcIP}:${packet.srcPort}-${packet.dstPort}`;
      const conn = this.connections.get(connKey);
      if (!conn || conn.state !== 'ESTABLISHED') {
        this.stats.ackFloodBlocked++;
        return this.result(Action.DROP, `ACK flood: ${ackRate.toFixed(0)}/s`, ThreatLevel.HIGH, start);
      }
    }

    // Valid ACK for half-open → establish
    const connKey = `${packet.srcIP}:${packet.srcPort}-${packet.dstPort}`;
    const conn = this.connections.get(connKey);
    if (conn && conn.state === 'HALF_OPEN') {
      conn.state = 'ESTABLISHED';
      this.halfOpenCount = Math.max(0, this.halfOpenCount - 1);

      // Increment per-IP connection count
      const ipConns = (this.connectionsPerIP.get(packet.srcIP) || 0) + 1;
      this.connectionsPerIP.set(packet.srcIP, ipConns);
      this.totalConnections++;
    }

    return this.result(Action.ALLOW, 'ACK processed', ThreatLevel.NONE, start);
  }

  private processRST(packet: PacketInfo, start: bigint): FilterResult {
    const counter = this.getOrCreateCounter(this.rstCounters, packet.srcIP);
    counter.increment(packet.timestamp);
    const rstRate = counter.getRate(packet.timestamp);

    if (rstRate > 500) {
      this.stats.rstFloodBlocked++;
      return this.result(Action.DROP, `RST flood: ${rstRate.toFixed(0)}/s`, ThreatLevel.MEDIUM, start);
    }

    this.closeConnection(packet);
    return this.result(Action.ALLOW, 'RST processed', ThreatLevel.NONE, start);
  }

  // === UDP Processing ===

  private processUDP(packet: PacketInfo, start: bigint): FilterResult {
    if (!this.config.udpFloodProtection.enabled) {
      return this.result(Action.ALLOW, 'UDP protection disabled', ThreatLevel.NONE, start);
    }

    // 1. Rate limiting
    let bucket = this.udpBuckets.get(packet.srcIP);
    if (!bucket) {
      bucket = new TokenBucket(
        this.config.udpFloodProtection.maxRate.maxRequests,
        this.config.udpFloodProtection.maxRate.maxRequests
      );
      this.udpBuckets.set(packet.srcIP, bucket);
    }

    if (!bucket.consume()) {
      this.stats.udpFloodBlocked++;
      return this.result(Action.DROP, 'UDP rate exceeded', ThreatLevel.HIGH, start);
    }

    // 2. Amplification detection (DNS, NTP, SSDP, Memcached)
    if (this.isAmplificationVector(packet)) {
      const ratio = this.getAmplificationRatio(packet);
      if (ratio > this.config.udpFloodProtection.amplificationThreshold) {
        this.stats.amplificationBlocked++;
        return this.result(
          Action.DROP,
          `Amplification detected: ${ratio.toFixed(1)}x on port ${packet.dstPort}`,
          ThreatLevel.CRITICAL,
          start
        );
      }
    }

    return this.result(Action.ALLOW, 'L4-UDP passed', ThreatLevel.NONE, start);
  }

  // === Slowloris Detection ===

  processSlowloris(connId: string, ip: string, bytesReceived: number, headersComplete: boolean): FilterResult | null {
    if (!this.config.slowlorisProtection.enabled) return null;

    const start = process.hrtime.bigint();
    let state = this.slowConnections.get(connId);

    if (!state) {
      state = { startTime: Date.now(), bytesReceived: 0, headersComplete: false };
      this.slowConnections.set(connId, state);
    }

    state.bytesReceived += bytesReceived;
    state.headersComplete = headersComplete;

    const elapsed = Date.now() - state.startTime;

    // Header timeout
    if (!state.headersComplete && elapsed > this.config.slowlorisProtection.headerTimeoutMs) {
      this.stats.slowlorisDetected++;
      this.slowConnections.delete(connId);
      return this.result(
        Action.DROP,
        `Slowloris: headers incomplete after ${elapsed}ms`,
        ThreatLevel.HIGH,
        start
      );
    }

    // Minimum data rate check
    if (elapsed > 1000) {
      const dataRate = (state.bytesReceived / elapsed) * 1000; // bytes/sec
      if (dataRate < this.config.slowlorisProtection.minDataRate) {
        this.stats.slowlorisDetected++;
        this.slowConnections.delete(connId);
        return this.result(
          Action.DROP,
          `Slow connection: ${dataRate.toFixed(0)} B/s`,
          ThreatLevel.MEDIUM,
          start
        );
      }
    }

    return null;
  }

  // === Port Scan Detection ===

  private detectPortScan(packet: PacketInfo): FilterResult | null {
    let ports = this.portHistory.get(packet.srcIP);
    if (!ports) {
      ports = new Set<number>();
      this.portHistory.set(packet.srcIP, ports);
    }

    ports.add(packet.dstPort);

    if (ports.size > this.config.portScanDetection.maxPortsPerWindow) {
      this.stats.portScanDetected++;
      return {
        action: Action.DROP,
        reason: `Port scan: ${ports.size} ports from ${packet.srcIP}`,
        layer: 'L4',
        threatLevel: ThreatLevel.HIGH,
        processingTimeUs: 0,
      };
    }

    return null;
  }

  // === Connection Management ===

  private checkConnectionLimits(packet: PacketInfo): FilterResult | null {
    // Global connection limit
    if (this.totalConnections >= this.config.connectionLimits.maxTotal) {
      this.stats.connectionLimitHit++;
      return {
        action: Action.DROP,
        reason: `Global connection limit: ${this.totalConnections}`,
        layer: 'L4',
        threatLevel: ThreatLevel.HIGH,
        processingTimeUs: 0,
      };
    }

    // Per-IP connection limit
    const ipConns = this.connectionsPerIP.get(packet.srcIP) || 0;
    if (ipConns >= this.config.connectionLimits.maxPerIP) {
      this.stats.connectionLimitHit++;
      return {
        action: Action.RATE_LIMIT,
        reason: `Per-IP limit: ${ipConns} connections`,
        layer: 'L4',
        threatLevel: ThreatLevel.MEDIUM,
        processingTimeUs: 0,
      };
    }

    return null;
  }

  private closeConnection(packet: PacketInfo): void {
    const connKey = `${packet.srcIP}:${packet.srcPort}-${packet.dstPort}`;
    const conn = this.connections.get(connKey);
    if (conn) {
      this.connections.delete(connKey);
      if (conn.state === 'HALF_OPEN') {
        this.halfOpenCount = Math.max(0, this.halfOpenCount - 1);
      }
      if (conn.state === 'ESTABLISHED') {
        const ipConns = (this.connectionsPerIP.get(packet.srcIP) || 1) - 1;
        this.connectionsPerIP.set(packet.srcIP, Math.max(0, ipConns));
        this.totalConnections = Math.max(0, this.totalConnections - 1);
      }
    }
  }

  // === Utils ===

  private generateSynCookie(packet: PacketInfo): string {
    const data = `${packet.srcIP}:${packet.srcPort}:${packet.dstPort}:${this.synCookieSecret}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  verifySynCookie(packet: PacketInfo, cookie: string): boolean {
    const expected = this.generateSynCookie(packet);
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(cookie));
  }

  private isAmplificationVector(packet: PacketInfo): boolean {
    const ampPorts = [53, 123, 1900, 11211, 389, 161]; // DNS, NTP, SSDP, Memcached, LDAP, SNMP
    return ampPorts.includes(packet.dstPort);
  }

  private getAmplificationRatio(packet: PacketInfo): number {
    const key = `${packet.srcIP}:${packet.dstPort}`;
    let ratioState = this.udpResponseRatio.get(key);
    if (!ratioState) {
      ratioState = { requests: 0, responses: 0 };
      this.udpResponseRatio.set(key, ratioState);
    }
    ratioState.requests++;
    // Estimate amplification from packet size
    return packet.size / 64; // typical request is ~64 bytes
  }

  private getOrCreateSynCounter(ip: string): SlidingWindowCounter {
    let counter = this.synCounters.get(ip);
    if (!counter) {
      counter = new SlidingWindowCounter(1000);
      this.synCounters.set(ip, counter);
    }
    return counter;
  }

  private getOrCreateCounter(cache: LRUCache<SlidingWindowCounter>, ip: string): SlidingWindowCounter {
    let counter = cache.get(ip);
    if (!counter) {
      counter = new SlidingWindowCounter(1000);
      cache.set(ip, counter);
    }
    return counter;
  }

  private result(
    action: Action,
    reason: string,
    threatLevel: ThreatLevel,
    startTime: bigint,
    metadata?: Record<string, unknown>
  ): FilterResult {
    return {
      action,
      reason,
      layer: 'L4',
      threatLevel,
      processingTimeUs: this.elapsed(startTime),
      metadata,
    };
  }

  private elapsed(start: bigint): number {
    return Number(process.hrtime.bigint() - start) / 1000;
  }

  getStats() {
    return {
      ...this.stats,
      halfOpenConnections: this.halfOpenCount,
      totalConnections: this.totalConnections,
    };
  }

  resetStats(): void {
    for (const key of Object.keys(this.stats) as (keyof typeof this.stats)[]) {
      this.stats[key] = 0;
    }
  }
}
