// ============================================================================
// Layer 3 (Network) Protection
// Anti: IP Spoofing, ICMP Flood, Smurf Attack, IP Fragmentation,
//       Bogon/Martian Traffic, Land Attack, Teardrop
// ============================================================================

import {
  PacketInfo, FilterResult, Action, ThreatLevel,
  L3Config, Protocol, IPProfile
} from '../core/types';
import { TokenBucket, SlidingWindowCounter, BloomFilter, LRUCache } from '../utils/data-structures';
import { Logger } from '../utils/logger';

// Private/Bogon IP ranges (RFC 1918, RFC 5737, etc.)
const BOGON_PREFIXES = [
  '0.', '10.', '100.64.', '127.', '169.254.', '172.16.', '172.17.',
  '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
  '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
  '172.30.', '172.31.', '192.0.0.', '192.0.2.', '192.168.', '198.18.',
  '198.19.', '198.51.100.', '203.0.113.', '224.', '240.', '255.',
];

export class L3Filter {
  private readonly config: L3Config;
  private readonly log: Logger;

  // IP reputation tracking
  private ipProfiles: LRUCache<IPProfile>;
  private blacklist: BloomFilter;
  private blacklistExact: Set<string> = new Set();

  // Rate limiters
  private icmpBuckets: LRUCache<TokenBucket>;
  private ipRateCounters: LRUCache<SlidingWindowCounter>;

  // Fragment tracking
  private fragmentCounters: LRUCache<number>;

  // Metrics
  private stats = {
    totalProcessed: 0,
    spoofDetected: 0,
    bogonBlocked: 0,
    icmpLimited: 0,
    oversizeDropped: 0,
    ttlBlocked: 0,
    blacklisted: 0,
    landAttack: 0,
    reputationBlocked: 0,
  };

  constructor(config: L3Config) {
    this.config = config;
    this.log = new Logger('L3-Shield');

    this.ipProfiles = new LRUCache<IPProfile>(100000, 3600000);
    this.blacklist = new BloomFilter(1000000, 0.001);
    this.icmpBuckets = new LRUCache<TokenBucket>(50000, 60000);
    this.ipRateCounters = new LRUCache<SlidingWindowCounter>(100000, 120000);
    this.fragmentCounters = new LRUCache<number>(50000, 30000);
  }

  process(packet: PacketInfo): FilterResult {
    const start = process.hrtime.bigint();
    this.stats.totalProcessed++;
    const requestDerivedTraffic = packet.protocol === Protocol.HTTP || packet.protocol === Protocol.HTTPS;

    // 1. Blacklist check (fastest - O(1) bloom filter)
    if (this.blacklistExact.has(packet.srcIP) || this.blacklist.has(packet.srcIP)) {
      if (this.blacklistExact.has(packet.srcIP)) {
        this.stats.blacklisted++;
        return this.result(Action.DROP, 'IP blacklisted', ThreatLevel.HIGH, start);
      }
    }

    // 2. Land Attack detection (src == dst)
    if (!requestDerivedTraffic && packet.srcIP === packet.dstIP) {
      this.stats.landAttack++;
      this.escalateIP(packet.srcIP, 'LAND_ATTACK', 30);
      return this.result(Action.DROP, 'Land attack detected', ThreatLevel.CRITICAL, start);
    }

    // 3. Bogon / spoofing detection
    if (this.config.spoofDetection.enabled) {
      if (this.config.spoofDetection.bogonFiltering && this.isBogon(packet.srcIP)) {
        this.stats.bogonBlocked++;
        return this.result(Action.DROP, `Bogon IP: ${packet.srcIP}`, ThreatLevel.MEDIUM, start);
      }
    }

    // 4. Packet size validation
    if (!requestDerivedTraffic && packet.size > this.config.maxPacketSize) {
      this.stats.oversizeDropped++;
      this.escalateIP(packet.srcIP, 'OVERSIZE_PACKET', 5);
      return this.result(Action.DROP, `Oversize packet: ${packet.size}B`, ThreatLevel.MEDIUM, start);
    }

    // 5. TTL validation
    if (!requestDerivedTraffic && packet.ttl !== undefined && packet.ttl < this.config.minTTL) {
      this.stats.ttlBlocked++;
      this.escalateIP(packet.srcIP, 'LOW_TTL', 3);
      return this.result(Action.DROP, `Low TTL: ${packet.ttl}`, ThreatLevel.LOW, start);
    }

    // 6. ICMP rate limiting
    if (!requestDerivedTraffic && packet.protocol === Protocol.ICMP) {
      const bucket = this.getOrCreateICMPBucket(packet.srcIP);
      if (!bucket.consume()) {
        this.stats.icmpLimited++;
        this.escalateIP(packet.srcIP, 'ICMP_FLOOD', 10);
        return this.result(Action.DROP, 'ICMP rate exceeded', ThreatLevel.MEDIUM, start);
      }
    }

    // 7. Per-IP rate limiting
    const rateCounter = this.getOrCreateRateCounter(packet.srcIP);
    rateCounter.increment(packet.timestamp);
    const currentRate = rateCounter.getRate(packet.timestamp);

    if (currentRate > this.config.rateLimits.perIP.maxRequests) {
      this.escalateIP(packet.srcIP, 'HIGH_RATE', 15);
      return this.result(Action.RATE_LIMIT, `Rate: ${currentRate.toFixed(0)}/s`, ThreatLevel.HIGH, start);
    }

    // 8. IP reputation check
    if (this.config.ipReputation.enabled) {
      const profile = this.getIPProfile(packet.srcIP);
      profile.totalRequests++;
      const elapsed = packet.timestamp - profile.lastSeen;
      profile.lastSeen = packet.timestamp;

      if (profile.reputationScore >= this.config.ipReputation.maxScore) {
        this.stats.reputationBlocked++;
        this.addToBlacklist(packet.srcIP);
        return this.result(Action.BLACKHOLE, `Bad reputation: ${profile.reputationScore}`, ThreatLevel.CRITICAL, start);
      }

      // Decay reputation score over time
      if (elapsed > this.config.ipReputation.decayRateMs) {
        profile.reputationScore = Math.max(0, profile.reputationScore - 1);
      }
    }

    // 9. Fragment flood detection
    if (!requestDerivedTraffic && packet.size < 68 && packet.protocol === Protocol.TCP) {
      const fragKey = packet.srcIP;
      const current = (this.fragmentCounters.get(fragKey) || 0) + 1;
      this.fragmentCounters.set(fragKey, current);

      if (current > this.config.fragmentationLimit) {
        this.escalateIP(packet.srcIP, 'FRAG_FLOOD', 20);
        return this.result(Action.DROP, 'Fragment flood detected', ThreatLevel.HIGH, start);
      }
    }

    return this.result(Action.ALLOW, 'L3 passed', ThreatLevel.NONE, start);
  }

  // === Helpers ===

  private isBogon(ip: string): boolean {
    for (const prefix of BOGON_PREFIXES) {
      if (ip.startsWith(prefix)) return true;
    }
    return false;
  }

  private getOrCreateICMPBucket(ip: string): TokenBucket {
    let bucket = this.icmpBuckets.get(ip);
    if (!bucket) {
      bucket = new TokenBucket(
        this.config.rateLimits.icmp.maxRequests,
        this.config.rateLimits.icmp.maxRequests
      );
      this.icmpBuckets.set(ip, bucket);
    }
    return bucket;
  }

  private getOrCreateRateCounter(ip: string): SlidingWindowCounter {
    let counter = this.ipRateCounters.get(ip);
    if (!counter) {
      counter = new SlidingWindowCounter(this.config.rateLimits.perIP.windowMs);
      this.ipRateCounters.set(ip, counter);
    }
    return counter;
  }

  getIPProfile(ip: string): IPProfile {
    let profile = this.ipProfiles.get(ip);
    if (!profile) {
      profile = {
        ip,
        reputationScore: 0,
        totalRequests: 0,
        blockedRequests: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        threatLevel: ThreatLevel.NONE,
        flags: new Set(),
        connections: 0,
        avgRequestRate: 0,
      };
      this.ipProfiles.set(ip, profile);
    }
    return profile;
  }

  private escalateIP(ip: string, flag: string, scoreDelta: number): void {
    const profile = this.getIPProfile(ip);
    profile.reputationScore = Math.min(
      this.config.ipReputation.maxScore + 10,
      profile.reputationScore + scoreDelta
    );
    profile.blockedRequests++;
    profile.flags.add(flag);

    // Update threat level
    if (profile.reputationScore >= 80) profile.threatLevel = ThreatLevel.CRITICAL;
    else if (profile.reputationScore >= 50) profile.threatLevel = ThreatLevel.HIGH;
    else if (profile.reputationScore >= 25) profile.threatLevel = ThreatLevel.MEDIUM;
    else if (profile.reputationScore >= 10) profile.threatLevel = ThreatLevel.LOW;
  }

  addToBlacklist(ip: string): void {
    this.blacklist.add(ip);
    this.blacklistExact.add(ip);
    this.log.warn(`IP blacklisted: ${ip}`);
  }

  removeFromBlacklist(ip: string): void {
    this.blacklistExact.delete(ip);
    // Bloom filter entries can't be removed - they'll eventually be replaced
  }

  getBlacklistSize(): number {
    return this.blacklistExact.size;
  }

  private result(
    action: Action,
    reason: string,
    threatLevel: ThreatLevel,
    startTime: bigint
  ): FilterResult {
    const elapsed = Number(process.hrtime.bigint() - startTime) / 1000; // microseconds
    return {
      action,
      reason,
      layer: 'L3',
      threatLevel,
      processingTimeUs: elapsed,
    };
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
