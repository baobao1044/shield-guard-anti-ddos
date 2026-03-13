// ============================================================================
// Core Types & Interfaces
// ============================================================================

export enum Action {
  ALLOW = 'ALLOW',
  DROP = 'DROP',
  CHALLENGE = 'CHALLENGE',
  RATE_LIMIT = 'RATE_LIMIT',
  BLACKHOLE = 'BLACKHOLE',
}

export enum ThreatLevel {
  NONE = 0,
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4,
}

export enum Protocol {
  TCP = 'TCP',
  UDP = 'UDP',
  ICMP = 'ICMP',
  HTTP = 'HTTP',
  HTTPS = 'HTTPS',
  OTHER = 'OTHER',
}

export interface TCPFlags {
  syn?: boolean;
  ack?: boolean;
  fin?: boolean;
  rst?: boolean;
  psh?: boolean;
  urg?: boolean;
}

export interface PacketInfo {
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  protocol: Protocol;
  size: number;
  timestamp: number;
  ttl?: number;
  flags?: TCPFlags;
}

export interface HTTPRequest {
  ip: string;
  method: string;
  url: string;
  rawUrl?: string;
  headers: Record<string, string>;
  body?: string;
  contentLength?: number;
  bodySize?: number;
  hasBody?: boolean;
  userAgent?: string;
  timestamp: number;
}

export interface FilterResult {
  action: Action;
  reason: string;
  layer: string;
  threatLevel: ThreatLevel;
  processingTimeUs: number;
  metadata?: Record<string, unknown>;
}

export interface IPProfile {
  ip: string;
  reputationScore: number;
  totalRequests: number;
  blockedRequests: number;
  firstSeen: number;
  lastSeen: number;
  threatLevel: ThreatLevel;
  flags: Set<string>;
  connections: number;
  avgRequestRate: number;
}

export interface ConnectionState {
  ip: string;
  port: number;
  state: 'HALF_OPEN' | 'ESTABLISHED' | 'CLOSING';
  createdAt: number;
  lastActivity: number;
  bytesIn: number;
  bytesOut: number;
  requests: number;
}

export interface ShieldMetrics {
  totalPackets: number;
  totalAllowed: number;
  totalDropped: number;
  totalChallenged: number;
  totalRateLimited: number;
  avgProcessingTimeUs: number;
  peakRPS: number;
  currentRPS: number;
  activeConnections: number;
  blacklistedIPs: number;
  emergencyMode: boolean;
  threatsByLayer: { l3: number; l4: number; l7: number };
  topAttackVectors: Array<{ vector: string; count: number }>;
  topReasonCodes: Array<{ code: string; count: number }>;
  uptimeMs: number;
}

// === Config Interfaces ===

export interface RateLimit {
  maxRequests: number;
  windowMs: number;
  burstSize?: number;
}

export interface L3Config {
  enabled: boolean;
  spoofDetection: {
    enabled: boolean;
    bogonFiltering: boolean;
  };
  maxPacketSize: number;
  minTTL: number;
  rateLimits: {
    icmp: { maxRequests: number };
    perIP: { maxRequests: number; windowMs: number };
  };
  ipReputation: {
    enabled: boolean;
    maxScore: number;
    decayRateMs: number;
  };
  fragmentationLimit: number;
}

export interface L4Config {
  enabled: boolean;
  synFloodProtection: {
    enabled: boolean;
    maxHalfOpen: number;
    maxSynRate: number;
    synCookies: boolean;
  };
  udpFloodProtection: {
    enabled: boolean;
    maxRate: { maxRequests: number };
    amplificationThreshold: number;
  };
  connectionLimits: {
    maxTotal: number;
    maxPerIP: number;
    idleTimeoutMs: number;
  };
  portScanDetection: {
    enabled: boolean;
    maxPortsPerWindow: number;
    windowMs: number;
  };
  slowlorisProtection: {
    enabled: boolean;
    headerTimeoutMs: number;
    minDataRate: number;
  };
}

export interface L7Config {
  enabled: boolean;
  rateLimiting: {
    global: { windowMs: number; maxRequests: number };
    perIP: { maxRequests: number; windowMs: number; burstSize?: number };
    perEndpoint: { windowMs: number; maxRequests: number };
  };
  httpFloodProtection: {
    requestSizeLimit: number;
  };
  waf: {
    enabled: boolean;
    sqlInjection: boolean;
    xss: boolean;
    pathTraversal: boolean;
    commandInjection: boolean;
  };
  botDetection: {
    enabled: boolean;
    challengeThreshold: number;
    fingerprintAnalysis: boolean;
  };
  headerValidation: {
    enabled: boolean;
    requiredHeaders: string[];
    maxHeaders: number;
    maxHeaderSize: number;
  };
}

export interface ShieldConfig {
  global: {
    logLevel: string;
    emergencyThreshold: number;
    adaptiveMode: boolean;
    whitelistIPs: string[];
  };
  l3: L3Config;
  l4: L4Config;
  l7: L7Config;
}

// === Server Config ===

export interface TLSConfig {
  cert?: string;
  key?: string;
  selfSigned?: boolean;
}

export interface ServerConfig {
  target: string;
  port: number;
  httpsPort?: number;
  trustedProxies?: string[];
  trustForwardedHeaders?: boolean;
  tls?: TLSConfig;
  dashboardPassword?: string;
  shield?: Partial<ShieldConfig>;
  uam?: Partial<import('../layers/uam').UAMConfig>;
  http2?: Partial<import('../proxy/http2-server').Http2Config>;
  slowloris?: Partial<import('../layers/slowloris-guard').SlowlorisConfig>;
  tlsGuard?: Partial<import('../layers/tls-guard').TLSGuardConfig>;
  anomaly?: Partial<import('../layers/anomaly-engine').AnomalyConfig>;
  tarpit?: Partial<import('../layers/tarpit').TarpitConfig>;
  correlation?: Partial<import('../layers/correlation-engine').CorrelationConfig>;
  ja3?: Partial<import('../layers/ja3-fingerprint').JA3Config>;
  geoip?: Partial<import('../layers/geoip').GeoIPConfig>;
  wsStream?: Partial<import('../stats/ws-stream').WSStreamConfig>;
  mlWaf?: Partial<import('../layers/ml-waf').MLWafConfig>;
  circuitBreaker?: Partial<import('../proxy/circuit-breaker').CircuitBreakerConfig>;
  trafficShaper?: Partial<import('../proxy/circuit-breaker').TrafficShaperConfig>;
  biometric?: Partial<import('../layers/biometric-sdk').BiometricConfig>;
  threatIntel?: Partial<import('../layers/threat-intel').ThreatIntelConfig>;
  forensics?: Partial<import('../stats/forensics').ForensicsConfig>;
  plugins?: Partial<import('../core/plugin-loader').PluginConfig>;
  zeroTrust?: Partial<import('../proxy/mtls-gateway').ZeroTrustConfig>;
}
