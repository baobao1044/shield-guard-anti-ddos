import type { ServerConfig, ShieldConfig } from '../types';
import { DEFAULT_UAM_CONFIG } from '../../layers/uam';
import { DEFAULT_ANOMALY_CONFIG } from '../../layers/anomaly-engine';
import { DEFAULT_TARPIT_CONFIG } from '../../layers/tarpit';
import { DEFAULT_CORRELATION_CONFIG } from '../../layers/correlation-engine';
import { DEFAULT_JA3_CONFIG } from '../../layers/ja3-fingerprint';
import { DEFAULT_GEOIP_CONFIG } from '../../layers/geoip';
import { DEFAULT_ML_WAF_CONFIG } from '../../layers/ml-waf';
import { DEFAULT_THREAT_INTEL_CONFIG } from '../../layers/threat-intel';
import { DEFAULT_BIOMETRIC_CONFIG } from '../../layers/biometric-sdk';
import { DEFAULT_HTTP2_CONFIG } from '../../proxy/http2-server';
import {
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  DEFAULT_TRAFFIC_SHAPER_CONFIG,
} from '../../proxy/circuit-breaker';
import { DEFAULT_SLOWLORIS_CONFIG } from '../../layers/slowloris-guard';
import { DEFAULT_TLS_GUARD_CONFIG } from '../../layers/tls-guard';
import { DEFAULT_WS_CONFIG } from '../../stats/ws-stream';
import { DEFAULT_FORENSICS_CONFIG } from '../../stats/forensics';
import { DEFAULT_PLUGIN_CONFIG } from '../plugin-loader';
import { DEFAULT_ZERO_TRUST_CONFIG } from '../../security/auth/auth-middleware';

export const DEFAULT_CONFIG: ShieldConfig = {
  global: {
    logLevel: 'info',
    emergencyThreshold: 100000,
    adaptiveMode: true,
    whitelistIPs: [],
  },
  l3: {
    enabled: true,
    spoofDetection: {
      enabled: true,
      bogonFiltering: true,
    },
    maxPacketSize: 65535,
    minTTL: 1,
    rateLimits: {
      icmp: { maxRequests: 100 },
      perIP: { maxRequests: 1000, windowMs: 1000 },
    },
    ipReputation: {
      enabled: true,
      maxScore: 100,
      decayRateMs: 60000,
    },
    fragmentationLimit: 100,
  },
  l4: {
    enabled: true,
    synFloodProtection: {
      enabled: true,
      maxHalfOpen: 10000,
      maxSynRate: 200,
      synCookies: true,
    },
    udpFloodProtection: {
      enabled: true,
      maxRate: { maxRequests: 1000 },
      amplificationThreshold: 10,
    },
    connectionLimits: {
      maxTotal: 100000,
      maxPerIP: 100,
      idleTimeoutMs: 30000,
    },
    portScanDetection: {
      enabled: true,
      maxPortsPerWindow: 50,
      windowMs: 10000,
    },
    slowlorisProtection: {
      enabled: true,
      headerTimeoutMs: 10000,
      minDataRate: 10,
    },
  },
  l7: {
    enabled: true,
    rateLimiting: {
      global: { windowMs: 1000, maxRequests: 50000 },
      perIP: { maxRequests: 200, windowMs: 1000, burstSize: 500 },
      perEndpoint: { windowMs: 1000, maxRequests: 1000 },
    },
    httpFloodProtection: {
      requestSizeLimit: 10 * 1024 * 1024,
    },
    waf: {
      enabled: true,
      sqlInjection: true,
      xss: true,
      pathTraversal: true,
      commandInjection: true,
    },
    botDetection: {
      enabled: true,
      challengeThreshold: 50,
      fingerprintAnalysis: true,
    },
    headerValidation: {
      enabled: true,
      requiredHeaders: ['host'],
      maxHeaders: 100,
      maxHeaderSize: 16384,
    },
  },
};

export const DEFAULT_SERVER_CONFIG: ServerConfig = {
  target: 'http://localhost:3000',
  port: 8080,
  trustedProxies: [],
  trustForwardedHeaders: false,
  dashboardPassword: undefined,
  tls: undefined,
  httpsPort: undefined,
  shield: DEFAULT_CONFIG,
  uam: DEFAULT_UAM_CONFIG,
  http2: DEFAULT_HTTP2_CONFIG,
  slowloris: DEFAULT_SLOWLORIS_CONFIG,
  tlsGuard: DEFAULT_TLS_GUARD_CONFIG,
  anomaly: DEFAULT_ANOMALY_CONFIG,
  tarpit: DEFAULT_TARPIT_CONFIG,
  correlation: DEFAULT_CORRELATION_CONFIG,
  ja3: DEFAULT_JA3_CONFIG,
  geoip: DEFAULT_GEOIP_CONFIG,
  wsStream: DEFAULT_WS_CONFIG,
  mlWaf: DEFAULT_ML_WAF_CONFIG,
  circuitBreaker: DEFAULT_CIRCUIT_BREAKER_CONFIG,
  trafficShaper: DEFAULT_TRAFFIC_SHAPER_CONFIG,
  biometric: DEFAULT_BIOMETRIC_CONFIG,
  threatIntel: DEFAULT_THREAT_INTEL_CONFIG,
  forensics: DEFAULT_FORENSICS_CONFIG,
  plugins: DEFAULT_PLUGIN_CONFIG,
  zeroTrust: DEFAULT_ZERO_TRUST_CONFIG,
};
