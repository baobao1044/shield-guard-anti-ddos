// ============================================================================
// Default Configuration
// ============================================================================

import { ShieldConfig } from './types';

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
      requestSizeLimit: 10 * 1024 * 1024, // 10MB
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
