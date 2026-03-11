// ============================================================================
// Default Configuration + Runtime Validation
// ============================================================================

import { ServerConfig, ShieldConfig, TLSConfig } from './types';

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

export class ConfigValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown, path: string): JsonRecord {
  if (!isRecord(value)) {
    throw new ConfigValidationError(`${path} must be an object`);
  }
  return value;
}

function readString(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new ConfigValidationError(`${path} must be a non-empty string`);
  }
  return value;
}

function readOptionalString(value: unknown, path: string): string | undefined {
  if (value === undefined) return undefined;
  return readString(value, path);
}

function readBoolean(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') {
    throw new ConfigValidationError(`${path} must be a boolean`);
  }
  return value;
}

function readNumber(value: unknown, path: string, opts?: {
  integer?: boolean;
  min?: number;
  max?: number;
}): number {
  if (typeof value !== 'number' || Number.isNaN(value) || !Number.isFinite(value)) {
    throw new ConfigValidationError(`${path} must be a valid number`);
  }
  if (opts?.integer && !Number.isInteger(value)) {
    throw new ConfigValidationError(`${path} must be an integer`);
  }
  if (opts?.min !== undefined && value < opts.min) {
    throw new ConfigValidationError(`${path} must be >= ${opts.min}`);
  }
  if (opts?.max !== undefined && value > opts.max) {
    throw new ConfigValidationError(`${path} must be <= ${opts.max}`);
  }
  return value;
}

function readOptionalNumber(value: unknown, path: string, opts?: {
  integer?: boolean;
  min?: number;
  max?: number;
}): number | undefined {
  if (value === undefined) return undefined;
  return readNumber(value, path, opts);
}

function readStringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new ConfigValidationError(`${path} must be an array of strings`);
  }
  return [...value];
}

function validateUrl(value: string, path: string): string {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new ConfigValidationError(`${path} must use http or https`);
    }
    return url.toString().replace(/\/$/, '');
  } catch (error) {
    if (error instanceof ConfigValidationError) throw error;
    throw new ConfigValidationError(`${path} must be a valid URL`);
  }
}

function validateTls(raw: unknown): TLSConfig | undefined {
  if (raw === undefined) return undefined;
  const tls = asRecord(raw, 'tls');
  const cert = readOptionalString(tls.cert, 'tls.cert');
  const key = readOptionalString(tls.key, 'tls.key');
  const selfSigned = tls.selfSigned === undefined ? undefined : readBoolean(tls.selfSigned, 'tls.selfSigned');

  if ((cert && !key) || (!cert && key)) {
    throw new ConfigValidationError('tls.cert and tls.key must be provided together');
  }

  if (!cert && !selfSigned) {
    throw new ConfigValidationError('tls requires cert/key or selfSigned=true');
  }

  return { cert, key, selfSigned };
}

function validateShield(raw: unknown): Partial<ShieldConfig> | undefined {
  if (raw === undefined) return undefined;
  const shield = asRecord(raw, 'shield');
  const result: Partial<ShieldConfig> = {};

  if (shield.global !== undefined) {
    const global = asRecord(shield.global, 'shield.global');
    result.global = {
      logLevel: global.logLevel === undefined ? DEFAULT_CONFIG.global.logLevel : readString(global.logLevel, 'shield.global.logLevel'),
      emergencyThreshold: global.emergencyThreshold === undefined
        ? DEFAULT_CONFIG.global.emergencyThreshold
        : readNumber(global.emergencyThreshold, 'shield.global.emergencyThreshold', { integer: true, min: 1 }),
      adaptiveMode: global.adaptiveMode === undefined
        ? DEFAULT_CONFIG.global.adaptiveMode
        : readBoolean(global.adaptiveMode, 'shield.global.adaptiveMode'),
      whitelistIPs: global.whitelistIPs === undefined
        ? [...DEFAULT_CONFIG.global.whitelistIPs]
        : readStringArray(global.whitelistIPs, 'shield.global.whitelistIPs'),
    };
  }

  if (shield.l3 !== undefined) {
    const l3 = asRecord(shield.l3, 'shield.l3');
    result.l3 = {
      ...DEFAULT_CONFIG.l3,
      enabled: l3.enabled === undefined ? DEFAULT_CONFIG.l3.enabled : readBoolean(l3.enabled, 'shield.l3.enabled'),
      maxPacketSize: l3.maxPacketSize === undefined ? DEFAULT_CONFIG.l3.maxPacketSize : readNumber(l3.maxPacketSize, 'shield.l3.maxPacketSize', { integer: true, min: 1 }),
      minTTL: l3.minTTL === undefined ? DEFAULT_CONFIG.l3.minTTL : readNumber(l3.minTTL, 'shield.l3.minTTL', { integer: true, min: 0 }),
      fragmentationLimit: l3.fragmentationLimit === undefined ? DEFAULT_CONFIG.l3.fragmentationLimit : readNumber(l3.fragmentationLimit, 'shield.l3.fragmentationLimit', { integer: true, min: 1 }),
      spoofDetection: l3.spoofDetection === undefined ? DEFAULT_CONFIG.l3.spoofDetection : {
        enabled: readBoolean(asRecord(l3.spoofDetection, 'shield.l3.spoofDetection').enabled, 'shield.l3.spoofDetection.enabled'),
        bogonFiltering: readBoolean(asRecord(l3.spoofDetection, 'shield.l3.spoofDetection').bogonFiltering, 'shield.l3.spoofDetection.bogonFiltering'),
      },
      rateLimits: l3.rateLimits === undefined ? DEFAULT_CONFIG.l3.rateLimits : {
        icmp: {
          maxRequests: readNumber(asRecord(asRecord(l3.rateLimits, 'shield.l3.rateLimits').icmp, 'shield.l3.rateLimits.icmp').maxRequests, 'shield.l3.rateLimits.icmp.maxRequests', { integer: true, min: 1 }),
        },
        perIP: {
          maxRequests: readNumber(asRecord(asRecord(l3.rateLimits, 'shield.l3.rateLimits').perIP, 'shield.l3.rateLimits.perIP').maxRequests, 'shield.l3.rateLimits.perIP.maxRequests', { integer: true, min: 1 }),
          windowMs: readNumber(asRecord(asRecord(l3.rateLimits, 'shield.l3.rateLimits').perIP, 'shield.l3.rateLimits.perIP').windowMs, 'shield.l3.rateLimits.perIP.windowMs', { integer: true, min: 1 }),
        },
      },
      ipReputation: l3.ipReputation === undefined ? DEFAULT_CONFIG.l3.ipReputation : {
        enabled: readBoolean(asRecord(l3.ipReputation, 'shield.l3.ipReputation').enabled, 'shield.l3.ipReputation.enabled'),
        maxScore: readNumber(asRecord(l3.ipReputation, 'shield.l3.ipReputation').maxScore, 'shield.l3.ipReputation.maxScore', { integer: true, min: 1 }),
        decayRateMs: readNumber(asRecord(l3.ipReputation, 'shield.l3.ipReputation').decayRateMs, 'shield.l3.ipReputation.decayRateMs', { integer: true, min: 1 }),
      },
    };
  }

  if (shield.l4 !== undefined) {
    const l4 = asRecord(shield.l4, 'shield.l4');
    result.l4 = {
      ...DEFAULT_CONFIG.l4,
      enabled: l4.enabled === undefined ? DEFAULT_CONFIG.l4.enabled : readBoolean(l4.enabled, 'shield.l4.enabled'),
      synFloodProtection: l4.synFloodProtection === undefined ? DEFAULT_CONFIG.l4.synFloodProtection : {
        enabled: readBoolean(asRecord(l4.synFloodProtection, 'shield.l4.synFloodProtection').enabled, 'shield.l4.synFloodProtection.enabled'),
        maxHalfOpen: readNumber(asRecord(l4.synFloodProtection, 'shield.l4.synFloodProtection').maxHalfOpen, 'shield.l4.synFloodProtection.maxHalfOpen', { integer: true, min: 1 }),
        maxSynRate: readNumber(asRecord(l4.synFloodProtection, 'shield.l4.synFloodProtection').maxSynRate, 'shield.l4.synFloodProtection.maxSynRate', { integer: true, min: 1 }),
        synCookies: readBoolean(asRecord(l4.synFloodProtection, 'shield.l4.synFloodProtection').synCookies, 'shield.l4.synFloodProtection.synCookies'),
      },
      udpFloodProtection: l4.udpFloodProtection === undefined ? DEFAULT_CONFIG.l4.udpFloodProtection : {
        enabled: readBoolean(asRecord(l4.udpFloodProtection, 'shield.l4.udpFloodProtection').enabled, 'shield.l4.udpFloodProtection.enabled'),
        maxRate: {
          maxRequests: readNumber(asRecord(asRecord(l4.udpFloodProtection, 'shield.l4.udpFloodProtection').maxRate, 'shield.l4.udpFloodProtection.maxRate').maxRequests, 'shield.l4.udpFloodProtection.maxRate.maxRequests', { integer: true, min: 1 }),
        },
        amplificationThreshold: readNumber(asRecord(l4.udpFloodProtection, 'shield.l4.udpFloodProtection').amplificationThreshold, 'shield.l4.udpFloodProtection.amplificationThreshold', { min: 0 }),
      },
      connectionLimits: l4.connectionLimits === undefined ? DEFAULT_CONFIG.l4.connectionLimits : {
        maxTotal: readNumber(asRecord(l4.connectionLimits, 'shield.l4.connectionLimits').maxTotal, 'shield.l4.connectionLimits.maxTotal', { integer: true, min: 1 }),
        maxPerIP: readNumber(asRecord(l4.connectionLimits, 'shield.l4.connectionLimits').maxPerIP, 'shield.l4.connectionLimits.maxPerIP', { integer: true, min: 1 }),
        idleTimeoutMs: readNumber(asRecord(l4.connectionLimits, 'shield.l4.connectionLimits').idleTimeoutMs, 'shield.l4.connectionLimits.idleTimeoutMs', { integer: true, min: 1 }),
      },
      portScanDetection: l4.portScanDetection === undefined ? DEFAULT_CONFIG.l4.portScanDetection : {
        enabled: readBoolean(asRecord(l4.portScanDetection, 'shield.l4.portScanDetection').enabled, 'shield.l4.portScanDetection.enabled'),
        maxPortsPerWindow: readNumber(asRecord(l4.portScanDetection, 'shield.l4.portScanDetection').maxPortsPerWindow, 'shield.l4.portScanDetection.maxPortsPerWindow', { integer: true, min: 1 }),
        windowMs: readNumber(asRecord(l4.portScanDetection, 'shield.l4.portScanDetection').windowMs, 'shield.l4.portScanDetection.windowMs', { integer: true, min: 1 }),
      },
      slowlorisProtection: l4.slowlorisProtection === undefined ? DEFAULT_CONFIG.l4.slowlorisProtection : {
        enabled: readBoolean(asRecord(l4.slowlorisProtection, 'shield.l4.slowlorisProtection').enabled, 'shield.l4.slowlorisProtection.enabled'),
        headerTimeoutMs: readNumber(asRecord(l4.slowlorisProtection, 'shield.l4.slowlorisProtection').headerTimeoutMs, 'shield.l4.slowlorisProtection.headerTimeoutMs', { integer: true, min: 1 }),
        minDataRate: readNumber(asRecord(l4.slowlorisProtection, 'shield.l4.slowlorisProtection').minDataRate, 'shield.l4.slowlorisProtection.minDataRate', { min: 0 }),
      },
    };
  }

  if (shield.l7 !== undefined) {
    const l7 = asRecord(shield.l7, 'shield.l7');
    result.l7 = {
      ...DEFAULT_CONFIG.l7,
      enabled: l7.enabled === undefined ? DEFAULT_CONFIG.l7.enabled : readBoolean(l7.enabled, 'shield.l7.enabled'),
      rateLimiting: l7.rateLimiting === undefined ? DEFAULT_CONFIG.l7.rateLimiting : {
        global: {
          windowMs: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').global, 'shield.l7.rateLimiting.global').windowMs, 'shield.l7.rateLimiting.global.windowMs', { integer: true, min: 1 }),
          maxRequests: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').global, 'shield.l7.rateLimiting.global').maxRequests, 'shield.l7.rateLimiting.global.maxRequests', { integer: true, min: 1 }),
        },
        perIP: {
          maxRequests: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').perIP, 'shield.l7.rateLimiting.perIP').maxRequests, 'shield.l7.rateLimiting.perIP.maxRequests', { integer: true, min: 1 }),
          windowMs: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').perIP, 'shield.l7.rateLimiting.perIP').windowMs, 'shield.l7.rateLimiting.perIP.windowMs', { integer: true, min: 1 }),
          burstSize: readOptionalNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').perIP, 'shield.l7.rateLimiting.perIP').burstSize, 'shield.l7.rateLimiting.perIP.burstSize', { integer: true, min: 1 }),
        },
        perEndpoint: {
          windowMs: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').perEndpoint, 'shield.l7.rateLimiting.perEndpoint').windowMs, 'shield.l7.rateLimiting.perEndpoint.windowMs', { integer: true, min: 1 }),
          maxRequests: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').perEndpoint, 'shield.l7.rateLimiting.perEndpoint').maxRequests, 'shield.l7.rateLimiting.perEndpoint.maxRequests', { integer: true, min: 1 }),
        },
      },
      httpFloodProtection: l7.httpFloodProtection === undefined ? DEFAULT_CONFIG.l7.httpFloodProtection : {
        requestSizeLimit: readNumber(asRecord(l7.httpFloodProtection, 'shield.l7.httpFloodProtection').requestSizeLimit, 'shield.l7.httpFloodProtection.requestSizeLimit', { integer: true, min: 1 }),
      },
      waf: l7.waf === undefined ? DEFAULT_CONFIG.l7.waf : {
        enabled: readBoolean(asRecord(l7.waf, 'shield.l7.waf').enabled, 'shield.l7.waf.enabled'),
        sqlInjection: readBoolean(asRecord(l7.waf, 'shield.l7.waf').sqlInjection, 'shield.l7.waf.sqlInjection'),
        xss: readBoolean(asRecord(l7.waf, 'shield.l7.waf').xss, 'shield.l7.waf.xss'),
        pathTraversal: readBoolean(asRecord(l7.waf, 'shield.l7.waf').pathTraversal, 'shield.l7.waf.pathTraversal'),
        commandInjection: readBoolean(asRecord(l7.waf, 'shield.l7.waf').commandInjection, 'shield.l7.waf.commandInjection'),
      },
      botDetection: l7.botDetection === undefined ? DEFAULT_CONFIG.l7.botDetection : {
        enabled: readBoolean(asRecord(l7.botDetection, 'shield.l7.botDetection').enabled, 'shield.l7.botDetection.enabled'),
        challengeThreshold: readNumber(asRecord(l7.botDetection, 'shield.l7.botDetection').challengeThreshold, 'shield.l7.botDetection.challengeThreshold', { integer: true, min: 1 }),
        fingerprintAnalysis: readBoolean(asRecord(l7.botDetection, 'shield.l7.botDetection').fingerprintAnalysis, 'shield.l7.botDetection.fingerprintAnalysis'),
      },
      headerValidation: l7.headerValidation === undefined ? DEFAULT_CONFIG.l7.headerValidation : {
        enabled: readBoolean(asRecord(l7.headerValidation, 'shield.l7.headerValidation').enabled, 'shield.l7.headerValidation.enabled'),
        requiredHeaders: readStringArray(asRecord(l7.headerValidation, 'shield.l7.headerValidation').requiredHeaders, 'shield.l7.headerValidation.requiredHeaders'),
        maxHeaders: readNumber(asRecord(l7.headerValidation, 'shield.l7.headerValidation').maxHeaders, 'shield.l7.headerValidation.maxHeaders', { integer: true, min: 1 }),
        maxHeaderSize: readNumber(asRecord(l7.headerValidation, 'shield.l7.headerValidation').maxHeaderSize, 'shield.l7.headerValidation.maxHeaderSize', { integer: true, min: 1 }),
      },
    };
  }

  return result;
}

function validateOptionalObject<T extends object>(
  raw: unknown,
  path: string,
  validator: (record: JsonRecord, path: string) => T,
): T | undefined {
  if (raw === undefined) return undefined;
  return validator(asRecord(raw, path), path);
}

function validatePositivePort(value: unknown, path: string): number {
  return readNumber(value, path, { integer: true, min: 1, max: 65535 });
}

export function normalizeServerConfig(raw: Partial<ServerConfig>): ServerConfig {
  const target = validateUrl(readString(raw.target, 'target'), 'target');
  const port = validatePositivePort(raw.port, 'port');
  const httpsPort = raw.httpsPort === undefined ? undefined : validatePositivePort(raw.httpsPort, 'httpsPort');
  const tls = validateTls(raw.tls);
  const dashboardPassword = raw.dashboardPassword === undefined
    ? undefined
    : readOptionalString(raw.dashboardPassword, 'dashboardPassword');

  if (httpsPort !== undefined && !tls) {
    throw new ConfigValidationError('httpsPort requires tls.cert/key or tls.selfSigned=true');
  }

  const http2 = validateOptionalObject(raw.http2, 'http2', (record, path) => ({
    enabled: record.enabled === undefined ? undefined : readBoolean(record.enabled, `${path}.enabled`),
    port: record.port === undefined ? undefined : validatePositivePort(record.port, `${path}.port`),
    maxResetPerSec: record.maxResetPerSec === undefined ? undefined : readNumber(record.maxResetPerSec, `${path}.maxResetPerSec`, { integer: true, min: 1 }),
    maxStreamsPerSec: record.maxStreamsPerSec === undefined ? undefined : readNumber(record.maxStreamsPerSec, `${path}.maxStreamsPerSec`, { integer: true, min: 1 }),
    maxConcurrentStreams: record.maxConcurrentStreams === undefined ? undefined : readNumber(record.maxConcurrentStreams, `${path}.maxConcurrentStreams`, { integer: true, min: 1 }),
  }));

  const uam = validateOptionalObject(raw.uam, 'uam', (record, path) => ({
    enabled: record.enabled === undefined ? undefined : readBoolean(record.enabled, `${path}.enabled`),
    difficulty: record.difficulty === undefined ? undefined : readNumber(record.difficulty, `${path}.difficulty`, { integer: true, min: 1 }),
    cookieTTLSeconds: record.cookieTTLSeconds === undefined ? undefined : readNumber(record.cookieTTLSeconds, `${path}.cookieTTLSeconds`, { integer: true, min: 1 }),
    autoActivateThreshold: record.autoActivateThreshold === undefined ? undefined : readNumber(record.autoActivateThreshold, `${path}.autoActivateThreshold`, { integer: true, min: 1 }),
    exemptPaths: record.exemptPaths === undefined ? undefined : readStringArray(record.exemptPaths, `${path}.exemptPaths`),
  }));

  const slowloris = validateOptionalObject(raw.slowloris, 'slowloris', (record, path) => ({
    enabled: record.enabled === undefined ? undefined : readBoolean(record.enabled, `${path}.enabled`),
    headerTimeoutMs: record.headerTimeoutMs === undefined ? undefined : readNumber(record.headerTimeoutMs, `${path}.headerTimeoutMs`, { integer: true, min: 1 }),
    bodyTimeoutMs: record.bodyTimeoutMs === undefined ? undefined : readNumber(record.bodyTimeoutMs, `${path}.bodyTimeoutMs`, { integer: true, min: 1 }),
    minBodyRateBytesPerSec: record.minBodyRateBytesPerSec === undefined ? undefined : readNumber(record.minBodyRateBytesPerSec, `${path}.minBodyRateBytesPerSec`, { min: 0 }),
    maxConnectionsPerIP: record.maxConnectionsPerIP === undefined ? undefined : readNumber(record.maxConnectionsPerIP, `${path}.maxConnectionsPerIP`, { integer: true, min: 1 }),
    maxPendingHeaders: record.maxPendingHeaders === undefined ? undefined : readNumber(record.maxPendingHeaders, `${path}.maxPendingHeaders`, { integer: true, min: 1 }),
    idleTimeoutMs: record.idleTimeoutMs === undefined ? undefined : readNumber(record.idleTimeoutMs, `${path}.idleTimeoutMs`, { integer: true, min: 1 }),
  }));

  const tlsGuard = validateOptionalObject(raw.tlsGuard, 'tlsGuard', (record, path) => ({
    enabled: record.enabled === undefined ? undefined : readBoolean(record.enabled, `${path}.enabled`),
    maxHandshakesPerSecond: record.maxHandshakesPerSecond === undefined ? undefined : readNumber(record.maxHandshakesPerSecond, `${path}.maxHandshakesPerSecond`, { integer: true, min: 1 }),
    handshakeTimeoutMs: record.handshakeTimeoutMs === undefined ? undefined : readNumber(record.handshakeTimeoutMs, `${path}.handshakeTimeoutMs`, { integer: true, min: 1 }),
    maxFailedHandshakes: record.maxFailedHandshakes === undefined ? undefined : readNumber(record.maxFailedHandshakes, `${path}.maxFailedHandshakes`, { integer: true, min: 1 }),
    minTLSVersion: record.minTLSVersion === undefined ? undefined : readString(record.minTLSVersion, `${path}.minTLSVersion`),
  }));

  return {
    target,
    port,
    httpsPort,
    tls,
    dashboardPassword,
    shield: validateShield(raw.shield),
    uam,
    http2,
    slowloris,
    tlsGuard,
  };
}
