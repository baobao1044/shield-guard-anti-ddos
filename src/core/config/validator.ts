import type { ServerConfig, ShieldConfig, TLSConfig } from '../types';
import type { DeepPartial } from './types';
import type {
  ApiKeyEntry,
  JWTPublicKeyConfig,
  ZeroTrustConfig,
} from '../../security/auth/auth-middleware';
import { DEFAULT_CONFIG, DEFAULT_SERVER_CONFIG } from './defaults';
import { ConfigValidationError } from './errors';

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

function readNumber(
  value: unknown,
  path: string,
  opts?: { integer?: boolean; min?: number; max?: number },
): number {
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

function readOptionalNumber(
  value: unknown,
  path: string,
  opts?: { integer?: boolean; min?: number; max?: number },
): number | undefined {
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

function validatePositivePort(value: unknown, path: string): number {
  return readNumber(value, path, { integer: true, min: 1, max: 65535 });
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
    throw new ConfigValidationError('tls requires cert/key or tls.selfSigned=true');
  }

  return { cert, key, selfSigned };
}

function validateShield(raw: unknown): ShieldConfig {
  const shield = asRecord(raw, 'shield');
  const l3 = asRecord(shield.l3, 'shield.l3');
  const l4 = asRecord(shield.l4, 'shield.l4');
  const l7 = asRecord(shield.l7, 'shield.l7');
  const global = asRecord(shield.global, 'shield.global');

  const perIp = asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').perIP, 'shield.l7.rateLimiting.perIP');
  if (
    perIp.burstSize !== undefined &&
    readNumber(perIp.burstSize, 'shield.l7.rateLimiting.perIP.burstSize', { integer: true, min: 1 }) <
      readNumber(perIp.maxRequests, 'shield.l7.rateLimiting.perIP.maxRequests', { integer: true, min: 1 })
  ) {
    throw new ConfigValidationError('shield.l7.rateLimiting.perIP.burstSize must be >= maxRequests');
  }

  return {
    global: {
      logLevel: global.logLevel === undefined ? DEFAULT_CONFIG.global.logLevel : readString(global.logLevel, 'shield.global.logLevel'),
      emergencyThreshold: readNumber(global.emergencyThreshold, 'shield.global.emergencyThreshold', { integer: true, min: 1 }),
      adaptiveMode: readBoolean(global.adaptiveMode, 'shield.global.adaptiveMode'),
      whitelistIPs: readStringArray(global.whitelistIPs, 'shield.global.whitelistIPs'),
    },
    l3: {
      enabled: readBoolean(l3.enabled, 'shield.l3.enabled'),
      spoofDetection: {
        enabled: readBoolean(asRecord(l3.spoofDetection, 'shield.l3.spoofDetection').enabled, 'shield.l3.spoofDetection.enabled'),
        bogonFiltering: readBoolean(asRecord(l3.spoofDetection, 'shield.l3.spoofDetection').bogonFiltering, 'shield.l3.spoofDetection.bogonFiltering'),
      },
      maxPacketSize: readNumber(l3.maxPacketSize, 'shield.l3.maxPacketSize', { integer: true, min: 1 }),
      minTTL: readNumber(l3.minTTL, 'shield.l3.minTTL', { integer: true, min: 0 }),
      rateLimits: {
        icmp: {
          maxRequests: readNumber(asRecord(asRecord(l3.rateLimits, 'shield.l3.rateLimits').icmp, 'shield.l3.rateLimits.icmp').maxRequests, 'shield.l3.rateLimits.icmp.maxRequests', { integer: true, min: 1 }),
        },
        perIP: {
          maxRequests: readNumber(asRecord(asRecord(l3.rateLimits, 'shield.l3.rateLimits').perIP, 'shield.l3.rateLimits.perIP').maxRequests, 'shield.l3.rateLimits.perIP.maxRequests', { integer: true, min: 1 }),
          windowMs: readNumber(asRecord(asRecord(l3.rateLimits, 'shield.l3.rateLimits').perIP, 'shield.l3.rateLimits.perIP').windowMs, 'shield.l3.rateLimits.perIP.windowMs', { integer: true, min: 1 }),
        },
      },
      ipReputation: {
        enabled: readBoolean(asRecord(l3.ipReputation, 'shield.l3.ipReputation').enabled, 'shield.l3.ipReputation.enabled'),
        maxScore: readNumber(asRecord(l3.ipReputation, 'shield.l3.ipReputation').maxScore, 'shield.l3.ipReputation.maxScore', { integer: true, min: 1 }),
        decayRateMs: readNumber(asRecord(l3.ipReputation, 'shield.l3.ipReputation').decayRateMs, 'shield.l3.ipReputation.decayRateMs', { integer: true, min: 1 }),
      },
      fragmentationLimit: readNumber(l3.fragmentationLimit, 'shield.l3.fragmentationLimit', { integer: true, min: 1 }),
    },
    l4: {
      enabled: readBoolean(l4.enabled, 'shield.l4.enabled'),
      synFloodProtection: {
        enabled: readBoolean(asRecord(l4.synFloodProtection, 'shield.l4.synFloodProtection').enabled, 'shield.l4.synFloodProtection.enabled'),
        maxHalfOpen: readNumber(asRecord(l4.synFloodProtection, 'shield.l4.synFloodProtection').maxHalfOpen, 'shield.l4.synFloodProtection.maxHalfOpen', { integer: true, min: 1 }),
        maxSynRate: readNumber(asRecord(l4.synFloodProtection, 'shield.l4.synFloodProtection').maxSynRate, 'shield.l4.synFloodProtection.maxSynRate', { integer: true, min: 1 }),
        synCookies: readBoolean(asRecord(l4.synFloodProtection, 'shield.l4.synFloodProtection').synCookies, 'shield.l4.synFloodProtection.synCookies'),
      },
      udpFloodProtection: {
        enabled: readBoolean(asRecord(l4.udpFloodProtection, 'shield.l4.udpFloodProtection').enabled, 'shield.l4.udpFloodProtection.enabled'),
        maxRate: {
          maxRequests: readNumber(asRecord(asRecord(l4.udpFloodProtection, 'shield.l4.udpFloodProtection').maxRate, 'shield.l4.udpFloodProtection.maxRate').maxRequests, 'shield.l4.udpFloodProtection.maxRate.maxRequests', { integer: true, min: 1 }),
        },
        amplificationThreshold: readNumber(asRecord(l4.udpFloodProtection, 'shield.l4.udpFloodProtection').amplificationThreshold, 'shield.l4.udpFloodProtection.amplificationThreshold', { min: 0 }),
      },
      connectionLimits: {
        maxTotal: readNumber(asRecord(l4.connectionLimits, 'shield.l4.connectionLimits').maxTotal, 'shield.l4.connectionLimits.maxTotal', { integer: true, min: 1 }),
        maxPerIP: readNumber(asRecord(l4.connectionLimits, 'shield.l4.connectionLimits').maxPerIP, 'shield.l4.connectionLimits.maxPerIP', { integer: true, min: 1 }),
        idleTimeoutMs: readNumber(asRecord(l4.connectionLimits, 'shield.l4.connectionLimits').idleTimeoutMs, 'shield.l4.connectionLimits.idleTimeoutMs', { integer: true, min: 1 }),
      },
      portScanDetection: {
        enabled: readBoolean(asRecord(l4.portScanDetection, 'shield.l4.portScanDetection').enabled, 'shield.l4.portScanDetection.enabled'),
        maxPortsPerWindow: readNumber(asRecord(l4.portScanDetection, 'shield.l4.portScanDetection').maxPortsPerWindow, 'shield.l4.portScanDetection.maxPortsPerWindow', { integer: true, min: 1 }),
        windowMs: readNumber(asRecord(l4.portScanDetection, 'shield.l4.portScanDetection').windowMs, 'shield.l4.portScanDetection.windowMs', { integer: true, min: 1 }),
      },
      slowlorisProtection: {
        enabled: readBoolean(asRecord(l4.slowlorisProtection, 'shield.l4.slowlorisProtection').enabled, 'shield.l4.slowlorisProtection.enabled'),
        headerTimeoutMs: readNumber(asRecord(l4.slowlorisProtection, 'shield.l4.slowlorisProtection').headerTimeoutMs, 'shield.l4.slowlorisProtection.headerTimeoutMs', { integer: true, min: 1 }),
        minDataRate: readNumber(asRecord(l4.slowlorisProtection, 'shield.l4.slowlorisProtection').minDataRate, 'shield.l4.slowlorisProtection.minDataRate', { min: 0 }),
      },
    },
    l7: {
      enabled: readBoolean(l7.enabled, 'shield.l7.enabled'),
      rateLimiting: {
        global: {
          windowMs: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').global, 'shield.l7.rateLimiting.global').windowMs, 'shield.l7.rateLimiting.global.windowMs', { integer: true, min: 1 }),
          maxRequests: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').global, 'shield.l7.rateLimiting.global').maxRequests, 'shield.l7.rateLimiting.global.maxRequests', { integer: true, min: 1 }),
        },
        perIP: {
          maxRequests: readNumber(perIp.maxRequests, 'shield.l7.rateLimiting.perIP.maxRequests', { integer: true, min: 1 }),
          windowMs: readNumber(perIp.windowMs, 'shield.l7.rateLimiting.perIP.windowMs', { integer: true, min: 1 }),
          burstSize: readOptionalNumber(perIp.burstSize, 'shield.l7.rateLimiting.perIP.burstSize', { integer: true, min: 1 }),
        },
        perEndpoint: {
          windowMs: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').perEndpoint, 'shield.l7.rateLimiting.perEndpoint').windowMs, 'shield.l7.rateLimiting.perEndpoint.windowMs', { integer: true, min: 1 }),
          maxRequests: readNumber(asRecord(asRecord(l7.rateLimiting, 'shield.l7.rateLimiting').perEndpoint, 'shield.l7.rateLimiting.perEndpoint').maxRequests, 'shield.l7.rateLimiting.perEndpoint.maxRequests', { integer: true, min: 1 }),
        },
      },
      httpFloodProtection: {
        requestSizeLimit: readNumber(asRecord(l7.httpFloodProtection, 'shield.l7.httpFloodProtection').requestSizeLimit, 'shield.l7.httpFloodProtection.requestSizeLimit', { integer: true, min: 1 }),
      },
      waf: {
        enabled: readBoolean(asRecord(l7.waf, 'shield.l7.waf').enabled, 'shield.l7.waf.enabled'),
        sqlInjection: readBoolean(asRecord(l7.waf, 'shield.l7.waf').sqlInjection, 'shield.l7.waf.sqlInjection'),
        xss: readBoolean(asRecord(l7.waf, 'shield.l7.waf').xss, 'shield.l7.waf.xss'),
        pathTraversal: readBoolean(asRecord(l7.waf, 'shield.l7.waf').pathTraversal, 'shield.l7.waf.pathTraversal'),
        commandInjection: readBoolean(asRecord(l7.waf, 'shield.l7.waf').commandInjection, 'shield.l7.waf.commandInjection'),
      },
      botDetection: {
        enabled: readBoolean(asRecord(l7.botDetection, 'shield.l7.botDetection').enabled, 'shield.l7.botDetection.enabled'),
        challengeThreshold: readNumber(asRecord(l7.botDetection, 'shield.l7.botDetection').challengeThreshold, 'shield.l7.botDetection.challengeThreshold', { integer: true, min: 1 }),
        fingerprintAnalysis: readBoolean(asRecord(l7.botDetection, 'shield.l7.botDetection').fingerprintAnalysis, 'shield.l7.botDetection.fingerprintAnalysis'),
      },
      headerValidation: {
        enabled: readBoolean(asRecord(l7.headerValidation, 'shield.l7.headerValidation').enabled, 'shield.l7.headerValidation.enabled'),
        requiredHeaders: readStringArray(asRecord(l7.headerValidation, 'shield.l7.headerValidation').requiredHeaders, 'shield.l7.headerValidation.requiredHeaders'),
        maxHeaders: readNumber(asRecord(l7.headerValidation, 'shield.l7.headerValidation').maxHeaders, 'shield.l7.headerValidation.maxHeaders', { integer: true, min: 1 }),
        maxHeaderSize: readNumber(asRecord(l7.headerValidation, 'shield.l7.headerValidation').maxHeaderSize, 'shield.l7.headerValidation.maxHeaderSize', { integer: true, min: 1 }),
      },
    },
  };
}

function validateFeeds(raw: unknown, path: string): Array<{ name: string; url: string; format: string; enabled: boolean }> {
  if (!Array.isArray(raw)) {
    throw new ConfigValidationError(`${path} must be an array`);
  }
  return raw.map((item, index) => {
    const feed = asRecord(item, `${path}[${index}]`);
    return {
      name: readString(feed.name, `${path}[${index}].name`),
      url: validateUrl(readString(feed.url, `${path}[${index}].url`), `${path}[${index}].url`),
      format: readString(feed.format, `${path}[${index}].format`),
      enabled: readBoolean(feed.enabled, `${path}[${index}].enabled`),
    };
  });
}

function validatePublicKeys(raw: unknown, path: string): JWTPublicKeyConfig[] {
  if (!Array.isArray(raw)) {
    throw new ConfigValidationError(`${path} must be an array`);
  }
  return raw.map((item, index) => {
    const key = asRecord(item, `${path}[${index}]`);
    return {
      kid: readString(key.kid, `${path}[${index}].kid`),
      pem: readString(key.pem, `${path}[${index}].pem`),
      alg: readOptionalString(key.alg, `${path}[${index}].alg`),
    };
  });
}

function validateApiKeys(raw: unknown, path: string): ApiKeyEntry[] {
  if (!Array.isArray(raw)) {
    throw new ConfigValidationError(`${path} must be an array`);
  }
  return raw.map((item, index) => {
    const key = asRecord(item, `${path}[${index}]`);
    return {
      key: readString(key.key, `${path}[${index}].key`),
      name: readString(key.name, `${path}[${index}].name`),
      rateLimit: readNumber(key.rateLimit, `${path}[${index}].rateLimit`, { integer: true, min: 1 }),
      permissions: readStringArray(key.permissions, `${path}[${index}].permissions`),
      active: readBoolean(key.active, `${path}[${index}].active`),
    };
  });
}

function validateZeroTrust(raw: unknown): ZeroTrustConfig {
  const zeroTrust = asRecord(raw, 'zeroTrust');
  const mtls = asRecord(zeroTrust.mtls, 'zeroTrust.mtls');
  const jwt = asRecord(zeroTrust.jwt, 'zeroTrust.jwt');
  const apiKeys = asRecord(zeroTrust.apiKeys, 'zeroTrust.apiKeys');

  const algorithms = readStringArray(jwt.algorithms, 'zeroTrust.jwt.algorithms');
  if (algorithms.length === 0) {
    throw new ConfigValidationError('zeroTrust.jwt.algorithms must not be empty');
  }

  return {
    enabled: readBoolean(zeroTrust.enabled, 'zeroTrust.enabled'),
    mtls: {
      enabled: readBoolean(mtls.enabled, 'zeroTrust.mtls.enabled'),
      requireClientCert: readBoolean(mtls.requireClientCert, 'zeroTrust.mtls.requireClientCert'),
      allowedCNs: readStringArray(mtls.allowedCNs, 'zeroTrust.mtls.allowedCNs'),
      allowedFingerprints: readStringArray(mtls.allowedFingerprints, 'zeroTrust.mtls.allowedFingerprints'),
    },
    jwt: {
      enabled: readBoolean(jwt.enabled, 'zeroTrust.jwt.enabled'),
      headerName: readString(jwt.headerName, 'zeroTrust.jwt.headerName').toLowerCase(),
      algorithms,
      issuer: readOptionalString(jwt.issuer, 'zeroTrust.jwt.issuer'),
      audience: readOptionalString(jwt.audience, 'zeroTrust.jwt.audience'),
      clockToleranceSec: readNumber(jwt.clockToleranceSec, 'zeroTrust.jwt.clockToleranceSec', { integer: true, min: 0 }),
      sharedSecret: readOptionalString(jwt.sharedSecret, 'zeroTrust.jwt.sharedSecret'),
      jwksUri: jwt.jwksUri === undefined ? undefined : validateUrl(readString(jwt.jwksUri, 'zeroTrust.jwt.jwksUri'), 'zeroTrust.jwt.jwksUri'),
      publicKeys: jwt.publicKeys === undefined ? [] : validatePublicKeys(jwt.publicKeys, 'zeroTrust.jwt.publicKeys'),
    },
    apiKeys: {
      enabled: readBoolean(apiKeys.enabled, 'zeroTrust.apiKeys.enabled'),
      headerName: readString(apiKeys.headerName, 'zeroTrust.apiKeys.headerName').toLowerCase(),
      keys: validateApiKeys(apiKeys.keys, 'zeroTrust.apiKeys.keys'),
    },
  };
}

function validateTrafficClass(raw: unknown, path: string): { rateLimit: number; burstSize: number } {
  const trafficClass = asRecord(raw, path);
  return {
    rateLimit: readNumber(trafficClass.rateLimit, `${path}.rateLimit`, { integer: true, min: 1 }),
    burstSize: readNumber(trafficClass.burstSize, `${path}.burstSize`, { integer: true, min: 1 }),
  };
}

export function normalizeServerConfig(raw: DeepPartial<ServerConfig>): ServerConfig {
  const target = validateUrl(readString(raw.target, 'target'), 'target');
  const port = validatePositivePort(raw.port, 'port');
  const httpsPort = raw.httpsPort === undefined ? undefined : validatePositivePort(raw.httpsPort, 'httpsPort');
  const tls = validateTls(raw.tls);
  const dashboardPassword = raw.dashboardPassword === undefined ? undefined : readOptionalString(raw.dashboardPassword, 'dashboardPassword');

  if (httpsPort !== undefined && !tls) {
    throw new ConfigValidationError('httpsPort requires tls.cert/key or tls.selfSigned=true');
  }

  const trustedProxies = raw.trustedProxies === undefined ? [] : readStringArray(raw.trustedProxies, 'trustedProxies');
  const trustForwardedHeaders = raw.trustForwardedHeaders === undefined
    ? DEFAULT_SERVER_CONFIG.trustForwardedHeaders
    : readBoolean(raw.trustForwardedHeaders, 'trustForwardedHeaders');

  const http2 = asRecord(raw.http2, 'http2');
  const slowloris = asRecord(raw.slowloris, 'slowloris');
  const tlsGuard = asRecord(raw.tlsGuard, 'tlsGuard');
  const anomaly = asRecord(raw.anomaly, 'anomaly');
  const tarpit = asRecord(raw.tarpit, 'tarpit');
  const correlation = asRecord(raw.correlation, 'correlation');
  const ja3 = asRecord(raw.ja3, 'ja3');
  const geoip = asRecord(raw.geoip, 'geoip');
  const wsStream = asRecord(raw.wsStream, 'wsStream');
  const mlWaf = asRecord(raw.mlWaf, 'mlWaf');
  const circuitBreaker = asRecord(raw.circuitBreaker, 'circuitBreaker');
  const trafficShaper = asRecord(raw.trafficShaper, 'trafficShaper');
  const trafficClasses = asRecord(trafficShaper.classes, 'trafficShaper.classes');
  const biometric = asRecord(raw.biometric, 'biometric');
  const threatIntel = asRecord(raw.threatIntel, 'threatIntel');
  const forensics = asRecord(raw.forensics, 'forensics');
  const plugins = asRecord(raw.plugins, 'plugins');

  return {
    target,
    port,
    httpsPort,
    tls,
    dashboardPassword,
    trustedProxies,
    trustForwardedHeaders,
    shield: validateShield(raw.shield),
    uam: {
      enabled: readBoolean(asRecord(raw.uam, 'uam').enabled, 'uam.enabled'),
      difficulty: readNumber(asRecord(raw.uam, 'uam').difficulty, 'uam.difficulty', { integer: true, min: 1 }),
      cookieTTLSeconds: readNumber(asRecord(raw.uam, 'uam').cookieTTLSeconds, 'uam.cookieTTLSeconds', { integer: true, min: 1 }),
      autoActivateThreshold: readNumber(asRecord(raw.uam, 'uam').autoActivateThreshold, 'uam.autoActivateThreshold', { integer: true, min: 1 }),
      exemptPaths: readStringArray(asRecord(raw.uam, 'uam').exemptPaths, 'uam.exemptPaths'),
    },
    http2: {
      enabled: readBoolean(http2.enabled, 'http2.enabled'),
      port: validatePositivePort(http2.port, 'http2.port'),
      maxResetPerSec: readNumber(http2.maxResetPerSec, 'http2.maxResetPerSec', { integer: true, min: 1 }),
      maxStreamsPerSec: readNumber(http2.maxStreamsPerSec, 'http2.maxStreamsPerSec', { integer: true, min: 1 }),
      maxConcurrentStreams: readNumber(http2.maxConcurrentStreams, 'http2.maxConcurrentStreams', { integer: true, min: 1 }),
    },
    slowloris: {
      enabled: readBoolean(slowloris.enabled, 'slowloris.enabled'),
      headerTimeoutMs: readNumber(slowloris.headerTimeoutMs, 'slowloris.headerTimeoutMs', { integer: true, min: 1 }),
      bodyTimeoutMs: readNumber(slowloris.bodyTimeoutMs, 'slowloris.bodyTimeoutMs', { integer: true, min: 1 }),
      minBodyRateBytesPerSec: readNumber(slowloris.minBodyRateBytesPerSec, 'slowloris.minBodyRateBytesPerSec', { min: 0 }),
      maxConnectionsPerIP: readNumber(slowloris.maxConnectionsPerIP, 'slowloris.maxConnectionsPerIP', { integer: true, min: 1 }),
      maxPendingHeaders: readNumber(slowloris.maxPendingHeaders, 'slowloris.maxPendingHeaders', { integer: true, min: 1 }),
      idleTimeoutMs: readNumber(slowloris.idleTimeoutMs, 'slowloris.idleTimeoutMs', { integer: true, min: 1 }),
    },
    tlsGuard: {
      enabled: readBoolean(tlsGuard.enabled, 'tlsGuard.enabled'),
      maxHandshakesPerSecond: readNumber(tlsGuard.maxHandshakesPerSecond, 'tlsGuard.maxHandshakesPerSecond', { integer: true, min: 1 }),
      handshakeTimeoutMs: readNumber(tlsGuard.handshakeTimeoutMs, 'tlsGuard.handshakeTimeoutMs', { integer: true, min: 1 }),
      maxFailedHandshakes: readNumber(tlsGuard.maxFailedHandshakes, 'tlsGuard.maxFailedHandshakes', { integer: true, min: 1 }),
      minTLSVersion: readString(tlsGuard.minTLSVersion, 'tlsGuard.minTLSVersion'),
    },
    anomaly: {
      enabled: readBoolean(anomaly.enabled, 'anomaly.enabled'),
      learningPeriodMs: readNumber(anomaly.learningPeriodMs, 'anomaly.learningPeriodMs', { integer: true, min: 0 }),
      snapshotIntervalMs: readNumber(anomaly.snapshotIntervalMs, 'anomaly.snapshotIntervalMs', { integer: true, min: 100 }),
      emaAlpha: readNumber(anomaly.emaAlpha, 'anomaly.emaAlpha', { min: 0.001, max: 1 }),
      zScoreThreshold: readNumber(anomaly.zScoreThreshold, 'anomaly.zScoreThreshold', { min: 0.5 }),
      criticalZScoreThreshold: readNumber(anomaly.criticalZScoreThreshold, 'anomaly.criticalZScoreThreshold', { min: 1 }),
      minSamples: readNumber(anomaly.minSamples, 'anomaly.minSamples', { integer: true, min: 1 }),
    },
    tarpit: {
      enabled: readBoolean(tarpit.enabled, 'tarpit.enabled'),
      honeypotPaths: readStringArray(tarpit.honeypotPaths, 'tarpit.honeypotPaths'),
      tarpitEnabled: readBoolean(tarpit.tarpitEnabled, 'tarpit.tarpitEnabled'),
      tarpitBytesPerSecond: readNumber(tarpit.tarpitBytesPerSecond, 'tarpit.tarpitBytesPerSecond', { min: 0.1 }),
      tarpitMaxDurationMs: readNumber(tarpit.tarpitMaxDurationMs, 'tarpit.tarpitMaxDurationMs', { integer: true, min: 1000 }),
      tarpitResponseSize: readNumber(tarpit.tarpitResponseSize, 'tarpit.tarpitResponseSize', { integer: true, min: 1 }),
      autoBlacklistOnHoneypot: readBoolean(tarpit.autoBlacklistOnHoneypot, 'tarpit.autoBlacklistOnHoneypot'),
      honeypotResponseCode: readNumber(tarpit.honeypotResponseCode, 'tarpit.honeypotResponseCode', { integer: true, min: 100, max: 599 }),
    },
    correlation: {
      enabled: readBoolean(correlation.enabled, 'correlation.enabled'),
      signatureWindowMs: readNumber(correlation.signatureWindowMs, 'correlation.signatureWindowMs', { integer: true, min: 1000 }),
      minIPsForCorrelation: readNumber(correlation.minIPsForCorrelation, 'correlation.minIPsForCorrelation', { integer: true, min: 2 }),
      maxTrackedSignatures: readNumber(correlation.maxTrackedSignatures, 'correlation.maxTrackedSignatures', { integer: true, min: 100 }),
      botScoreBoost: readNumber(correlation.botScoreBoost, 'correlation.botScoreBoost', { integer: true, min: 1 }),
      autoBlockThreshold: readNumber(correlation.autoBlockThreshold, 'correlation.autoBlockThreshold', { integer: true, min: 2 }),
    },
    ja3: {
      enabled: readBoolean(ja3.enabled, 'ja3.enabled'),
      mismatchScoreBoost: readNumber(ja3.mismatchScoreBoost, 'ja3.mismatchScoreBoost', { integer: true, min: 1 }),
      blockUnknownFingerprints: readBoolean(ja3.blockUnknownFingerprints, 'ja3.blockUnknownFingerprints'),
      logFingerprints: readBoolean(ja3.logFingerprints, 'ja3.logFingerprints'),
    },
    geoip: {
      enabled: readBoolean(geoip.enabled, 'geoip.enabled'),
      blockedCountries: readStringArray(geoip.blockedCountries, 'geoip.blockedCountries'),
      allowedCountries: readStringArray(geoip.allowedCountries, 'geoip.allowedCountries'),
      challengeCountries: readStringArray(geoip.challengeCountries, 'geoip.challengeCountries'),
      action: readString(geoip.action, 'geoip.action') as 'block' | 'challenge' | 'log',
    },
    wsStream: {
      enabled: readBoolean(wsStream.enabled, 'wsStream.enabled'),
      metricsIntervalMs: readNumber(wsStream.metricsIntervalMs, 'wsStream.metricsIntervalMs', { integer: true, min: 100 }),
      maxClients: readNumber(wsStream.maxClients, 'wsStream.maxClients', { integer: true, min: 1 }),
      path: readString(wsStream.path, 'wsStream.path'),
    },
    mlWaf: {
      enabled: readBoolean(mlWaf.enabled, 'mlWaf.enabled'),
      threshold: readNumber(mlWaf.threshold, 'mlWaf.threshold', { min: 0, max: 1 }),
      learningMode: readBoolean(mlWaf.learningMode, 'mlWaf.learningMode'),
      ensembleWeight: readNumber(mlWaf.ensembleWeight, 'mlWaf.ensembleWeight', { min: 0, max: 1 }),
    },
    circuitBreaker: {
      enabled: readBoolean(circuitBreaker.enabled, 'circuitBreaker.enabled'),
      failureThreshold: readNumber(circuitBreaker.failureThreshold, 'circuitBreaker.failureThreshold', { integer: true, min: 1 }),
      failureWindowMs: readNumber(circuitBreaker.failureWindowMs, 'circuitBreaker.failureWindowMs', { integer: true, min: 1 }),
      resetTimeoutMs: readNumber(circuitBreaker.resetTimeoutMs, 'circuitBreaker.resetTimeoutMs', { integer: true, min: 1 }),
      halfOpenMaxRequests: readNumber(circuitBreaker.halfOpenMaxRequests, 'circuitBreaker.halfOpenMaxRequests', { integer: true, min: 1 }),
      timeoutMs: readNumber(circuitBreaker.timeoutMs, 'circuitBreaker.timeoutMs', { integer: true, min: 1 }),
      errorRateThreshold: readNumber(circuitBreaker.errorRateThreshold, 'circuitBreaker.errorRateThreshold', { min: 0, max: 1 }),
    },
    trafficShaper: {
      enabled: readBoolean(trafficShaper.enabled, 'trafficShaper.enabled'),
      classes: {
        premium: validateTrafficClass(trafficClasses.premium, 'trafficShaper.classes.premium'),
        normal: validateTrafficClass(trafficClasses.normal, 'trafficShaper.classes.normal'),
        suspicious: validateTrafficClass(trafficClasses.suspicious, 'trafficShaper.classes.suspicious'),
        bot: validateTrafficClass(trafficClasses.bot, 'trafficShaper.classes.bot'),
      },
      premiumHeaders: readStringArray(trafficShaper.premiumHeaders, 'trafficShaper.premiumHeaders'),
      premiumIPs: readStringArray(trafficShaper.premiumIPs, 'trafficShaper.premiumIPs'),
    },
    biometric: {
      enabled: readBoolean(biometric.enabled, 'biometric.enabled'),
      injectIntoHTML: readBoolean(biometric.injectIntoHTML, 'biometric.injectIntoHTML'),
      scoreTTLMs: readNumber(biometric.scoreTTLMs, 'biometric.scoreTTLMs', { integer: true, min: 1 }),
      minEventsForScore: readNumber(biometric.minEventsForScore, 'biometric.minEventsForScore', { integer: true, min: 1 }),
      humanThreshold: readNumber(biometric.humanThreshold, 'biometric.humanThreshold', { integer: true, min: 0, max: 100 }),
    },
    threatIntel: {
      enabled: readBoolean(threatIntel.enabled, 'threatIntel.enabled'),
      feeds: validateFeeds(threatIntel.feeds, 'threatIntel.feeds'),
      refreshIntervalMs: readNumber(threatIntel.refreshIntervalMs, 'threatIntel.refreshIntervalMs', { integer: true, min: 1000 }),
      maxEntries: readNumber(threatIntel.maxEntries, 'threatIntel.maxEntries', { integer: true, min: 1 }),
    },
    forensics: {
      enabled: readBoolean(forensics.enabled, 'forensics.enabled'),
      maxCaptures: readNumber(forensics.maxCaptures, 'forensics.maxCaptures', { integer: true, min: 1 }),
      captureBody: readBoolean(forensics.captureBody, 'forensics.captureBody'),
      maxBodyBytes: readNumber(forensics.maxBodyBytes, 'forensics.maxBodyBytes', { integer: true, min: 1 }),
      minThreatLevel: readNumber(forensics.minThreatLevel, 'forensics.minThreatLevel', { integer: true, min: 0 }),
    },
    plugins: {
      enabled: readBoolean(plugins.enabled, 'plugins.enabled'),
      pluginDir: readString(plugins.pluginDir, 'plugins.pluginDir'),
      hotReload: readBoolean(plugins.hotReload, 'plugins.hotReload'),
      sandboxed: readBoolean(plugins.sandboxed, 'plugins.sandboxed'),
      timeoutMs: readNumber(plugins.timeoutMs, 'plugins.timeoutMs', { integer: true, min: 1 }),
    },
    zeroTrust: validateZeroTrust(raw.zeroTrust),
  };
}
