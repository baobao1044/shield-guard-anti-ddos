// ============================================================================
// mTLS Zero-Trust Gateway
// Mutual TLS verification + JWT validation + API key management
// ============================================================================

import * as crypto from 'crypto';
import { LRUCache } from '../utils/data-structures';
import { Logger } from '../utils/logger';

const log = new Logger('ZeroTrust');
const SUPPORTED_JWT_ALGORITHMS = new Set([
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'ES256', 'ES384', 'ES512',
]);

type SupportedJWTAlgorithm =
  | 'HS256' | 'HS384' | 'HS512'
  | 'RS256' | 'RS384' | 'RS512'
  | 'ES256' | 'ES384' | 'ES512';

export interface ZeroTrustConfig {
  enabled: boolean;
  mtls: {
    enabled: boolean;
    requireClientCert: boolean;
    allowedCNs: string[];
    allowedFingerprints: string[];
  };
  jwt: {
    enabled: boolean;
    headerName: string;
    algorithms: string[];
    issuer?: string;
    audience?: string;
    clockToleranceSec: number;
    sharedSecrets: string[];
    publicKeys: string[];
  };
  apiKeys: {
    enabled: boolean;
    headerName: string;
    keys: ApiKeyEntry[];
  };
}

export interface ApiKeyEntry {
  key: string;
  name: string;
  rateLimit: number;
  permissions: string[];
  active: boolean;
}

export const DEFAULT_ZERO_TRUST_CONFIG: ZeroTrustConfig = {
  enabled: false,
  mtls: {
    enabled: false,
    requireClientCert: false,
    allowedCNs: [],
    allowedFingerprints: [],
  },
  jwt: {
    enabled: false,
    headerName: 'authorization',
    algorithms: ['RS256', 'ES256'],
    clockToleranceSec: 30,
    sharedSecrets: [],
    publicKeys: [],
  },
  apiKeys: {
    enabled: false,
    headerName: 'x-api-key',
    keys: [],
  },
};

interface JWTHeader {
  alg?: string;
  kid?: string;
  typ?: string;
}

interface JWTPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nbf?: number;
  [key: string]: unknown;
}

export interface AuthResult {
  allowed: boolean;
  identity?: string;
  reason?: string;
  rateLimit?: number;
  permissions?: string[];
}

function base64UrlDecode(value: string): Buffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, 'base64');
}

function decodeJSON<T>(value: string, label: string): T {
  try {
    return JSON.parse(base64UrlDecode(value).toString('utf8')) as T;
  } catch {
    throw new Error(`Invalid JWT ${label}`);
  }
}

function getHashAlgorithm(alg: SupportedJWTAlgorithm): string {
  switch (alg) {
    case 'HS256':
    case 'RS256':
    case 'ES256':
      return 'sha256';
    case 'HS384':
    case 'RS384':
    case 'ES384':
      return 'sha384';
    case 'HS512':
    case 'RS512':
    case 'ES512':
      return 'sha512';
  }
}

function isHmacAlgorithm(alg: SupportedJWTAlgorithm): boolean {
  return alg.startsWith('HS');
}

function isEcdsaAlgorithm(alg: SupportedJWTAlgorithm): boolean {
  return alg.startsWith('ES');
}

function getEcdsaComponentLength(alg: SupportedJWTAlgorithm): number {
  switch (alg) {
    case 'ES256': return 32;
    case 'ES384': return 48;
    case 'ES512': return 66;
    default: throw new Error(`Unsupported ECDSA algorithm: ${alg}`);
  }
}

function trimLeadingZeros(buffer: Buffer): Buffer {
  let index = 0;
  while (index < buffer.length - 1 && buffer[index] === 0) {
    index++;
  }
  return buffer.subarray(index);
}

function encodeDerInteger(buffer: Buffer): Buffer {
  const trimmed = trimLeadingZeros(buffer);
  if (trimmed[0] & 0x80) {
    return Buffer.concat([Buffer.from([0x02, trimmed.length + 1, 0x00]), trimmed]);
  }
  return Buffer.concat([Buffer.from([0x02, trimmed.length]), trimmed]);
}

function joseToDer(signature: Buffer, alg: SupportedJWTAlgorithm): Buffer {
  if (!isEcdsaAlgorithm(alg)) {
    return signature;
  }

  const componentLength = getEcdsaComponentLength(alg);
  if (signature.length !== componentLength * 2) {
    throw new Error('Invalid ECDSA JWT signature length');
  }

  const r = encodeDerInteger(signature.subarray(0, componentLength));
  const s = encodeDerInteger(signature.subarray(componentLength));
  const sequenceLength = r.length + s.length;
  return Buffer.concat([Buffer.from([0x30, sequenceLength]), r, s]);
}

export class ZeroTrustGateway {
  private readonly config: ZeroTrustConfig;
  private apiKeyMap: Map<string, ApiKeyEntry> = new Map();
  private apiKeyRates: LRUCache<number>;

  private stats = {
    mtlsChecks: 0,
    mtlsAllowed: 0,
    mtlsDenied: 0,
    jwtChecks: 0,
    jwtValid: 0,
    jwtInvalid: 0,
    apiKeyChecks: 0,
    apiKeyValid: 0,
    apiKeyInvalid: 0,
    apiKeyRateLimited: 0,
  };

  constructor(config: ZeroTrustConfig) {
    this.config = config;
    this.apiKeyRates = new LRUCache(10000, 60000);

    for (const entry of config.apiKeys.keys) {
      if (entry.active) {
        const hash = crypto.createHash('sha256').update(entry.key).digest('hex');
        this.apiKeyMap.set(hash, entry);
      }
    }

    if (config.enabled) {
      log.info('Zero-Trust Gateway initialized', {
        mtls: config.mtls.enabled,
        jwt: config.jwt.enabled,
        apiKeys: config.apiKeys.enabled,
        activeKeys: this.apiKeyMap.size,
      });
    }
  }

  verifyClientCert(cert: { subject?: { CN?: string }; fingerprint256?: string; valid?: boolean }): AuthResult {
    if (!this.config.mtls.enabled) return { allowed: true };

    this.stats.mtlsChecks++;

    if (!cert || !cert.valid) {
      if (this.config.mtls.requireClientCert) {
        this.stats.mtlsDenied++;
        return { allowed: false, reason: 'Client certificate required' };
      }
      return { allowed: true };
    }

    if (this.config.mtls.allowedCNs.length > 0) {
      const cn = cert.subject?.CN;
      if (!cn || !this.config.mtls.allowedCNs.includes(cn)) {
        this.stats.mtlsDenied++;
        return { allowed: false, reason: `CN not allowed: ${cn || 'none'}` };
      }
    }

    if (this.config.mtls.allowedFingerprints.length > 0) {
      const fingerprint = cert.fingerprint256;
      if (!fingerprint || !this.config.mtls.allowedFingerprints.includes(fingerprint)) {
        this.stats.mtlsDenied++;
        return { allowed: false, reason: 'Certificate fingerprint not allowed' };
      }
    }

    this.stats.mtlsAllowed++;
    return { allowed: true, identity: cert.subject?.CN || 'cert-auth' };
  }

  private verifyJWTSignature(signingInput: string, signaturePart: string, alg: SupportedJWTAlgorithm): boolean {
    const hashAlgorithm = getHashAlgorithm(alg);
    const signature = joseToDer(base64UrlDecode(signaturePart), alg);

    if (isHmacAlgorithm(alg)) {
      for (const secret of this.config.jwt.sharedSecrets) {
        const expected = crypto.createHmac(hashAlgorithm, secret).update(signingInput).digest();
        if (expected.length === signature.length && crypto.timingSafeEqual(expected, signature)) {
          return true;
        }
      }
      return false;
    }

    return this.config.jwt.publicKeys.some((key) => {
      try {
        return crypto.verify(hashAlgorithm, Buffer.from(signingInput), key, signature);
      } catch {
        return false;
      }
    });
  }

  validateJWT(authHeader: string): AuthResult {
    if (!this.config.jwt.enabled) return { allowed: true };

    this.stats.jwtChecks++;
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    const parts = token.split('.');
    if (parts.length !== 3) {
      this.stats.jwtInvalid++;
      return { allowed: false, reason: 'Invalid JWT format' };
    }

    try {
      const header = decodeJSON<JWTHeader>(parts[0], 'header');
      const payload = decodeJSON<JWTPayload>(parts[1], 'payload');
      const alg = header.alg as SupportedJWTAlgorithm | undefined;

      if (!alg || !SUPPORTED_JWT_ALGORITHMS.has(alg) || !this.config.jwt.algorithms.includes(alg)) {
        this.stats.jwtInvalid++;
        return { allowed: false, reason: `JWT algorithm not allowed: ${alg || 'missing'}` };
      }

      const signingInput = `${parts[0]}.${parts[1]}`;
      if (!this.verifyJWTSignature(signingInput, parts[2], alg)) {
        this.stats.jwtInvalid++;
        return { allowed: false, reason: 'JWT signature verification failed' };
      }

      const now = Math.floor(Date.now() / 1000);
      const tolerance = this.config.jwt.clockToleranceSec;

      if (payload.exp && payload.exp + tolerance < now) {
        this.stats.jwtInvalid++;
        return { allowed: false, reason: 'JWT expired' };
      }

      if (payload.nbf && payload.nbf - tolerance > now) {
        this.stats.jwtInvalid++;
        return { allowed: false, reason: 'JWT not yet valid' };
      }

      if (this.config.jwt.issuer && payload.iss !== this.config.jwt.issuer) {
        this.stats.jwtInvalid++;
        return { allowed: false, reason: `Invalid JWT issuer: ${payload.iss}` };
      }

      if (this.config.jwt.audience) {
        const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!audiences.includes(this.config.jwt.audience)) {
          this.stats.jwtInvalid++;
          return { allowed: false, reason: 'Invalid JWT audience' };
        }
      }

      this.stats.jwtValid++;
      return { allowed: true, identity: payload.sub || 'jwt-auth' };
    } catch (error) {
      this.stats.jwtInvalid++;
      return { allowed: false, reason: error instanceof Error ? error.message : 'JWT decode error' };
    }
  }

  validateApiKey(key: string, requestPath: string): AuthResult {
    if (!this.config.apiKeys.enabled) return { allowed: true };

    this.stats.apiKeyChecks++;
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    const entry = this.apiKeyMap.get(hash);

    if (!entry) {
      this.stats.apiKeyInvalid++;
      return { allowed: false, reason: 'Invalid API key' };
    }

    if (entry.permissions.length > 0) {
      const allowed = entry.permissions.some((permission) => requestPath.startsWith(permission));
      if (!allowed) {
        this.stats.apiKeyInvalid++;
        return { allowed: false, reason: `API key not authorized for path: ${requestPath}` };
      }
    }

    const currentCount = this.apiKeyRates.get(hash) || 0;
    if (currentCount >= entry.rateLimit) {
      this.stats.apiKeyRateLimited++;
      return { allowed: false, reason: 'API key rate limit exceeded', rateLimit: entry.rateLimit };
    }

    this.apiKeyRates.set(hash, currentCount + 1);
    this.stats.apiKeyValid++;
    return {
      allowed: true,
      identity: entry.name,
      rateLimit: entry.rateLimit,
      permissions: entry.permissions,
    };
  }

  authenticate(
    headers: Record<string, string>,
    requestPath: string,
    clientCert?: { subject?: { CN?: string }; fingerprint256?: string; valid?: boolean },
  ): AuthResult {
    if (!this.config.enabled) return { allowed: true };

    if (this.config.mtls.enabled) {
      const result = this.verifyClientCert(clientCert ?? { valid: false });
      if (!result.allowed) return result;
      if (result.identity) return result;
    }

    const authHeader = headers[this.config.jwt.headerName];
    if (this.config.jwt.enabled && authHeader) {
      return this.validateJWT(authHeader);
    }

    const apiKey = headers[this.config.apiKeys.headerName];
    if (this.config.apiKeys.enabled && apiKey) {
      return this.validateApiKey(apiKey, requestPath);
    }

    if (this.config.mtls.requireClientCert || this.config.jwt.enabled || this.config.apiKeys.enabled) {
      return { allowed: false, reason: 'Authentication required' };
    }

    return { allowed: true };
  }

  getStats() {
    return { ...this.stats };
  }
}
