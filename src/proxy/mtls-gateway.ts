// ============================================================================
// mTLS Zero-Trust Gateway
// Mutual TLS verification + JWT validation + API key management
// ============================================================================

import * as crypto from 'crypto';
import { LRUCache } from '../utils/data-structures';
import { Logger } from '../utils/logger';

const log = new Logger('ZeroTrust');

export interface ZeroTrustConfig {
  enabled: boolean;
  mtls: {
    enabled: boolean;
    requireClientCert: boolean;
    allowedCNs: string[];          // Allowed Common Names  
    allowedFingerprints: string[]; // Allowed cert SHA256 fingerprints
  };
  jwt: {
    enabled: boolean;
    headerName: string;            // Header to read JWT from (default: 'authorization')
    algorithms: string[];          // Allowed algorithms (default: ['RS256','ES256'])
    issuer?: string;               // Required issuer claim
    audience?: string;             // Required audience claim
    clockToleranceSec: number;     // Clock skew tolerance
  };
  apiKeys: {
    enabled: boolean;
    headerName: string;            // Header containing API key (default: 'x-api-key')
    keys: ApiKeyEntry[];
  };
}

export interface ApiKeyEntry {
  key: string;
  name: string;
  rateLimit: number;             // Requests per minute
  permissions: string[];         // Allowed path prefixes
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
  },
  apiKeys: {
    enabled: false,
    headerName: 'x-api-key',
    keys: [],
  },
};

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

export class ZeroTrustGateway {
  private readonly config: ZeroTrustConfig;
  private apiKeyMap: Map<string, ApiKeyEntry> = new Map();
  private apiKeyRates: LRUCache<number>; // key -> request count in current minute

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
    this.apiKeyRates = new LRUCache(10000, 60000); // 1 min TTL

    // Index API keys for O(1) lookup
    for (const entry of config.apiKeys.keys) {
      if (entry.active) {
        // Hash the key for secure comparison
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

  /**
   * Verify mTLS client certificate
   */
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

    // Check allowed CNs
    if (this.config.mtls.allowedCNs.length > 0) {
      const cn = cert.subject?.CN;
      if (!cn || !this.config.mtls.allowedCNs.includes(cn)) {
        this.stats.mtlsDenied++;
        return { allowed: false, reason: `CN not allowed: ${cn || 'none'}` };
      }
    }

    // Check allowed fingerprints
    if (this.config.mtls.allowedFingerprints.length > 0) {
      const fp = cert.fingerprint256;
      if (!fp || !this.config.mtls.allowedFingerprints.includes(fp)) {
        this.stats.mtlsDenied++;
        return { allowed: false, reason: 'Certificate fingerprint not allowed' };
      }
    }

    this.stats.mtlsAllowed++;
    return { allowed: true, identity: cert.subject?.CN || 'cert-auth' };
  }

  /**
   * Validate JWT token from request headers
   * NOTE: This performs structural validation only (no signature verification
   * without the public key — in production, integrate with JWKS endpoint)
   */
  validateJWT(authHeader: string): AuthResult {
    if (!this.config.jwt.enabled) return { allowed: true };

    this.stats.jwtChecks++;

    // Extract token from "Bearer <token>"
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    const parts = token.split('.');
    if (parts.length !== 3) {
      this.stats.jwtInvalid++;
      return { allowed: false, reason: 'Invalid JWT format' };
    }

    try {
      // Decode payload (Base64URL)
      const payload = JSON.parse(
        Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
      ) as JWTPayload;

      const now = Math.floor(Date.now() / 1000);
      const tolerance = this.config.jwt.clockToleranceSec;

      // Check expiration
      if (payload.exp && payload.exp + tolerance < now) {
        this.stats.jwtInvalid++;
        return { allowed: false, reason: 'JWT expired' };
      }

      // Check not-before
      if (payload.nbf && payload.nbf - tolerance > now) {
        this.stats.jwtInvalid++;
        return { allowed: false, reason: 'JWT not yet valid' };
      }

      // Check issuer
      if (this.config.jwt.issuer && payload.iss !== this.config.jwt.issuer) {
        this.stats.jwtInvalid++;
        return { allowed: false, reason: `Invalid JWT issuer: ${payload.iss}` };
      }

      // Check audience
      if (this.config.jwt.audience) {
        const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!aud.includes(this.config.jwt.audience)) {
          this.stats.jwtInvalid++;
          return { allowed: false, reason: 'Invalid JWT audience' };
        }
      }

      this.stats.jwtValid++;
      return { allowed: true, identity: payload.sub || 'jwt-auth' };
    } catch {
      this.stats.jwtInvalid++;
      return { allowed: false, reason: 'JWT decode error' };
    }
  }

  /**
   * Validate API key and check rate limits
   */
  validateApiKey(key: string, requestPath: string): AuthResult {
    if (!this.config.apiKeys.enabled) return { allowed: true };

    this.stats.apiKeyChecks++;

    const hash = crypto.createHash('sha256').update(key).digest('hex');
    const entry = this.apiKeyMap.get(hash);

    if (!entry) {
      this.stats.apiKeyInvalid++;
      return { allowed: false, reason: 'Invalid API key' };
    }

    // Check permissions (path prefix matching)
    if (entry.permissions.length > 0) {
      const allowed = entry.permissions.some(p => requestPath.startsWith(p));
      if (!allowed) {
        this.stats.apiKeyInvalid++;
        return { allowed: false, reason: `API key not authorized for path: ${requestPath}` };
      }
    }

    // Check rate limit
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

  /**
   * Combined auth check: mTLS → JWT → API Key (first match wins)
   */
  authenticate(
    headers: Record<string, string>,
    requestPath: string,
    clientCert?: { subject?: { CN?: string }; fingerprint256?: string; valid?: boolean },
  ): AuthResult {
    if (!this.config.enabled) return { allowed: true };

    // mTLS check
    if (this.config.mtls.enabled && clientCert) {
      const result = this.verifyClientCert(clientCert);
      if (!result.allowed) return result;
      if (result.identity) return result; // Authenticated via cert
    }

    // JWT check
    const authHeader = headers[this.config.jwt.headerName];
    if (this.config.jwt.enabled && authHeader) {
      return this.validateJWT(authHeader);
    }

    // API key check
    const apiKey = headers[this.config.apiKeys.headerName];
    if (this.config.apiKeys.enabled && apiKey) {
      return this.validateApiKey(apiKey, requestPath);
    }

    // No auth mechanism matched
    if (this.config.mtls.requireClientCert || this.config.jwt.enabled || this.config.apiKeys.enabled) {
      return { allowed: false, reason: 'Authentication required' };
    }

    return { allowed: true };
  }

  getStats() { return { ...this.stats }; }
}
