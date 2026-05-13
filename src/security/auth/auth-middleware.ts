import * as crypto from 'crypto';
import { LRUCache } from '../../utils/data-structures';
import { Logger } from '../../utils/logger';
import { JWTVerifier, type JWTVerifierConfig, type JWTPublicKeyConfig } from './jwt-verifier';
import { AuthVerificationError } from './errors';

const log = new Logger('ZeroTrust');

export interface ApiKeyEntry {
  key: string;
  name: string;
  rateLimit: number;
  permissions: string[];
  active: boolean;
}

export interface ZeroTrustConfig {
  enabled: boolean;
  mtls: {
    enabled: boolean;
    requireClientCert: boolean;
    allowedCNs: string[];
    allowedFingerprints: string[];
  };
  jwt: JWTVerifierConfig;
  apiKeys: {
    enabled: boolean;
    headerName: string;
    keys: ApiKeyEntry[];
  };
}

export interface AuthResult {
  allowed: boolean;
  statusCode: number;
  identity?: string;
  reason?: string;
  metadata?: Record<string, unknown>;
}

export interface AuthenticationInput {
  headers: Record<string, string>;
  requestPath: string;
  clientCert?: { subject?: { CN?: string }; fingerprint256?: string; valid?: boolean };
  isTls: boolean;
}

export { type JWTPublicKeyConfig };

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
    publicKeys: [],
  },
  apiKeys: {
    enabled: false,
    headerName: 'x-api-key',
    keys: [],
  },
};

export class ZeroTrustGateway {
  private readonly config: ZeroTrustConfig;
  private readonly apiKeyMap = new Map<string, ApiKeyEntry>();
  private readonly apiKeyRates = new LRUCache<number>(10000, 60000);
  private readonly jwtVerifier: JWTVerifier;

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
    this.jwtVerifier = new JWTVerifier(config.jwt);

    for (const entry of config.apiKeys.keys) {
      if (!entry.active) continue;
      const hash = crypto.createHash('sha256').update(entry.key).digest('hex');
      this.apiKeyMap.set(hash, entry);
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

  private verifyClientCert(
    cert: AuthenticationInput['clientCert'],
    isTls: boolean,
  ): AuthResult {
    if (!this.config.mtls.enabled) {
      return { allowed: true, statusCode: 200 };
    }

    this.stats.mtlsChecks++;

    if (!isTls) {
      this.stats.mtlsDenied++;
      return { allowed: false, statusCode: 400, reason: 'mTLS requires TLS transport' };
    }

    if (!cert || !cert.valid) {
      this.stats.mtlsDenied++;
      return {
        allowed: false,
        statusCode: 401,
        reason: this.config.mtls.requireClientCert ? 'Client certificate required' : 'Valid client certificate required',
      };
    }

    if (this.config.mtls.allowedCNs.length > 0) {
      const cn = cert.subject?.CN;
      if (!cn || !this.config.mtls.allowedCNs.includes(cn)) {
        this.stats.mtlsDenied++;
        return { allowed: false, statusCode: 403, reason: `CN not allowed: ${cn ?? 'none'}` };
      }
    }

    if (this.config.mtls.allowedFingerprints.length > 0) {
      const fingerprint = cert.fingerprint256;
      if (!fingerprint || !this.config.mtls.allowedFingerprints.includes(fingerprint)) {
        this.stats.mtlsDenied++;
        return { allowed: false, statusCode: 403, reason: 'Certificate fingerprint not allowed' };
      }
    }

    this.stats.mtlsAllowed++;
    return {
      allowed: true,
      statusCode: 200,
      identity: cert.subject?.CN ?? 'cert-auth',
      metadata: { mechanism: 'mtls' },
    };
  }

  private async verifyJWT(rawHeader: string): Promise<AuthResult> {
    if (!this.config.jwt.enabled) {
      return { allowed: true, statusCode: 200 };
    }

    this.stats.jwtChecks++;
    const token = rawHeader.startsWith('Bearer ') ? rawHeader.slice(7) : rawHeader;
    try {
      const verified = await this.jwtVerifier.verify(token);
      this.stats.jwtValid++;
      return {
        allowed: true,
        statusCode: 200,
        identity: verified.subject,
        metadata: {
          mechanism: 'jwt',
          kid: verified.kid,
          alg: verified.alg,
        },
      };
    } catch (error) {
      this.stats.jwtInvalid++;
      const reason = error instanceof AuthVerificationError || error instanceof Error
        ? error.message
        : 'JWT verification failed';
      return { allowed: false, statusCode: 401, reason };
    }
  }

  private verifyApiKey(key: string, requestPath: string): AuthResult {
    if (!this.config.apiKeys.enabled) {
      return { allowed: true, statusCode: 200 };
    }

    this.stats.apiKeyChecks++;
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    const entry = this.apiKeyMap.get(hash);
    if (!entry) {
      this.stats.apiKeyInvalid++;
      return { allowed: false, statusCode: 401, reason: 'Invalid API key' };
    }

    if (entry.permissions.length > 0 && !entry.permissions.some((prefix) => requestPath.startsWith(prefix))) {
      this.stats.apiKeyInvalid++;
      return { allowed: false, statusCode: 403, reason: `API key not authorized for path: ${requestPath}` };
    }

    const currentCount = this.apiKeyRates.get(hash) ?? 0;
    if (currentCount >= entry.rateLimit) {
      this.stats.apiKeyRateLimited++;
      return { allowed: false, statusCode: 429, reason: 'API key rate limit exceeded' };
    }

    this.apiKeyRates.set(hash, currentCount + 1);
    this.stats.apiKeyValid++;
    return {
      allowed: true,
      statusCode: 200,
      identity: entry.name,
      metadata: {
        mechanism: 'apiKey',
        rateLimit: entry.rateLimit,
        permissions: entry.permissions,
      },
    };
  }

  async authenticate(input: AuthenticationInput): Promise<AuthResult> {
    if (!this.config.enabled) {
      return { allowed: true, statusCode: 200 };
    }

    if (this.config.mtls.enabled) {
      const certResult = this.verifyClientCert(input.clientCert, input.isTls);
      if (!certResult.allowed) return certResult;
      if (certResult.identity) return certResult;
    }

    const authHeader = input.headers[this.config.jwt.headerName];
    if (this.config.jwt.enabled && authHeader) {
      return this.verifyJWT(authHeader);
    }

    const apiKey = input.headers[this.config.apiKeys.headerName];
    if (this.config.apiKeys.enabled && apiKey) {
      return this.verifyApiKey(apiKey, input.requestPath);
    }

    if (this.config.jwt.enabled || this.config.apiKeys.enabled || this.config.mtls.requireClientCert) {
      return { allowed: false, statusCode: 401, reason: 'Authentication required' };
    }

    return { allowed: true, statusCode: 200 };
  }

  getStats() {
    return { ...this.stats };
  }
}
