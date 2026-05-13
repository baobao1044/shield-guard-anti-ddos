import { createSecretKey } from 'crypto';
import type { VerifiedToken } from './claims';
import { JWKSCache } from './jwks-cache';
import { AuthConfigurationError, AuthVerificationError } from './errors';

export interface JWTPublicKeyConfig {
  kid: string;
  pem: string;
  alg?: string;
}

export interface JWTVerifierConfig {
  enabled: boolean;
  headerName: string;
  algorithms: string[];
  issuer?: string;
  audience?: string;
  clockToleranceSec: number;
  sharedSecret?: string;
  publicKeys: JWTPublicKeyConfig[];
  jwksUri?: string;
}

type KeyMaterial = Awaited<ReturnType<typeof importPublicKey>>;

const publicKeyCache = new Map<string, Promise<KeyMaterial>>();

async function importPublicKey(pem: string, algorithm: string) {
  const jose = await import('jose');
  if (pem.includes('BEGIN CERTIFICATE')) {
    return jose.importX509(pem, algorithm);
  }
  return jose.importSPKI(pem, algorithm);
}

export class JWTVerifier {
  private readonly config: JWTVerifierConfig;
  private readonly jwksCache: JWKSCache;

  constructor(config: JWTVerifierConfig, jwksCache = new JWKSCache()) {
    this.config = config;
    this.jwksCache = jwksCache;
  }

  private async resolveKey(token: string, header: { alg?: string; kid?: string }) {
    if (header.alg === 'none') {
      throw new AuthVerificationError('Unsecured JWTs are not accepted');
    }
    if (!header.alg || !this.config.algorithms.includes(header.alg)) {
      throw new AuthVerificationError(`Unsupported JWT algorithm: ${header.alg ?? 'unknown'}`);
    }
    if (!header.kid) {
      throw new AuthVerificationError('JWT kid header is required');
    }

    if (header.alg.startsWith('HS')) {
      if (!this.config.sharedSecret) {
        throw new AuthConfigurationError('Missing shared secret for HMAC JWT verification');
      }
      return createSecretKey(Buffer.from(this.config.sharedSecret, 'utf8'));
    }

    const configuredKey = this.config.publicKeys.find((entry) => entry.kid === header.kid);
    if (configuredKey) {
      const cacheKey = `${configuredKey.kid}:${header.alg}`;
      let keyPromise = publicKeyCache.get(cacheKey);
      if (!keyPromise) {
        keyPromise = importPublicKey(configuredKey.pem, configuredKey.alg ?? header.alg);
        publicKeyCache.set(cacheKey, keyPromise);
      }
      return keyPromise;
    }

    if (this.config.jwksUri) {
      return this.jwksCache.get(this.config.jwksUri);
    }

    throw new AuthVerificationError(`No verification key configured for kid=${header.kid}`);
  }

  async verify(token: string): Promise<VerifiedToken> {
    const jose = await import('jose');
    const header = jose.decodeProtectedHeader(token);
    const key = await this.resolveKey(token, header);

    const { payload, protectedHeader } = await jose.jwtVerify(token, key, {
      issuer: this.config.issuer,
      audience: this.config.audience,
      algorithms: this.config.algorithms,
      clockTolerance: this.config.clockToleranceSec,
    });

    return {
      subject: typeof payload.sub === 'string' && payload.sub !== '' ? payload.sub : 'jwt-auth',
      kid: protectedHeader.kid ?? 'unknown',
      alg: protectedHeader.alg ?? 'unknown',
      claims: {
        subject: typeof payload.sub === 'string' ? payload.sub : 'jwt-auth',
        issuer: typeof payload.iss === 'string' ? payload.iss : undefined,
        audience: payload.aud,
        issuedAt: payload.iat,
        expiresAt: payload.exp,
        notBefore: payload.nbf,
        claims: payload,
      },
    };
  }
}
