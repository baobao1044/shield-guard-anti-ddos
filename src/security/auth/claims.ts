export interface VerifiedTokenClaims {
  subject: string;
  issuer?: string;
  audience?: string | string[];
  issuedAt?: number;
  expiresAt?: number;
  notBefore?: number;
  claims: Record<string, unknown>;
}

export interface VerifiedToken {
  subject: string;
  kid: string;
  alg: string;
  claims: VerifiedTokenClaims;
}
