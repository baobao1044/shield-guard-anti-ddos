type RemoteJWKSet = ReturnType<(typeof import('jose'))['createRemoteJWKSet']>;

export class JWKSCache {
  private readonly cache = new Map<string, RemoteJWKSet>();

  async get(jwksUri: string): Promise<RemoteJWKSet> {
    const existing = this.cache.get(jwksUri);
    if (existing) {
      return existing;
    }

    const { createRemoteJWKSet } = await import('jose');
    const remote = createRemoteJWKSet(new URL(jwksUri));
    this.cache.set(jwksUri, remote);
    return remote;
  }
}
