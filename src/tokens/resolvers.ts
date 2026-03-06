import { computeJwkThumbprint } from '#crypto/jwk';
import type { DPoPKeyProvider, TokenKeyContext, TokenKeyResolver } from '#types';

/**
 * Default {@link TokenKeyResolver} that uses JWK thumbprint of the DPoP public key.
 */
export class DPoPJktTokenKeyResolver implements TokenKeyResolver {
  constructor(private readonly dPoPKeyProvider: DPoPKeyProvider) {}

  async resolveKey(_context: TokenKeyContext): Promise<string> {
    const currentKey = this.dPoPKeyProvider.getCurrentKey();
    return await computeJwkThumbprint(currentKey.getKeyPair().publicKey);
  }
}
