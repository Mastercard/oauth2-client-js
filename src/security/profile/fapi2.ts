import type {
  DPoPKeyProvider,
  JWTAlgorithm,
  SecurityProfile,
  SecurityProfileValidationContext,
  TokenResponse
} from '#types';
import { validateKeyFAPI2 } from '#utils/crypto';
import { isAbsoluteHttpsURL } from '#http/url';

/**
 * {@link SecurityProfile} implementing FAPI 2.0 with `private_key_jwt` and DPoP.
 *
 * See: <a href="https://openid.bitbucket.io/fapi/fapi-security-profile-2_0.html">FAPI 2.0 Security Profile</a>
 */
export class FAPI2PrivateKeyDPoPProfile implements SecurityProfile {
  validateCompliance(context: SecurityProfileValidationContext): void {
    if (context.tokenEndpoint && !isAbsoluteHttpsURL(context.tokenEndpoint)) {
      throw new Error('FAPI 2.0 requires HTTPS token endpoint');
    }

    if (!context.clientPrivateKey) {
      throw new Error('FAPI 2.0 requires strong client authentication using private_key_jwt method');
    }

    if (!context.kid || context.kid.trim() === '') {
      throw new Error('FAPI 2.0 requires Key ID (kid) to be specified for client assertion verification');
    }

    if (!context.clientId || context.clientId.trim() === '') {
      throw new Error('FAPI 2.0 requires a valid client identifier');
    }

    // Validate DPoP key provider is present
    if (!context.dPoPKeyProvider) {
      throw new Error('FAPI 2.0 requires DPoP key provider');
    }

    // Validate client private key meets FAPI 2.0 minimum length requirements
    validateKeyFAPI2(context.clientPrivateKey, 'client private key');

    // Validate DPoP keys meet FAPI 2.0 minimum length requirements before constructing the client
    this.validateDPoPKeys(context.dPoPKeyProvider);
  }

  validateDPoPKeys(dPoPKeyProvider: DPoPKeyProvider): void {
    const dPoPKey = dPoPKeyProvider.getCurrentKey();
    const keyPair = dPoPKey.getKeyPair();
    validateKeyFAPI2(keyPair.privateKey, 'DPoP private key');
    validateKeyFAPI2(keyPair.publicKey, 'DPoP public key');
  }

  getRequiredAlgorithms(): JWTAlgorithm[] {
    return ['ES256', 'PS256'];
  }

  validateClientAssertionAlgorithm(algorithm: JWTAlgorithm): boolean {
    const requiredAlgorithms = this.getRequiredAlgorithms();
    if (!requiredAlgorithms.includes(algorithm)) {
      throw new Error(
        `FAPI 2.0 requires client assertion to use one of: ${requiredAlgorithms.join(', ')}, but got: ${algorithm}`
      );
    }
    return true;
  }

  isDPoPRequired(): boolean {
    return true;
  }

  getClientAssertionLifetime(): number {
    return 90;
  }

  validateTokenResponse(tokenResponse: TokenResponse, requestedScopes: Set<string>): void {
    if (!tokenResponse.expiresIn || tokenResponse.expiresIn <= 0) {
      throw new Error(
        'FAPI 2.0 requires valid expires_in field in token response for proper token lifetime management'
      );
    }

    // Validate scope if provided
    if (requestedScopes.size > 0 && tokenResponse.scope) {
      const grantedScopes = tokenResponse.scope.split(' ');
      const missingScopes = [...requestedScopes].filter(scope => !grantedScopes.includes(scope));
      if (this.shouldFailOnScopeMismatch()) {
        throw new Error(
          `FAPI 2.0 Security: Granted scopes are a subset of requested scopes. Missing: ${missingScopes.join(', ')}`
        );
      }
    }
  }

  validateResourceUrl(url: string, context: string): void {
    if (!isAbsoluteHttpsURL(url)) {
      throw new Error(`FAPI 2.0 requires HTTPS for ${context}: ${url}`);
    }
  }

  // Per RFC 6749 §3.3, authorization servers MAY grant subset of requested scopes
  shouldFailOnScopeMismatch(): boolean {
    return false;
  }
}
