import type { DPoPKeyProvider, HttpAdapter, Logger, ScopeResolver, SecurityProfile, TokenStore } from '#types';

/**
 * Configuration for OAuth2 clients supporting DPoP-bound access tokens.
 * This interface provides all necessary configuration parameters for establishing OAuth2
 * authentication with token endpoint, including client credentials, DPoP proof generation,
 * scope management, and access token storage.
 *
 * Configuration instances are created using {@link OAuth2ClientBuilder}. All required fields must
 * be provided before building, otherwise an error will be thrown.
 */
export interface OAuth2ClientConfig {
  /** The OAuth2 client identifier. */
  clientId: string;
  /** The private key used for client authentication via `private_key_jwt`. */
  clientPrivateKey: CryptoKey;
  /** The key identifier for the client authentication key. */
  kid: string;
  /** The OAuth2 token endpoint URL where token requests will be sent. */
  tokenEndpoint: string;
  /** The authorization server's unique identifier. */
  issuer: string;
  /** The resolver that determines which scopes to request for each API call. */
  scopeResolver: ScopeResolver;
  /** The security profile to use. Default is {@link FAPI2PrivateKeyDPoPProfile}. */
  securityProfile?: SecurityProfile;
  /** The User-Agent header value for HTTP requests. */
  userAgent?: string;
  /** The tolerance for clock skew when validating token expiration. */
  clockSkewTolerance?: number;
  /** The storage mechanism for caching access tokens. Default is {@link InMemoryTokenStore}. */
  tokenStore?: TokenStore;
  /** The provider for DPoP key pairs used to generate DPoP proof tokens. */
  dPoPKeyProvider: DPoPKeyProvider;
  /** A custom HTTP adapter for token endpoint requests. */
  httpAdapter?: HttpAdapter;

  /** A custom logger for diagnostic output. */
  logger?: Logger;
}
