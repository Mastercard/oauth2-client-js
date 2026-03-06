import { OAuth2ClientConfig } from './config';
import type { OAuth2Client } from './client';
import { OAuth2ClientInternal } from './client';
import type { DPoPKeyProvider, HttpAdapter, Logger, ScopeResolver, SecurityProfile, TokenStore } from '#types';

/**
 * Builder for constructing {@link OAuth2Client} instances.
 * Provides a fluent API for configuring all OAuth2 client parameters with validation on build.
 *
 * Example usage:
 * ```typescript
 * const client = new OAuth2ClientBuilder()
 *   .clientId('ZvT0sklPsqzTNgKJIiex5_wppXz0Tj2wl33LUZtXmCQH8dry')
 *   .kid('302449525fad5309874b16298f3cbaaf0000000000000000')
 *   .clientKey(clientPrivateKey)
 *   .tokenEndpoint('https://sandbox.api.mastercard.com/oauth/token')
 *   .issuer('https://sandbox.api.mastercard.com')
 *   .scopeResolver(new StaticScopeResolver(['service:scope1', 'service:scope2']))
 *   .dPoPKeyProvider(new StaticDPoPKeyProvider(dpopPrivateKey, dpopPublicKey))
 *   .build();
 * ```
 */
export class OAuth2ClientBuilder {
  private config: Partial<OAuth2ClientConfig> = {};

  /** Sets the OAuth2 client identifier. */
  clientId(clientId: string): this {
    this.config.clientId = clientId;
    return this;
  }

  /** Sets the private key used for client authentication via `private_key_jwt`. */
  clientKey(privateKey: CryptoKey): this {
    this.config.clientPrivateKey = privateKey;
    return this;
  }

  /** Sets the key identifier for the client authentication key. */
  kid(kid: string): this {
    this.config.kid = kid;
    return this;
  }

  /** Sets the OAuth2 token endpoint URL where token requests will be sent. */
  tokenEndpoint(url: string): this {
    this.config.tokenEndpoint = url;
    return this;
  }

  /**
   * Sets the authorization server's unique identifier.
   * See: <a href="https://datatracker.ietf.org/doc/html/rfc8414#section-2">Authorization Server Metadata</a>
   */
  issuer(url: string): this {
    this.config.issuer = url;
    return this;
  }

  /**
   * Sets the User-Agent header value for HTTP requests.
   * Default uses the library's generated user agent string.
   */
  userAgent(userAgent: string): this {
    this.config.userAgent = userAgent;
    return this;
  }

  /**
   * Sets the security profile to use.
   * Default is {@link FAPI2PrivateKeyDPoPProfile}.
   * Currently only FAPI 2.0 with private_key_jwt and DPoP is supported.
   */
  securityProfile(profile: SecurityProfile): this {
    this.config.securityProfile = profile;
    return this;
  }

  /** Sets the resolver that determines which scopes to request for each API call. */
  scopeResolver(resolver: ScopeResolver): this {
    this.config.scopeResolver = resolver;
    return this;
  }

  /** Sets the provider for DPoP key pairs used to generate DPoP proof tokens. */
  dPoPKeyProvider(provider: DPoPKeyProvider): this {
    this.config.dPoPKeyProvider = provider;
    return this;
  }

  /**
   * Sets the storage mechanism for caching access tokens.
   * Default is {@link InMemoryTokenStore}.
   */
  tokenStore(store: TokenStore): this {
    this.config.tokenStore = store;
    return this;
  }

  /** Sets a custom HTTP adapter for token endpoint requests. */
  httpAdapter(adapter: HttpAdapter): this {
    this.config.httpAdapter = adapter;
    return this;
  }

  /**
   * Sets the tolerance for clock skew when validating token expiration.
   * Must be a positive number. Default is 0 seconds.
   */
  clockSkewTolerance(seconds: number): this {
    this.config.clockSkewTolerance = seconds;
    return this;
  }

  /** Sets a custom logger for diagnostic output. */
  logger(logger: Logger): this {
    this.config.logger = logger;
    return this;
  }

  /** Builds the {@link OAuth2Client} instance with validation. */
  build(): OAuth2Client {
    return new OAuth2ClientInternal(this.config as OAuth2ClientConfig);
  }
}
