/** Supported JWT signing algorithms for FAPI 2.0 compliance. */
export type JWTAlgorithm = 'ES256' | 'PS256';

/** JWT header structure for signed tokens. */
export interface JWTHeader {
  alg: JWTAlgorithm;
  typ: 'JWT' | 'dpop+jwt' | string;
  kid?: string;
  jwk?: JsonWebKey;
}

/** Logging interface for OAuth2 client diagnostic output. */
export interface Logger {
  trace(...data: any[]): void;
  debug(...data: any[]): void;
  info(...data: any[]): void;
  warn(...data: any[]): void;
  error(...data: any[]): void;
}

/** JWT payload claims. */
export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
}

/** Asymmetric `CryptoKey` pair for signing operations. */
export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/**
 * DPoP key used to supply keys for creating DPoP proofs.
 */
export interface DPoPKey {
  /** Returns the key pair used for signing DPoP proofs. */
  getKeyPair(): KeyPair;
  /** Returns the key identifier (useful for key rotation scenarios). */
  getKeyId(): Promise<string>;
}

/**
 * Internal context for security profile validation.
 */
export interface SecurityProfileValidationContext {
  clientId: string;
  clientPrivateKey?: CryptoKey;
  kid: string;
  tokenEndpoint?: string;
  dPoPKeyProvider?: DPoPKeyProvider;
}

/**
 * Internal OAuth2 configuration used by {@link OAuth2ClientInternal} after validation.
 */
export interface OAuth2Configuration {
  clientId: string;
  clientPrivateKey: CryptoKey;
  kid: string;
  tokenEndpoint: string;
  issuer: string;
  scopeResolver: ScopeResolver;
  securityProfile: SecurityProfile;
  userAgent: string;
  clockSkewTolerance: number;
  dPoPKeyProvider: DPoPKeyProvider;
}

/**
 * Security profile defining OAuth2 compliance requirements and validation rules.
 * Implementations validate configuration against specific security standards (e.g., FAPI 2.0).
 */
export interface SecurityProfile {
  /** Validates that the configuration meets the security profile requirements. */
  validateCompliance(context: SecurityProfileValidationContext): void;

  /** Returns the list of allowed JWT signing algorithms. */
  getRequiredAlgorithms(): JWTAlgorithm[];

  /** Returns whether DPoP proof-of-possession is required. */
  isDPoPRequired(): boolean;

  /** Validates that the client assertion uses an allowed algorithm. */
  validateClientAssertionAlgorithm?(algorithm: JWTAlgorithm): boolean;

  /** Returns the lifetime in seconds for client assertions. */
  getClientAssertionLifetime?(): number;

  /** Returns the audience value to use in client assertions. */
  getClientAssertionAudience?(issuer: string): string;

  /** Validates the token response against security profile requirements. */
  validateTokenResponse?(tokenResponse: TokenResponse, requestedScopes: Set<string>): void;

  /** Returns whether to fail when granted scopes don't match requested scopes. */
  shouldFailOnScopeMismatch?(): boolean;

  /** Validates that resource URLs meet security requirements (e.g., HTTPS). */
  validateResourceUrl(url: string, context: string): void;
}

/**
 * Model for the response from an OAuth2 token endpoint.
 * See: <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.1">RFC 6749 Section 5.1</a>
 */
export interface TokenResponse {
  accessToken: string;
  tokenType: 'Bearer' | 'DPoP';
  expiresIn: number;
  scope?: string;
}

/**
 * Represents a cached access token with metadata for storage and retrieval.
 */
export interface AccessToken {
  tokenValue: string;
  scopes: Set<string>;
  expiresAt: number;
  /** JWK Thumbprint binding the token to a DPoP key. */
  jkt?: string;
}

/**
 * Filter criteria for {@link TokenStore} lookups.
 * Multiple criteria use "AND" logic.
 */
export interface AccessTokenFilter {
  /** JWK Thumbprint to match. */
  jkt?: string;
  /** Scopes to match. */
  scopes: Set<string>;
}

/**
 * Interface for caching and retrieving OAuth 2.0 access tokens.
 * Implementations should handle token expiration.
 */
export interface TokenStore {
  /** Adds an access token to the store. */
  put(accessToken: AccessToken): Promise<void>;

  /**
   * Retrieves an access token matching the specified filter criteria.
   * Returns `null` if no token was found, or if the stored token has expired.
   */
  get(filter: AccessTokenFilter): Promise<AccessToken | null>;
}

/**
 * Resolves OAuth2 scopes for API requests.
 * Implementations determine which scopes to include in token requests based on the HTTP method and target URL.
 */
export interface ScopeResolver {
  /** Returns a set of scopes to request for an HTTP request to the given URL with the given method. */
  resolveScopes(httpMethod: string, url: string): Promise<Set<string>>;

  /** Returns all possible scopes that can be requested. */
  allScopes(): Promise<Set<string>>;
}

/**
 * DPoP key provider used to supply keys for creating DPoP proofs.
 */
export interface DPoPKeyProvider {
  /** Gets the current key to be used for signing DPoP proofs. */
  getCurrentKey(): DPoPKey;

  /** Returns a key by `kid` (useful in scenarios where the provider returns different key pairs over time). */
  getKey(kid: string): DPoPKey;
}

/** Context for token key resolution. */
export interface TokenKeyContext {
  clientId: string;
  securityProfile: SecurityProfile;
}

/**
 * Resolves cache keys for associating tokens with DPoP keys.
 * The default implementation uses JWK Thumbprint (`jkt`).
 */
export interface TokenKeyResolver {
  /** Computes a cache key for token storage based on the context. */
  resolveKey(context: TokenKeyContext): Promise<string>;
}

/** HTTP request structure for token endpoint calls. */
export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

/** HTTP response structure from token endpoint. */
export interface HttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
}

/**
 * Abstraction for HTTP operations used for token endpoint requests.
 */
export interface HttpAdapter {
  /** Executes an HTTP request and returns the response. */
  execute(request: HttpRequest): Promise<HttpResponse>;
}

/** Cryptographic operations provider for JWT signing and hashing. */
export interface CryptoProvider {
  exportKey(format: 'jwk', key: CryptoKey): Promise<JsonWebKey>;
  digest(algorithm: 'SHA-256', data: BufferSource): Promise<ArrayBuffer>;
  sign(
    algorithm: EcdsaParams | RsaHashedImportParams | RsaPssParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer>;
  getRandomValues<T extends ArrayBufferView>(array: T): T;
}

/** Runtime environment abstraction for cross-platform crypto and OS detection. */
export interface RuntimeEnvironment {
  crypto: Crypto;
  cryptoProvider: CryptoProvider;
  osName: string;
  osVersion: string;
}
