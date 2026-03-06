import { JWTSigner, JWTUtils } from '#crypto/jwt';
import { DPoPProofGenerator, DPoPRefreshOptions } from '#security/extension/dpop';
import { FAPI2PrivateKeyDPoPProfile } from '#security/profile/fapi2';
import { InMemoryTokenStore } from '#tokens/store';
import { RuntimeEnvironment } from '#utils/runtime';
import { isDPoPNonceError } from '#utils/oauth2-errors';
import { getAlgorithmFromKey } from '#utils/crypto';
import type {
  AccessToken,
  DPoPKeyProvider,
  HttpAdapter,
  HttpRequest,
  HttpResponse,
  JWTPayload,
  Logger,
  OAuth2Configuration,
  TokenKeyResolver,
  TokenResponse,
  TokenStore
} from '#types';
import { OAuth2ClientConfig } from './config';
import { FetchHttpAdapter } from '#http/adapters/fetch';
import { noopLogger } from '#utils/logger';
import { DPoPJktTokenKeyResolver } from '#tokens/resolvers';

/**
 * Acts as an orchestrator for adding OAuth2 authentication to API requests.
 * This interface provides methods for generating OAuth2 headers, handling server responses,
 * and building token requests with DPoP proof-of-possession.
 */
export interface OAuth2Client {
  /** Generates OAuth2 headers (`Authorization`, `DPoP`, ...) for a resource server request. */
  getOAuth2Headers(method: string, url: string, headers?: Record<string, string>): Promise<Record<string, string>>;

  /**
   * Processes server response to handle DPoP nonce updates and authentication errors.
   * Returns updated headers for retry if a `use_dpop_nonce` error was detected, `undefined` otherwise.
   * See: <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-8">RFC 9449 Section 8</a>
   */
  handleServerResponse(
    statusCode: number,
    responseHeaders: Record<string, string>,
    httpMethod: string,
    url: string
  ): Promise<Record<string, string> | undefined>;

  /** Constructs an HTTP request for the token endpoint with `private_key_jwt` client assertion and DPoP proof. */
  buildTokenRequest(scopes: Set<string>, dPoPKeyId?: string, nonce?: string): Promise<HttpRequest>;

  /** Builds headers for resource server requests including `Authorization` and `DPoP` proof. */
  buildResourceRequestHeaders(
    headers: Record<string, string> | undefined,
    method: string,
    url: string,
    accessToken: string,
    dPoPKeyId?: string,
    nonce?: string
  ): Promise<Record<string, string>>;
}

export class OAuth2ClientInternal implements OAuth2Client {
  private readonly log: Logger;
  private readonly config: OAuth2Configuration;
  private readonly tokenStore: TokenStore;
  private readonly httpAdapter: HttpAdapter;
  private readonly tokenKeyResolver: TokenKeyResolver;
  private readonly jwtSigner = new JWTSigner();

  private readonly dPoPProofGenerator: DPoPProofGenerator | undefined;
  private readonly dPoPKeyProvider: DPoPKeyProvider | undefined;

  constructor(config: OAuth2ClientConfig) {
    this.log = config.logger ?? noopLogger;
    this.config = this.validateAndNormalizeConfig(config);
    this.tokenStore = config.tokenStore ?? new InMemoryTokenStore();
    this.dPoPKeyProvider = config.dPoPKeyProvider;
    this.httpAdapter = config.httpAdapter ?? new FetchHttpAdapter();

    this.dPoPProofGenerator = new DPoPProofGenerator(this.dPoPKeyProvider, this.config.clockSkewTolerance);
    this.tokenKeyResolver = new DPoPJktTokenKeyResolver(this.config.dPoPKeyProvider);

    this.info('OAuth2Client initialized');
  }

  async getOAuth2Headers(
    method: string,
    url: string,
    headers?: Record<string, string>
  ): Promise<Record<string, string>> {
    this.config.securityProfile.validateResourceUrl?.(url, 'resource server');

    const httpRequest = await this.createAuthenticatedRequest(method, url, headers ? { headers } : {});

    return httpRequest.headers;
  }

  async handleServerResponse(
    statusCode: number,
    responseHeaders: Record<string, string>,
    httpMethod: string,
    url: string
  ): Promise<Record<string, string> | undefined> {
    this.debug(`Handle server response with status code ${statusCode}`);
    const isDPoPRequired = this.config.securityProfile.isDPoPRequired();
    const normalizedHeaders = this.normalizeHeaders(responseHeaders);

    // Update nonce if in the headers
    if (isDPoPRequired && normalizedHeaders['dpop-nonce']) {
      const nonce = normalizedHeaders['dpop-nonce'];
      this.debug(`Found nonce in the response headers, updating stored nonce`);
      this.dPoPProofGenerator?.updateNonce(nonce);
    }

    // Handle DPoP nonce errors (and token refresh) when DPoP is required
    if (isDPoPRequired && isDPoPNonceError(statusCode, normalizedHeaders)) {
      this.warn(`DPoP nonce error detected (status ${statusCode}), retrying with updated nonce`);
      const currentDPoPKey = this.getDPoPKeyProvider()?.getCurrentKey();
      const jkt = await this.resolveJkt();
      return this.refreshTokenOnError(httpMethod, url, jkt, {
        isDPoPError: true,
        isDPoPRequired,
        dPoPKeyId: await currentDPoPKey?.getKeyId()
      });
    } else {
      this.debug('Not an Auth error, not refreshing token');
    }

    return undefined;
  }

  getLogger(): Logger {
    return this.log;
  }

  getDPoPKeyProvider(): DPoPKeyProvider | undefined {
    return this.dPoPKeyProvider;
  }

  private async refreshTokenOnError(
    httpMethod: string,
    url: string,
    jkt: string,
    dpopRefreshOpts?: DPoPRefreshOptions
  ): Promise<Record<string, string> | undefined> {
    const scopes = await this.config.scopeResolver.resolveScopes(httpMethod, url);

    // Get the token from store
    const existingToken = await this.tokenStore.get({ jkt, scopes });

    let accessToken = existingToken?.tokenValue;

    // Only refresh if no cached token exists
    if (!existingToken) {
      this.info('No cached token found, requesting new token');
      accessToken = (await this.refreshToken(httpMethod, url, jkt, dpopRefreshOpts?.dPoPKeyId)).accessToken;
    } else {
      this.debug('Reusing existing cached token for retry');
    }

    if (accessToken) {
      this.debug('Building OAuth2 headers with access token');
      return await this.buildResourceRequestHeaders({}, httpMethod, url, accessToken, dpopRefreshOpts?.dPoPKeyId);
    }

    // do not retry
    this.warn('No access token available, not retrying');
    return undefined;
  }

  private async getAccessToken(httpMethod: string, url: string, jkt: string, dPoPKeyId?: string): Promise<string> {
    this.debug(`Getting access token`);
    const scopes = await this.config.scopeResolver.resolveScopes(httpMethod, url);

    // Try to get cached token
    const cachedToken = await this.tokenStore.get({ jkt, scopes });

    if (!cachedToken) {
      this.info('Token not found in cache or expiring soon, requesting new token');
      // Token not in the cache or expiring, refresh it
      const tokenResponse = await this.refreshToken(httpMethod, url, jkt, dPoPKeyId);
      return tokenResponse.accessToken;
    }

    this.debug('Token found in cache and valid');
    return cachedToken.tokenValue;
  }

  private async refreshToken(httpMethod: string, url: string, jkt: string, dPoPKeyId?: string): Promise<TokenResponse> {
    const scopes = await this.config.scopeResolver.resolveScopes(httpMethod, url);
    const newTokenResponse = await this.requestToken(scopes, dPoPKeyId);
    await this.storeToken(jkt, newTokenResponse, scopes);
    return newTokenResponse;
  }

  private async requestToken(scopes: Set<string> = new Set(), dPoPKeyId?: string): Promise<TokenResponse> {
    let response = await this.executeTokenRequest(scopes, dPoPKeyId);

    if (isDPoPNonceError(response.status, response.headers, response.body)) {
      this.warn('DPoP nonce error detected, retrying token request');
      // Retry once (after caching the nonce)
      response = await this.executeTokenRequest(scopes, dPoPKeyId);
    }

    const tokenResponse = this.parseTokenResponse(response.body);
    this.validateTokenResponse(tokenResponse, scopes);
    this.info(`Received access token (${tokenResponse.tokenType}, expires in ${tokenResponse.expiresIn}sec.)`);
    return tokenResponse;
  }

  private async executeTokenRequest(scopes: Set<string>, dPoPKeyId?: string): Promise<HttpResponse> {
    const request = await this.buildTokenRequest(scopes, dPoPKeyId);
    this.info(`Executing token request for scopes [${Array.from(scopes)}]`);
    const response = await this.httpAdapter.execute(request);

    if (response.status >= 200 && response.status < 300) {
      this.info(`Token request completed successfully (status ${response.status})`);
    } else {
      this.warn(`Token request failed with status ${response.status}: ${response.statusText}`);
    }

    // cache DPoP nonce if present
    await this.handleServerResponse(response.status, response.headers, request.method.toUpperCase(), request.url);
    return response;
  }

  async buildTokenRequest(scopes: Set<string>, dPoPKeyId?: string, nonce?: string): Promise<HttpRequest> {
    const tokenEndpoint = this.config.tokenEndpoint;
    const body = await this.buildTokenRequestBody(scopes);
    const headers = await this.buildTokenRequestHeaders(tokenEndpoint, dPoPKeyId, nonce);

    return {
      method: 'POST',
      url: tokenEndpoint,
      headers,
      body: body.toString()
    };
  }

  private async buildTokenRequestBody(scopes: Set<string>): Promise<URLSearchParams> {
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.config.clientId
    });

    if (scopes.size > 0) {
      body.append('scope', [...scopes].join(' '));
    }

    if (this.config.clientPrivateKey) {
      await this.addClientAuthentication(body);
    }

    return body;
  }

  private async addClientAuthentication(body: URLSearchParams): Promise<void> {
    const clientAssertion = await this.createClientAssertion();
    body.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    body.append('client_assertion', clientAssertion);
  }

  private async buildTokenRequestHeaders(
    tokenEndpoint: string,
    dPoPKeyId?: string,
    nonce?: string
  ): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      ...(this.config.userAgent && { 'User-Agent': this.config.userAgent })
    };
    if (this.config.securityProfile.isDPoPRequired() && this.dPoPProofGenerator && dPoPKeyId) {
      this.debug('Generating DPoP proof for authenticated request');
      headers['DPoP'] = await this.dPoPProofGenerator.generateProof('POST', tokenEndpoint, dPoPKeyId, nonce);
    }
    return headers;
  }

  private validateTokenResponse(tokenResponse: TokenResponse, scopes: Set<string>): void {
    if (!tokenResponse.accessToken) {
      this.error('Token response validation failed: missing access_token');
      throw new Error('Token response missing access_token');
    }

    if (!tokenResponse.tokenType) {
      this.error('Token response validation failed: missing token_type');
      throw new Error('Token response missing token_type');
    }

    if (!tokenResponse.expiresIn) {
      this.error('Token response validation failed: missing expires_in');
      throw new Error('Token response missing expires_in');
    }

    this.validateTokenType(tokenResponse.tokenType);
    this.applySecurityProfileValidation(tokenResponse, scopes);
  }

  private validateTokenType(tokenType: string): void {
    const normalizedTokenType = tokenType.toLowerCase();

    if (normalizedTokenType !== 'dpop') {
      this.error(`Token type validation failed: expected DPoP but received ${tokenType}`);
      throw new Error(`Expected DPoP token type but received: ${tokenType}`);
    }
  }

  private applySecurityProfileValidation(tokenResponse: TokenResponse, scopes: Set<string>): void {
    if (this.config.securityProfile.validateTokenResponse) {
      this.config.securityProfile.validateTokenResponse(tokenResponse, scopes);
    }
  }

  private async createAuthenticatedRequest(
    method: string,
    url: string,
    options: {
      headers?: Record<string, string>;
      body?: string;
    } = {}
  ): Promise<HttpRequest> {
    const currentDPoPKey = this.getDPoPKeyProvider()?.getCurrentKey();
    const dPoPKeyId = await currentDPoPKey?.getKeyId();
    const jkt = await this.resolveJkt();

    const accessToken = await this.getAccessToken(method, url, jkt, dPoPKeyId);

    const headers = await this.buildResourceRequestHeaders(options.headers, method, url, accessToken, dPoPKeyId);

    return { method, url, headers };
  }

  async buildResourceRequestHeaders(
    headers: Record<string, string> | undefined,
    method: string,
    url: string,
    accessToken: string,
    dPoPKeyId?: string,
    nonce?: string
  ): Promise<Record<string, string>> {
    const authHeaders: Record<string, string> = {
      ...(this.config.userAgent && { 'User-Agent': this.config.userAgent }),
      ...headers
    };

    // Add DPoP header
    if (this.config.securityProfile.isDPoPRequired() && dPoPKeyId && this.dPoPProofGenerator) {
      this.debug('Generating DPoP proof for authenticated request');
      authHeaders['DPoP'] = await this.dPoPProofGenerator.generateProof(method, url, dPoPKeyId, nonce, accessToken);
    }
    authHeaders['Authorization'] = `DPoP ${accessToken}`;
    return authHeaders;
  }

  private validateAndNormalizeConfig(config: OAuth2ClientConfig): OAuth2Configuration {
    if (!config.clientId) {
      this.log.error('clientId is not set in the configuration');
      throw new Error('clientId is required');
    }

    if (!config.clientPrivateKey) {
      this.log.error('clientPrivateKey is not set in the configuration');
      throw new Error('clientPrivateKey is required');
    }

    if (!config.kid) {
      this.log.error('kid is not set in the configuration');
      throw new Error('kid is required');
    }

    if (!config.tokenEndpoint) {
      this.log.error('tokenEndpoint is not set in the configuration');
      throw new Error('tokenEndpoint is required');
    }

    if (!config.issuer) {
      this.log.error('issuer is not set in the configuration');
      throw new Error('issuer is required');
    }

    if (!config.scopeResolver) {
      this.log.error('scopeResolver is not set in the configuration');
      throw new Error('scopeResolver is required');
    }

    if (!config.dPoPKeyProvider) {
      throw new Error('dPoPKeyProvider is required');
    }

    if (config.clockSkewTolerance && config.clockSkewTolerance < 0) {
      throw new Error('Clock skew tolerance must be positive');
    }

    // Only FAPI2 with DPoP profile is currently supported
    if (config.securityProfile && !(config.securityProfile instanceof FAPI2PrivateKeyDPoPProfile)) {
      this.log.error('Unsupported security profile provided in the configuration');
      throw new Error('Security profile must be FAPI 2.0 with private_key_jwt and DPoP');
    }

    const userAgent = this.defaultUserAgent(config.userAgent);
    const clockSkewTolerance = config.clockSkewTolerance ?? 0;
    const securityProfile = config.securityProfile ?? new FAPI2PrivateKeyDPoPProfile();

    const normalizedConfig: OAuth2Configuration = {
      clientId: config.clientId,
      clientPrivateKey: config.clientPrivateKey,
      kid: config.kid,
      clockSkewTolerance,
      scopeResolver: config.scopeResolver,
      securityProfile,
      tokenEndpoint: config.tokenEndpoint,
      issuer: config.issuer,
      userAgent,
      dPoPKeyProvider: config.dPoPKeyProvider
    };

    securityProfile.validateCompliance({
      clientId: config.clientId,
      clientPrivateKey: config.clientPrivateKey,
      kid: config.kid,
      tokenEndpoint: config.tokenEndpoint,
      dPoPKeyProvider: config.dPoPKeyProvider
    });

    const algorithm = getAlgorithmFromKey(config.clientPrivateKey);

    securityProfile.validateClientAssertionAlgorithm?.(algorithm);

    this.info('Configuration validated successfully');
    return normalizedConfig;
  }

  private defaultUserAgent(userAgent?: string): string {
    if (userAgent) {
      return userAgent;
    }
    const runtime = RuntimeEnvironment.detect();
    const version = process.env.npm_package_version;
    return `mastercard-oauth2-js-client / ${version} (${runtime.osName}; ${runtime.osVersion})`;
  }

  private async createClientAssertion(): Promise<string> {
    const jti = JWTUtils.generateJti();

    // Get assertion lifetime from security profile or use default
    const assertionLifetime = this.config.securityProfile?.getClientAssertionLifetime?.() ?? 90;

    // Determine audience from security profile or use default
    const audience =
      this.config.securityProfile?.getClientAssertionAudience?.(this.config.issuer) ?? this.config.issuer;

    // Apply clock skew tolerance
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + assertionLifetime + this.config.clockSkewTolerance;
    const nbf = iat - this.config.clockSkewTolerance;

    const payload: JWTPayload = {
      iss: this.config.clientId,
      sub: this.config.clientId,
      aud: audience,
      jti,
      iat,
      nbf,
      exp: exp
    };

    const header = { kid: this.config.kid };

    return await this.jwtSigner.signJWT(payload, this.config.clientPrivateKey, header);
  }

  private async storeToken(jkt: string, tokenResponse: TokenResponse, scopes: Set<string>): Promise<void> {
    if (!tokenResponse.expiresIn) {
      throw new Error('Token response must include expiry');
    }

    const accessToken: AccessToken = {
      tokenValue: tokenResponse.accessToken,
      scopes,
      expiresAt: Date.now() + tokenResponse.expiresIn * 1000,
      jkt
    };

    await this.tokenStore.put(accessToken);
    this.debug(`Token stored in cache with jkt: ${jkt}`);
  }

  private parseTokenResponse(response: string): TokenResponse {
    try {
      const parsed = JSON.parse(response) as {
        access_token: string;
        expires_in: number;
        scope: string;
        token_type: 'Bearer' | 'DPoP';
      };

      return {
        accessToken: parsed.access_token,
        expiresIn: parsed.expires_in,
        scope: parsed.scope,
        tokenType: parsed.token_type
      };
    } catch (error) {
      this.error('Failed to parse token response as JSON', { response, error });
      throw new Error('Failed to parse JSON access token response');
    }
  }

  private normalizeHeaders(headers: Record<string, string>): Record<string, string> {
    const normalized: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers || {})) {
      normalized[key.toLowerCase()] = value;
    }
    return normalized;
  }

  private async resolveJkt(): Promise<string> {
    return this.tokenKeyResolver.resolveKey({
      clientId: this.config.clientId,
      securityProfile: this.config.securityProfile
    });
  }

  private debug(..._args: any[]): void {
    this.log.debug('[client]', ..._args);
  }

  private info(..._args: any[]): void {
    this.log.info('[client]', ..._args);
  }

  private warn(..._args: any[]): void {
    this.log.warn('[client]', ..._args);
  }

  private error(..._args: any[]): void {
    this.log.error('[client]', ..._args);
  }
}
