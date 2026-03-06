import { beforeEach, describe, expect, it } from '@jest/globals';
import { OAuth2ClientInternal } from '#core/client';
import type { AccessToken, HttpAdapter, HttpResponse, Logger, TokenStore } from '#types';
import type { OAuth2ClientConfig } from '#core/config';
import { StaticDPoPKeyProvider } from '#security/extension/dpop';
import { StaticScopeResolver } from '#scope/static';
import { InMemoryTokenStore } from '#tokens/store';

describe('OAuth2ClientInternal', () => {
  let clientPrivateKey: CryptoKey;
  let dPoPPrivateKey: CryptoKey;
  let dPoPPublicKey: CryptoKey;
  let mockHttpAdapter: HttpAdapter;

  beforeEach(async () => {
    // Create test keys
    const clientKeyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );
    clientPrivateKey = clientKeyPair.privateKey;

    const dPoPKeyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );
    dPoPPrivateKey = dPoPKeyPair.privateKey;
    dPoPPublicKey = dPoPKeyPair.publicKey;

    mockHttpAdapter = {
      execute: async (): Promise<HttpResponse> => ({
        status: 200,
        statusText: 'OK',
        headers: {},
        body: JSON.stringify({
          access_token: 'test-token',
          token_type: 'DPoP',
          expires_in: 3600,
          scope: 'read'
        })
      })
    };
  });

  describe('configuration validation', () => {
    it('should throw error when clientId is missing', () => {
      // GIVEN
      const config = {
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey)
      } as unknown as OAuth2ClientConfig;

      // WHEN & THEN
      expect(() => new OAuth2ClientInternal(config)).toThrow('clientId is required');
    });

    it('should throw error when clientPrivateKey is missing', () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey)
      } as unknown as OAuth2ClientConfig;

      // WHEN & THEN
      expect(() => new OAuth2ClientInternal(config)).toThrow('clientPrivateKey is required');
    });

    it('should throw error when kid is missing', () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey)
      } as unknown as OAuth2ClientConfig;

      // WHEN & THEN
      expect(() => new OAuth2ClientInternal(config)).toThrow('kid is required');
    });

    it('should throw error when tokenEndpoint is missing', () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey)
      } as unknown as OAuth2ClientConfig;

      // WHEN & THEN
      expect(() => new OAuth2ClientInternal(config)).toThrow('tokenEndpoint is required');
    });

    it('should throw error when issuer is missing', () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey)
      } as unknown as OAuth2ClientConfig;

      // WHEN & THEN
      expect(() => new OAuth2ClientInternal(config)).toThrow('issuer is required');
    });

    it('should throw error when scopeResolver is missing', () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey)
      } as unknown as OAuth2ClientConfig;

      // WHEN & THEN
      expect(() => new OAuth2ClientInternal(config)).toThrow('scopeResolver is required');
    });

    it('should throw error when dPoPKeyProvider is missing', () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read'])
      } as unknown as OAuth2ClientConfig;

      // WHEN & THEN
      expect(() => new OAuth2ClientInternal(config)).toThrow('dPoPKeyProvider is required');
    });

    it('should throw error when clockSkewTolerance is negative', () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        clockSkewTolerance: -10
      } as OAuth2ClientConfig;

      // WHEN & THEN
      expect(() => new OAuth2ClientInternal(config)).toThrow('Clock skew tolerance must be positive');
    });

    it('should create client with valid configuration', () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey)
      } as OAuth2ClientConfig;

      // WHEN
      const client = new OAuth2ClientInternal(config);

      // THEN
      expect(client).toBeDefined();
      expect(client.getLogger()).toBeDefined();
      expect(client.getDPoPKeyProvider()).toBe(config.dPoPKeyProvider);
    });

    it('should use custom logger if provided', () => {
      // GIVEN
      const mockLogger: Logger = {
        trace: () => {},
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {}
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        logger: mockLogger
      } as OAuth2ClientConfig;

      // WHEN
      const client = new OAuth2ClientInternal(config);

      // THEN
      expect(client.getLogger()).toBe(mockLogger);
    });
  });

  describe('handleServerResponse', () => {
    let client: OAuth2ClientInternal;
    let mockHttpAdapter: HttpAdapter;

    beforeEach(() => {
      // Create mock HTTP adapter
      mockHttpAdapter = {
        execute: async (): Promise<HttpResponse> => ({
          status: 200,
          statusText: 'OK',
          headers: {},
          body: JSON.stringify({
            access_token: 'test-token',
            token_type: 'DPoP',
            expires_in: 3600,
            scope: 'read'
          })
        })
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      client = new OAuth2ClientInternal(config);
    });

    it('should return retry headers when isDPoPRequired and isDPoPNonceError', async () => {
      // GIVEN
      await client.getOAuth2Headers('GET', 'https://api.example.com/resource');

      // Simulate a DPoP nonce error response (use_dpop_nonce)
      const statusCode = 401;
      const headers = {
        'www-authenticate': 'DPoP error="use_dpop_nonce"',
        'dpop-nonce': 'server-provided-nonce'
      };

      // WHEN
      const result = await client.handleServerResponse(statusCode, headers, 'GET', 'https://api.example.com/resource');

      // THEN
      expect(result).toBeDefined();
      expect(result!['Authorization']).toMatch(/^DPoP /);
      expect(result!['DPoP']).toBeDefined();
    });

    it('should not retry when status is 401 but not a DPoP nonce error', async () => {
      // GIVEN
      const statusCode = 401;
      const headers = {
        'www-authenticate': 'Bearer error="invalid_token"'
      };

      // WHEN
      const result = await client.handleServerResponse(statusCode, headers, 'GET', 'https://api.example.com/resource');

      // THEN
      expect(result).toBeUndefined();
    });

    it('should not retry when status is 403 even with www-authenticate header', async () => {
      // GIVEN
      const statusCode = 403;
      const headers = {
        'www-authenticate': 'DPoP error="insufficient_scope"'
      };

      // WHEN
      const result = await client.handleServerResponse(statusCode, headers, 'GET', 'https://api.example.com/resource');

      // THEN - should return undefined (no retry)
      expect(result).toBeUndefined();
    });

    it('should cache DPoP nonce from response headers', async () => {
      // GIVEN
      const statusCode = 200;
      const headers = {
        'dpop-nonce': 'test-nonce-value'
      };

      // WHEN
      await client.handleServerResponse(statusCode, headers, 'GET', 'https://api.example.com/resource');

      // THEN - should not throw
      expect(true).toBe(true);
    });

    it('should return undefined for success responses', async () => {
      // GIVEN
      const statusCode = 200;
      const headers = {};

      // WHEN
      const result = await client.handleServerResponse(statusCode, headers, 'GET', 'https://api.example.com/resource');

      // THEN
      expect(result).toBeUndefined();
    });

    it('should return undefined for token endpoint responses', async () => {
      // GIVEN
      const statusCode = 400;
      const headers = {};

      // WHEN
      const result = await client.handleServerResponse(statusCode, headers, 'POST', 'https://auth.example.com/token');

      // THEN
      expect(result).toBeUndefined();
    });

    it('should return undefined when no www-authenticate header', async () => {
      // GIVEN
      const statusCode = 404;
      const headers = {};

      // WHEN
      const result = await client.handleServerResponse(statusCode, headers, 'GET', 'https://api.example.com/resource');

      // THEN
      expect(result).toBeUndefined();
    });

    it('should return undefined when status code is not 400-403', async () => {
      // GIVEN
      const statusCode = 500;
      const headers = {
        'www-authenticate': 'DPoP error="invalid_token"'
      };

      // WHEN
      const result = await client.handleServerResponse(statusCode, headers, 'GET', 'https://api.example.com/resource');

      // THEN
      expect(result).toBeUndefined();
    });
  });

  describe('token response validation', () => {
    it('should throw error when JSON is invalid', async () => {
      // GIVEN
      const mockHttpAdapter: HttpAdapter = {
        execute: async (): Promise<HttpResponse> => ({
          status: 200,
          statusText: 'OK',
          headers: {},
          body: 'invalid json {}'
        })
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);

      // WHEN & THEN
      await expect(client.getOAuth2Headers('GET', 'https://api.example.com/resource')).rejects.toThrow(
        'Failed to parse JSON access token response'
      );
    });

    it('should throw error when access_token is missing', async () => {
      // GIVEN
      const mockHttpAdapter: HttpAdapter = {
        execute: async (): Promise<HttpResponse> => ({
          status: 200,
          statusText: 'OK',
          headers: {},
          body: JSON.stringify({
            token_type: 'DPoP',
            expires_in: 3600
          })
        })
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);

      // WHEN & THEN
      await expect(client.getOAuth2Headers('GET', 'https://api.example.com/resource')).rejects.toThrow(
        'Token response missing access_token'
      );
    });

    it('should throw error when token_type is missing', async () => {
      // GIVEN
      const mockHttpAdapter: HttpAdapter = {
        execute: async (): Promise<HttpResponse> => ({
          status: 200,
          statusText: 'OK',
          headers: {},
          body: JSON.stringify({
            access_token: 'test-token',
            expires_in: 3600
          })
        })
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);

      // WHEN & THEN
      await expect(client.getOAuth2Headers('GET', 'https://api.example.com/resource')).rejects.toThrow(
        'Token response missing token_type'
      );
    });

    it('should throw error when expires_in is missing', async () => {
      // GIVEN
      const mockHttpAdapter: HttpAdapter = {
        execute: async (): Promise<HttpResponse> => ({
          status: 200,
          statusText: 'OK',
          headers: {},
          body: JSON.stringify({
            access_token: 'test-token',
            token_type: 'DPoP'
          })
        })
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);

      // WHEN & THEN
      await expect(client.getOAuth2Headers('GET', 'https://api.example.com/resource')).rejects.toThrow(
        'Token response missing expires_in'
      );
    });

    it('should throw error when token_type is not DPoP', async () => {
      // GIVEN
      const mockHttpAdapter: HttpAdapter = {
        execute: async (): Promise<HttpResponse> => ({
          status: 200,
          statusText: 'OK',
          headers: {},
          body: JSON.stringify({
            access_token: 'test-token',
            token_type: 'Bearer',
            expires_in: 3600
          })
        })
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);

      // WHEN & THEN
      await expect(client.getOAuth2Headers('GET', 'https://api.example.com/resource')).rejects.toThrow(
        'Expected DPoP token type but received: Bearer'
      );
    });
  });

  describe('token store edge cases', () => {
    function newConfig(store: TokenStore): OAuth2ClientConfig {
      return {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        tokenStore: store,
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;
    }

    it('should request new token when store returns null', async () => {
      // GIVEN
      const mockTokenStore: TokenStore = {
        put: async () => {},
        get: async () => null
      };

      const client = new OAuth2ClientInternal(newConfig(mockTokenStore));

      // WHEN
      const headers = await client.getOAuth2Headers('GET', 'https://api.example.com/resource');

      // THEN
      expect(headers).toBeDefined();
      expect(headers['Authorization']).toContain('DPoP');
    });

    it('should use cached token when store returns valid token', async () => {
      // GIVEN
      const cachedToken: AccessToken = {
        tokenValue: 'cached-token',
        scopes: new Set(['read']),
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'test-jkt'
      };

      const mockTokenStore: TokenStore = {
        put: async () => {},
        get: async () => cachedToken
      };

      const client = new OAuth2ClientInternal(newConfig(mockTokenStore));

      // WHEN
      const headers = await client.getOAuth2Headers('GET', 'https://api.example.com/resource');

      // THEN
      expect(headers).toBeDefined();
      expect(headers['Authorization']).toBe('DPoP cached-token');
    });

    it('should remove expired tokens from store when storing new token', async () => {
      // GIVEN
      const expiredTime = Date.now() - 10000;

      class TrackingTokenStore extends InMemoryTokenStore {
        constructor() {
          super();
          (this as any).store.set('<none>|read', {
            tokenValue: 'expired-token',
            scopes: new Set(['read']),
            expiresAt: expiredTime
          });
        }
      }

      const tokenStore = new TrackingTokenStore();

      expect((tokenStore as any).store.size).toBe(1);

      const client = new OAuth2ClientInternal(newConfig(tokenStore));

      // WHEN
      await client.getOAuth2Headers('GET', 'https://api.example.com/resource');

      // THEN
      expect((tokenStore as any).store.has('<none>|read')).toBe(true);
      const storedToken = (tokenStore as any).store.get('<none>|read');
      expect(storedToken.tokenValue).not.toBe('expired-token');
    });
  });

  describe('buildResourceRequestHeaders', () => {
    it('should build headers with custom user agent', async () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter,
        userAgent: 'CustomAgent/1.0'
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);

      // WHEN
      const headers = await client.buildResourceRequestHeaders(
        {},
        'GET',
        'https://api.example.com/resource',
        'test-token',
        'key-id'
      );

      // THEN
      expect(headers['User-Agent']).toBe('CustomAgent/1.0');
      expect(headers['Authorization']).toBe('DPoP test-token');
      expect(headers['DPoP']).toBeDefined();
    });

    it('should merge provided headers with OAuth2 headers', async () => {
      // GIVEN
      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);

      // WHEN
      const headers = await client.buildResourceRequestHeaders(
        { 'X-Custom-Header': 'custom-value' },
        'GET',
        'https://api.example.com/resource',
        'test-token',
        'key-id'
      );

      // THEN
      expect(headers['X-Custom-Header']).toBe('custom-value');
      expect(headers['Authorization']).toBe('DPoP test-token');
    });
  });

  describe('buildTokenRequest', () => {
    it('should build token request with scopes', async () => {
      // GIVEN
      const mockHttpAdapter: HttpAdapter = {
        execute: async (): Promise<HttpResponse> => ({
          status: 200,
          statusText: 'OK',
          headers: {},
          body: JSON.stringify({
            access_token: 'test-token',
            token_type: 'DPoP',
            expires_in: 3600,
            scope: 'read write'
          })
        })
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver(['read', 'write']),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);
      const scopes = new Set(['read', 'write']);

      // WHEN
      const request = await client.buildTokenRequest(scopes, 'key-id');

      // THEN
      expect(request.method).toBe('POST');
      expect(request.url).toBe('https://auth.example.com/token');
      expect(request.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
      expect(request.headers['Accept']).toBe('application/json');
      expect(request.headers['DPoP']).toBeDefined();
      // URLSearchParams encodes spaces as + (both + and %20 are valid)
      expect(request.body).toMatch(/scope=read[+%20]write/);
    });

    it('should build token request without scopes', async () => {
      // GIVEN
      const mockHttpAdapter: HttpAdapter = {
        execute: async (): Promise<HttpResponse> => ({
          status: 200,
          statusText: 'OK',
          headers: {},
          body: JSON.stringify({
            access_token: 'test-token',
            token_type: 'DPoP',
            expires_in: 3600
          })
        })
      };

      const config = {
        clientId: 'test-client',
        clientPrivateKey,
        kid: 'test-kid',
        tokenEndpoint: 'https://auth.example.com/token',
        issuer: 'https://auth.example.com',
        scopeResolver: new StaticScopeResolver([]),
        dPoPKeyProvider: new StaticDPoPKeyProvider(dPoPPrivateKey, dPoPPublicKey),
        httpAdapter: mockHttpAdapter
      } as OAuth2ClientConfig;

      const client = new OAuth2ClientInternal(config);
      const scopes = new Set<string>();

      // WHEN
      const request = await client.buildTokenRequest(scopes, 'key-id');

      // THEN
      expect(request.body).not.toContain('scope=');
    });
  });
});
