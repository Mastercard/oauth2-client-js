import { describe, expect, it } from '@jest/globals';
import type { Logger } from '#types';
import { OAuth2ClientBuilder } from '#core/builder';
import { FetchHttpAdapter } from '#http/adapters/fetch';
import { StaticScopeResolver } from '#scope/static';
import { StaticDPoPKeyProvider } from '#security/extension/dpop';
import { InMemoryTokenStore } from '#tokens/store';

describe('OAuth2ClientBuilder', () => {
  async function createTestKeys() {
    return await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );
  }

  async function clientBuilder(): Promise<OAuth2ClientBuilder> {
    const keyPair = await createTestKeys();
    const scopeResolver = new StaticScopeResolver(['read']);
    const dpopKeyProvider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

    return new OAuth2ClientBuilder()
      .clientId('test-client')
      .clientKey(keyPair.privateKey)
      .kid('test-kid')
      .tokenEndpoint('https://auth.example.com/token')
      .issuer('https://auth.example.com')
      .scopeResolver(scopeResolver)
      .dPoPKeyProvider(dpopKeyProvider);
  }

  describe('fluent API methods', () => {
    it('should set clientId', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();

      // WHEN
      const result = builder.clientId('test-client-id');

      // THEN
      expect(result).toBe(builder);
    });

    it('should set privateKey', async () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();
      const keyPair = await createTestKeys();

      // WHEN
      const result = builder.clientKey(keyPair.privateKey);

      // THEN
      expect(result).toBe(builder);
    });

    it('should set kid', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();

      // WHEN
      const result = builder.kid('test-kid');

      // THEN
      expect(result).toBe(builder);
    });

    it('should set tokenEndpoint', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();

      // WHEN
      const result = builder.tokenEndpoint('https://auth.example.com/token');

      // THEN
      expect(result).toBe(builder);
    });

    it('should set issuer', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();

      // WHEN
      const result = builder.issuer('https://auth.example.com');

      // THEN
      expect(result).toBe(builder);
    });

    it('should set userAgent', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();

      // WHEN
      const result = builder.userAgent('custom-user-agent');

      // THEN
      expect(result).toBe(builder);
    });

    it('should set scopeResolver', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();
      const resolver = new StaticScopeResolver(['read', 'write']);

      // WHEN
      const result = builder.scopeResolver(resolver);

      // THEN
      expect(result).toBe(builder);
    });

    it('should set dPoPKeyProvider', async () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();
      const keyPair = await createTestKeys();
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // WHEN
      const result = builder.dPoPKeyProvider(provider);

      // THEN
      expect(result).toBe(builder);
    });

    it('should set tokenStore', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();
      const store = new InMemoryTokenStore();

      // WHEN
      const result = builder.tokenStore(store);

      // THEN
      expect(result).toBe(builder);
    });

    it('should set httpAdapter', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();
      const adapter = new FetchHttpAdapter();

      // WHEN
      const result = builder.httpAdapter(adapter);

      // THEN
      expect(result).toBe(builder);
    });

    it('should set clockSkewTolerance', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();

      // WHEN
      const result = builder.clockSkewTolerance(10);

      // THEN
      expect(result).toBe(builder);
    });

    it('should set logger', () => {
      // GIVEN
      const builder = new OAuth2ClientBuilder();
      const logger: Logger = {
        trace: () => {},
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {}
      };

      // WHEN
      const result = builder.logger(logger);

      // THEN
      expect(result).toBe(builder);
    });
  });

  describe('method chaining', () => {
    it('should allow chaining multiple configuration methods', async () => {
      // GIVEN
      const keyPair = await createTestKeys();
      const scopeResolver = new StaticScopeResolver(['read']);
      const dpopKeyProvider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // WHEN
      const builder = new OAuth2ClientBuilder()
        .clientId('test-client')
        .clientKey(keyPair.privateKey)
        .kid('test-kid')
        .tokenEndpoint('https://auth.example.com/token')
        .issuer('https://auth.example.com')
        .scopeResolver(scopeResolver)
        .dPoPKeyProvider(dpopKeyProvider)
        .userAgent('test-agent')
        .clockSkewTolerance(10);

      // THEN
      expect(builder).toBeDefined();
    });

    it('should allow setting properties in any order', async () => {
      // GIVEN
      const keyPair = await createTestKeys();
      const scopeResolver = new StaticScopeResolver(['read']);
      const dpopKeyProvider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // WHEN
      const builder = new OAuth2ClientBuilder()
        .issuer('https://auth.example.com')
        .clientId('test-client')
        .dPoPKeyProvider(dpopKeyProvider)
        .tokenEndpoint('https://auth.example.com/token')
        .kid('test-kid')
        .scopeResolver(scopeResolver)
        .clientKey(keyPair.privateKey);

      // THEN
      expect(builder).toBeDefined();
    });
  });

  describe('build', () => {
    it('should build OAuth2Client with all required configuration', async () => {
      // GIVEN
      const builder = await clientBuilder();

      // WHEN
      const client = builder.build();

      // THEN
      expect(client).toBeDefined();
      expect(client.getOAuth2Headers).toBeDefined();
      expect(client.handleServerResponse).toBeDefined();
    });

    it('should build client with optional configurations', async () => {
      // GIVEN
      const keyPair = await createTestKeys();
      const scopeResolver = new StaticScopeResolver(['read']);
      const dpopKeyProvider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);
      const tokenStore = new InMemoryTokenStore();
      const httpAdapter = new FetchHttpAdapter();

      const builder = new OAuth2ClientBuilder()
        .clientId('test-client')
        .clientKey(keyPair.privateKey)
        .kid('test-kid')
        .tokenEndpoint('https://auth.example.com/token')
        .issuer('https://auth.example.com')
        .scopeResolver(scopeResolver)
        .dPoPKeyProvider(dpopKeyProvider)
        .tokenStore(tokenStore)
        .httpAdapter(httpAdapter)
        .userAgent('custom-agent')
        .clockSkewTolerance(20);

      // WHEN
      const client = builder.build();

      // THEN
      expect(client).toBeDefined();
    });

    it('should build client with custom logger', async () => {
      // GIVEN
      const keyPair = await createTestKeys();
      const scopeResolver = new StaticScopeResolver(['read']);
      const dpopKeyProvider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);
      const logger: Logger = {
        trace: () => {},
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {}
      };

      const builder = new OAuth2ClientBuilder()
        .clientId('test-client')
        .clientKey(keyPair.privateKey)
        .kid('test-kid')
        .tokenEndpoint('https://auth.example.com/token')
        .issuer('https://auth.example.com')
        .scopeResolver(scopeResolver)
        .dPoPKeyProvider(dpopKeyProvider)
        .logger(logger);

      // WHEN
      const client = builder.build();

      // THEN
      expect(client).toBeDefined();
    });
  });

  describe('edge cases', () => {
    it('should allow overwriting previously set values', async () => {
      // GIVEN
      const keyPair = await createTestKeys();
      const scopeResolver = new StaticScopeResolver(['read']);
      const dpopKeyProvider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      const builder = new OAuth2ClientBuilder()
        .clientId('first-client')
        .clientId('second-client')
        .kid('first-kid')
        .kid('second-kid')
        .userAgent('first-agent')
        .userAgent('second-agent')
        .clientKey(keyPair.privateKey)
        .tokenEndpoint('https://auth.example.com/token')
        .issuer('https://auth.example.com')
        .scopeResolver(scopeResolver)
        .dPoPKeyProvider(dpopKeyProvider);

      // WHEN
      const client = builder.build();

      // THEN
      expect(client).toBeDefined();
    });

    it('should allow building multiple clients from same builder', async () => {
      // GIVEN
      const builder = await clientBuilder();

      // WHEN
      const client1 = builder.build();
      const client2 = builder.build();

      // THEN
      expect(client1).toBeDefined();
      expect(client2).toBeDefined();
      expect(client1).not.toBe(client2);
    });

    it('should allow modifying configuration after first build', async () => {
      // GIVEN
      const builder = await clientBuilder();
      const client1 = builder.build();

      // WHEN
      builder.userAgent('modified-agent');
      const client2 = builder.build();

      // THEN
      expect(client1).toBeDefined();
      expect(client2).toBeDefined();
    });
  });
});
