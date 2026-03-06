import { describe, expect, it } from '@jest/globals';
import { DPoPJktTokenKeyResolver } from '#tokens/resolvers';
import type { DPoPKey, DPoPKeyProvider, KeyPair, SecurityProfile, TokenKeyContext } from '#types';

describe('DPoPJktTokenKeyResolver', () => {
  async function createMockKeyPair(): Promise<KeyPair> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );

    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey
    };
  }

  function createMockDPoPKeyProvider(keyPair: KeyPair, keyId: string): DPoPKeyProvider {
    const mockDPoPKey: DPoPKey = {
      getKeyPair: () => keyPair,
      getKeyId: async () => keyId
    };

    return {
      getCurrentKey: () => mockDPoPKey,
      getKey: (_kid: string) => mockDPoPKey
    };
  }

  function createMockSecurityProfile(): SecurityProfile {
    return {
      validateCompliance: () => {},
      getRequiredAlgorithms: () => ['ES256', 'PS256'],
      isDPoPRequired: () => true,
      validateResourceUrl: () => {}
    };
  }

  describe('resolveKey', () => {
    it('should resolve key using JWK thumbprint of DPoP public key', async () => {
      // GIVEN
      const keyPair = await createMockKeyPair();
      const mockProvider = createMockDPoPKeyProvider(keyPair, 'test-key-id');
      const resolver = new DPoPJktTokenKeyResolver(mockProvider);
      const context: TokenKeyContext = {
        clientId: 'test-client-id',
        securityProfile: createMockSecurityProfile()
      };

      // WHEN
      const resolvedKey = await resolver.resolveKey(context);

      // THEN
      expect(resolvedKey).toBeDefined();
      expect(typeof resolvedKey).toBe('string');
      expect(resolvedKey.length).toBe(43); // SHA-256 base64url length
      expect(resolvedKey).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should produce consistent key for same DPoP key', async () => {
      // GIVEN
      const keyPair = await createMockKeyPair();
      const mockProvider = createMockDPoPKeyProvider(keyPair, 'test-key-id');
      const resolver = new DPoPJktTokenKeyResolver(mockProvider);
      const context: TokenKeyContext = {
        clientId: 'test-client-id',
        securityProfile: createMockSecurityProfile()
      };

      // WHEN
      const resolvedKey1 = await resolver.resolveKey(context);
      const resolvedKey2 = await resolver.resolveKey(context);
      const resolvedKey3 = await resolver.resolveKey(context);

      // THEN
      expect(resolvedKey1).toBe(resolvedKey2);
      expect(resolvedKey2).toBe(resolvedKey3);
    });

    it('should produce different keys for different DPoP keys', async () => {
      // GIVEN
      const keyPair1 = await createMockKeyPair();
      const keyPair2 = await createMockKeyPair();
      const mockProvider1 = createMockDPoPKeyProvider(keyPair1, 'key-id-1');
      const mockProvider2 = createMockDPoPKeyProvider(keyPair2, 'key-id-2');
      const resolver1 = new DPoPJktTokenKeyResolver(mockProvider1);
      const resolver2 = new DPoPJktTokenKeyResolver(mockProvider2);
      const context: TokenKeyContext = {
        clientId: 'test-client-id',
        securityProfile: createMockSecurityProfile()
      };

      // WHEN
      const resolvedKey1 = await resolver1.resolveKey(context);
      const resolvedKey2 = await resolver2.resolveKey(context);

      // THEN
      expect(resolvedKey1).not.toBe(resolvedKey2);
    });

    it('should not depend on context values', async () => {
      // GIVEN
      const keyPair = await createMockKeyPair();
      const mockProvider = createMockDPoPKeyProvider(keyPair, 'test-key-id');
      const resolver = new DPoPJktTokenKeyResolver(mockProvider);
      const context1: TokenKeyContext = {
        clientId: 'client-1',
        securityProfile: createMockSecurityProfile()
      };
      const context2: TokenKeyContext = {
        clientId: 'client-2',
        securityProfile: createMockSecurityProfile()
      };

      // WHEN
      const resolvedKey1 = await resolver.resolveKey(context1);
      const resolvedKey2 = await resolver.resolveKey(context2);

      // THEN
      expect(resolvedKey1).toBe(resolvedKey2);
    });

    it('should work with RSA keys', async () => {
      // GIVEN
      const rsaKeyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );
      const keyPair: KeyPair = {
        privateKey: rsaKeyPair.privateKey,
        publicKey: rsaKeyPair.publicKey
      };
      const mockProvider = createMockDPoPKeyProvider(keyPair, 'rsa-key-id');
      const resolver = new DPoPJktTokenKeyResolver(mockProvider);
      const context: TokenKeyContext = {
        clientId: 'test-client-id',
        securityProfile: createMockSecurityProfile()
      };

      // WHEN
      const resolvedKey = await resolver.resolveKey(context);

      // THEN
      expect(resolvedKey).toBeDefined();
      expect(typeof resolvedKey).toBe('string');
      expect(resolvedKey.length).toBe(43);
    });

    it('should use current key from provider', async () => {
      // GIVEN
      const keyPair1 = await createMockKeyPair();
      const keyPair2 = await createMockKeyPair();
      let currentKeyPair = keyPair1;

      const mockDPoPKey: DPoPKey = {
        getKeyPair: () => currentKeyPair,
        getKeyId: async () => 'dynamic-key-id'
      };

      const dynamicProvider: DPoPKeyProvider = {
        getCurrentKey: () => mockDPoPKey,
        getKey: (_kid: string) => mockDPoPKey
      };

      const resolver = new DPoPJktTokenKeyResolver(dynamicProvider);
      const context: TokenKeyContext = {
        clientId: 'test-client-id',
        securityProfile: createMockSecurityProfile()
      };

      // WHEN
      const resolvedKey1 = await resolver.resolveKey(context);
      currentKeyPair = keyPair2; // Change the key
      const resolvedKey2 = await resolver.resolveKey(context);

      // THEN
      expect(resolvedKey1).not.toBe(resolvedKey2);
    });

    it('should produce base64url encoded output', async () => {
      // GIVEN
      const keyPair = await createMockKeyPair();
      const mockProvider = createMockDPoPKeyProvider(keyPair, 'test-key-id');
      const resolver = new DPoPJktTokenKeyResolver(mockProvider);
      const context: TokenKeyContext = {
        clientId: 'test-client-id',
        securityProfile: createMockSecurityProfile()
      };

      // WHEN
      const resolvedKey = await resolver.resolveKey(context);

      // THEN
      expect(resolvedKey).not.toContain('=');
      expect(resolvedKey).not.toContain('+');
      expect(resolvedKey).not.toContain('/');
    });
  });

  describe('multiple resolver instances', () => {
    it('should produce same key when using same provider', async () => {
      // GIVEN
      const keyPair = await createMockKeyPair();
      const mockProvider = createMockDPoPKeyProvider(keyPair, 'test-key-id');
      const resolver1 = new DPoPJktTokenKeyResolver(mockProvider);
      const resolver2 = new DPoPJktTokenKeyResolver(mockProvider);
      const context: TokenKeyContext = {
        clientId: 'test-client-id',
        securityProfile: createMockSecurityProfile()
      };

      // WHEN
      const resolvedKey1 = await resolver1.resolveKey(context);
      const resolvedKey2 = await resolver2.resolveKey(context);

      // THEN
      expect(resolvedKey1).toBe(resolvedKey2);
    });
  });
});
