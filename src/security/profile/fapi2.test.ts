// noinspection HttpUrlsUsage

import { beforeAll, describe, expect, it } from '@jest/globals';
import { FAPI2PrivateKeyDPoPProfile } from '#security/profile/fapi2';
import type { DPoPKey, DPoPKeyProvider, KeyPair, OAuth2Configuration, TokenResponse } from '#types';

describe('FAPI2PrivateKeyDPoPProfile', () => {
  let profile: FAPI2PrivateKeyDPoPProfile;

  beforeAll(() => {
    profile = new FAPI2PrivateKeyDPoPProfile();
  });

  async function createMockKeyPair(algorithm: 'ECDSA' | 'RSA-PSS', size: number = 2048): Promise<KeyPair> {
    if (algorithm === 'ECDSA') {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: size === 256 ? 'P-256' : size === 384 ? 'P-384' : 'P-521'
        },
        true,
        ['sign', 'verify']
      );
      return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
    } else {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: size,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );
      return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
    }
  }

  function createMockDPoPKeyProvider(keyPair: KeyPair): DPoPKeyProvider {
    const dpopKey: DPoPKey = {
      getKeyPair: () => keyPair,
      getKeyId: async () => 'test-key-id'
    };
    return {
      getCurrentKey: () => dpopKey,
      getKey: (_kid: string) => dpopKey
    };
  }

  describe('validateCompliance', () => {
    describe('HTTPS requirement', () => {
      it('should accept HTTPS token endpoint (P-256 EC key)', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('ECDSA', 256);
        const dpopKeyProvider = createMockDPoPKeyProvider(keyPair);

        // noinspection JSUnusedGlobalSymbols
        const config: OAuth2Configuration = {
          clientId: 'test-client',
          clientPrivateKey: keyPair.privateKey,
          kid: 'test-kid',
          tokenEndpoint: 'https://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: dpopKeyProvider
        };

        // WHEN & THEN - should not throw
        expect(() => profile.validateCompliance(config)).not.toThrow();
      });

      it('should reject HTTP token endpoint', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('ECDSA', 256);
        const dpopKeyProvider = createMockDPoPKeyProvider(keyPair);

        const config: OAuth2Configuration = {
          clientId: 'test-client',
          clientPrivateKey: keyPair.privateKey,
          kid: 'test-kid',
          tokenEndpoint: 'http://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: dpopKeyProvider
        };

        // WHEN & THEN
        expect(() => profile.validateCompliance(config)).toThrow('FAPI 2.0 requires HTTPS token endpoint');
      });
    });

    describe('client authentication requirement', () => {
      it('should require client private key', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('ECDSA', 256);
        const dpopKeyProvider = createMockDPoPKeyProvider(keyPair);

        // noinspection JSUnusedGlobalSymbols
        const config = {
          clientId: 'test-client',
          clientPrivateKey: null as any,
          kid: 'test-kid',
          tokenEndpoint: 'https://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: dpopKeyProvider
        };

        // WHEN & THEN
        expect(() => profile.validateCompliance(config as OAuth2Configuration)).toThrow(
          'FAPI 2.0 requires strong client authentication using private_key_jwt method'
        );
      });
    });

    describe('kid requirement', () => {
      it('should require non-empty kid', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('ECDSA', 256);
        const dpopKeyProvider = createMockDPoPKeyProvider(keyPair);

        const config: OAuth2Configuration = {
          clientId: 'test-client',
          clientPrivateKey: keyPair.privateKey,
          kid: '',
          tokenEndpoint: 'https://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: dpopKeyProvider
        };

        // WHEN & THEN
        expect(() => profile.validateCompliance(config)).toThrow(
          'FAPI 2.0 requires Key ID (kid) to be specified for client assertion verification'
        );
      });

      it('should reject whitespace-only kid', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('ECDSA', 256);
        const dpopKeyProvider = createMockDPoPKeyProvider(keyPair);

        // noinspection JSUnusedGlobalSymbols
        const config: OAuth2Configuration = {
          clientId: 'test-client',
          clientPrivateKey: keyPair.privateKey,
          kid: '   ',
          tokenEndpoint: 'https://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: dpopKeyProvider
        };

        // WHEN & THEN
        expect(() => profile.validateCompliance(config)).toThrow('FAPI 2.0 requires Key ID (kid) to be specified');
      });
    });

    describe('client ID requirement', () => {
      it('should require non-empty client ID', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('ECDSA', 256);
        const dpopKeyProvider = createMockDPoPKeyProvider(keyPair);

        const config: OAuth2Configuration = {
          clientId: '',
          clientPrivateKey: keyPair.privateKey,
          kid: 'test-kid',
          tokenEndpoint: 'https://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: dpopKeyProvider
        };

        // WHEN & THEN
        expect(() => profile.validateCompliance(config)).toThrow('FAPI 2.0 requires a valid client identifier');
      });
    });

    describe('DPoP key provider requirement', () => {
      it('should require DPoP key provider', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('ECDSA', 256);

        // noinspection JSUnusedGlobalSymbols
        const config = {
          clientId: 'test-client',
          clientPrivateKey: keyPair.privateKey,
          kid: 'test-kid',
          tokenEndpoint: 'https://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: null as any
        };

        // WHEN & THEN
        expect(() => profile.validateCompliance(config as OAuth2Configuration)).toThrow(
          'FAPI 2.0 requires DPoP key provider'
        );
      });
    });

    describe('key length validation', () => {
      it('should accept 2048-bit RSA key', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('RSA-PSS', 2048);
        const dpopKeyProvider = createMockDPoPKeyProvider(keyPair);

        const config: OAuth2Configuration = {
          clientId: 'test-client',
          clientPrivateKey: keyPair.privateKey,
          kid: 'test-kid',
          tokenEndpoint: 'https://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: dpopKeyProvider
        };

        // WHEN & THEN
        expect(() => profile.validateCompliance(config)).not.toThrow();
      });

      it('should reject 1024-bit RSA key', async () => {
        // GIVEN
        const keyPair = await createMockKeyPair('RSA-PSS', 1024);
        const dpopKeyProvider = createMockDPoPKeyProvider(keyPair);

        // noinspection JSUnusedGlobalSymbols
        const config: OAuth2Configuration = {
          clientId: 'test-client',
          clientPrivateKey: keyPair.privateKey,
          kid: 'test-kid',
          tokenEndpoint: 'https://auth.example.com/token',
          issuer: 'https://auth.example.com',
          scopeResolver: { resolveScopes: async () => new Set(), allScopes: async () => new Set() },
          securityProfile: profile,
          userAgent: 'test',
          clockSkewTolerance: 0,
          dPoPKeyProvider: dpopKeyProvider
        };

        // WHEN & THEN
        expect(() => profile.validateCompliance(config)).toThrow(
          'FAPI 2.0 requires RSA keys to have a minimum length of 2048 bits'
        );
      });
    });
  });

  describe('getRequiredAlgorithms', () => {
    it('should return ES256 and PS256', () => {
      // GIVEN & WHEN
      const algorithms = profile.getRequiredAlgorithms();

      // THEN
      expect(algorithms).toEqual(['ES256', 'PS256']);
    });
  });

  describe('validateClientAssertionAlgorithm', () => {
    it('should accept ES256', () => {
      // GIVEN & WHEN & THEN
      expect(() => profile.validateClientAssertionAlgorithm('ES256')).not.toThrow();
      expect(profile.validateClientAssertionAlgorithm('ES256')).toBe(true);
    });

    it('should accept PS256', () => {
      // GIVEN & WHEN & THEN
      expect(() => profile.validateClientAssertionAlgorithm('PS256')).not.toThrow();
      expect(profile.validateClientAssertionAlgorithm('PS256')).toBe(true);
    });

    it('should reject unsupported algorithm', () => {
      // GIVEN & WHEN & THEN
      expect(() => profile.validateClientAssertionAlgorithm('RS256' as any)).toThrow(
        'FAPI 2.0 requires client assertion to use one of: ES256, PS256, but got: RS256'
      );
    });
  });

  describe('isDPoPRequired', () => {
    it('should return true', () => {
      // GIVEN & WHEN
      const result = profile.isDPoPRequired();

      // THEN
      expect(result).toBe(true);
    });
  });

  describe('getClientAssertionLifetime', () => {
    it('should return 90 seconds', () => {
      // GIVEN & WHEN
      const lifetime = profile.getClientAssertionLifetime();

      // THEN
      expect(lifetime).toBe(90);
    });
  });

  describe('validateTokenResponse', () => {
    it('should accept valid token response', () => {
      // GIVEN
      const tokenResponse: TokenResponse = {
        accessToken: 'test-token',
        tokenType: 'DPoP',
        expiresIn: 3600,
        scope: 'read write'
      };
      const requestedScopes = new Set(['read', 'write']);

      // WHEN & THEN
      expect(() => profile.validateTokenResponse(tokenResponse, requestedScopes)).not.toThrow();
    });

    it('should reject token response without expiresIn', () => {
      // GIVEN
      const tokenResponse = {
        accessToken: 'test-token',
        tokenType: 'DPoP' as const
      } as TokenResponse;
      const requestedScopes = new Set<string>();

      // WHEN & THEN
      expect(() => profile.validateTokenResponse(tokenResponse, requestedScopes)).toThrow(
        'FAPI 2.0 requires valid expires_in field'
      );
    });

    it('should reject token response with zero expiresIn', () => {
      // GIVEN
      const tokenResponse: TokenResponse = {
        accessToken: 'test-token',
        tokenType: 'DPoP',
        expiresIn: 0
      };
      const requestedScopes = new Set<string>();

      // WHEN & THEN
      expect(() => profile.validateTokenResponse(tokenResponse, requestedScopes)).toThrow(
        'FAPI 2.0 requires valid expires_in field'
      );
    });

    it('should reject token response with negative expiresIn', () => {
      // GIVEN
      const tokenResponse: TokenResponse = {
        accessToken: 'test-token',
        tokenType: 'DPoP',
        expiresIn: -1
      };
      const requestedScopes = new Set<string>();

      // WHEN & THEN
      expect(() => profile.validateTokenResponse(tokenResponse, requestedScopes)).toThrow(
        'FAPI 2.0 requires valid expires_in field'
      );
    });

    it('should not fail when granted scopes are subset of requested (shouldFailOnScopeMismatch = false)', () => {
      // GIVEN
      const tokenResponse: TokenResponse = {
        accessToken: 'test-token',
        tokenType: 'DPoP',
        expiresIn: 3600,
        scope: 'read'
      };
      const requestedScopes = new Set(['read', 'write']);

      // WHEN & THEN
      expect(() => profile.validateTokenResponse(tokenResponse, requestedScopes)).not.toThrow();
    });

    it('should handle empty scope in response with no requested scopes', () => {
      // GIVEN
      const tokenResponse: TokenResponse = {
        accessToken: 'test-token',
        tokenType: 'DPoP',
        expiresIn: 3600
      };
      const requestedScopes = new Set<string>();

      // WHEN & THEN
      expect(() => profile.validateTokenResponse(tokenResponse, requestedScopes)).not.toThrow();
    });
  });

  describe('validateResourceUrl', () => {
    it('should accept HTTPS URL', () => {
      // GIVEN & WHEN & THEN
      expect(() => profile.validateResourceUrl('https://api.example.com/resource', 'resource server')).not.toThrow();
    });

    it('should reject HTTP URL', () => {
      // GIVEN & WHEN & THEN
      expect(() => profile.validateResourceUrl('http://api.example.com/resource', 'resource server')).toThrow(
        'FAPI 2.0 requires HTTPS for resource server'
      );
    });

    it('should include context in error message', () => {
      // GIVEN & WHEN & THEN
      expect(() => profile.validateResourceUrl('http://api.example.com', 'API endpoint')).toThrow(
        'FAPI 2.0 requires HTTPS for API endpoint'
      );
    });
  });

  describe('shouldFailOnScopeMismatch', () => {
    it('should return false', () => {
      // GIVEN & WHEN
      const result = profile.shouldFailOnScopeMismatch();

      // THEN
      expect(result).toBe(false);
    });
  });
});
