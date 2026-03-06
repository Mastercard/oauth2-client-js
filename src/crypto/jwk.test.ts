import { describe, expect, it } from '@jest/globals';
import { computeJwkThumbprint } from '#crypto/jwk';

describe('computeJwkThumbprint', () => {
  const assertThumbprint = (thumbprint: string) => {
    expect(thumbprint).toBeDefined();
    expect(typeof thumbprint).toBe('string');
    expect(thumbprint.length).toBeGreaterThan(0);
    expect(thumbprint).not.toContain('=');
    expect(thumbprint).not.toContain('+');
    expect(thumbprint).not.toContain('/');
  };

  describe('should compute thumbprint for EC keys', () => {
    it('should compute JWK thumbprint for P-256 EC public key', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      assertThumbprint(thumbprint);
    });

    it('should compute JWK thumbprint for P-384 EC public key', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-384'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      expect(thumbprint).toBeDefined();
      expect(typeof thumbprint).toBe('string');
      expect(thumbprint.length).toBeGreaterThan(0);
    });

    it('should compute JWK thumbprint for P-521 EC public key', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-521'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      expect(thumbprint).toBeDefined();
      expect(typeof thumbprint).toBe('string');
      expect(thumbprint.length).toBeGreaterThan(0);
    });

    it('should produce consistent thumbprint for same EC key', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint1 = await computeJwkThumbprint(keyPair.publicKey);
      const thumbprint2 = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      expect(thumbprint1).toBe(thumbprint2);
    });

    it('should produce different thumbprints for different EC keys', async () => {
      // GIVEN
      const keyPair1 = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const keyPair2 = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint1 = await computeJwkThumbprint(keyPair1.publicKey);
      const thumbprint2 = await computeJwkThumbprint(keyPair2.publicKey);

      // THEN
      expect(thumbprint1).not.toBe(thumbprint2);
    });
  });

  describe('should compute thumbprint for RSA keys', () => {
    it('should compute JWK thumbprint for RSA-PSS public key', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      assertThumbprint(thumbprint);
    });

    it('should produce consistent thumbprint for same RSA key', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint1 = await computeJwkThumbprint(keyPair.publicKey);
      const thumbprint2 = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      expect(thumbprint1).toBe(thumbprint2);
    });

    it('should produce different thumbprints for different RSA keys', async () => {
      // GIVEN
      const keyPair1 = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );
      const keyPair2 = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint1 = await computeJwkThumbprint(keyPair1.publicKey);
      const thumbprint2 = await computeJwkThumbprint(keyPair2.publicKey);

      // THEN
      expect(thumbprint1).not.toBe(thumbprint2);
    });

    it('should compute thumbprint for RSA key with different modulus length', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      expect(thumbprint).toBeDefined();
      expect(typeof thumbprint).toBe('string');
      expect(thumbprint.length).toBeGreaterThan(0);
    });
  });

  describe('thumbprint format', () => {
    it('should produce base64url encoded output', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      expect(thumbprint).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should produce SHA-256 length output (43 characters)', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprint = await computeJwkThumbprint(keyPair.publicKey);

      // THEN
      expect(thumbprint.length).toBe(43);
    });
  });

  describe('error handling', () => {
    it('should throw error when JWK is missing kty parameter', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // Mock the crypto provider to return a JWK without kty
      const originalExportKey = crypto.subtle.exportKey.bind(crypto.subtle);
      crypto.subtle.exportKey = async (format: any, key: any) => {
        const jwk = await originalExportKey(format, key);
        delete (jwk as any).kty;
        return jwk;
      };

      // WHEN & THEN
      await expect(computeJwkThumbprint(keyPair.publicKey)).rejects.toThrow('JWK missing required "kty" parameter');

      // Restore original
      crypto.subtle.exportKey = originalExportKey;
    });

    it('should throw error for unsupported key type', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // Mock the crypto provider to return a JWK with unsupported kty
      const originalExportKey = crypto.subtle.exportKey.bind(crypto.subtle);
      crypto.subtle.exportKey = async (format: any, key: any) => {
        const jwk = await originalExportKey(format, key);
        (jwk as any).kty = 'oct';
        return jwk;
      };

      // WHEN & THEN
      await expect(computeJwkThumbprint(keyPair.publicKey)).rejects.toThrow(
        'Unsupported key type for JWK thumbprint: oct'
      );

      // Restore original
      crypto.subtle.exportKey = originalExportKey;
    });

    it('should throw error when RSA JWK is missing required parameters', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      // Mock the crypto provider to return a JWK without 'e' parameter
      const originalExportKey = crypto.subtle.exportKey.bind(crypto.subtle);
      crypto.subtle.exportKey = async (format: any, key: any) => {
        const jwk = await originalExportKey(format, key);
        delete (jwk as any).e;
        return jwk;
      };

      // WHEN & THEN
      await expect(computeJwkThumbprint(keyPair.publicKey)).rejects.toThrow(
        'RSA JWK missing required parameters (e, n)'
      );

      // Restore original
      crypto.subtle.exportKey = originalExportKey;
    });

    it('should throw error when EC JWK is missing required parameters', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // Mock the crypto provider to return a JWK without 'x' parameter
      const originalExportKey = crypto.subtle.exportKey.bind(crypto.subtle);
      crypto.subtle.exportKey = async (format: any, key: any) => {
        const jwk = await originalExportKey(format, key);
        delete (jwk as any).x;
        return jwk;
      };

      // WHEN & THEN
      await expect(computeJwkThumbprint(keyPair.publicKey)).rejects.toThrow(
        'EC JWK missing required parameters (crv, x, y)'
      );

      // Restore original
      crypto.subtle.exportKey = originalExportKey;
    });
  });

  describe('edge cases', () => {
    it('should handle EC keys with different curves', async () => {
      // GIVEN
      const p256KeyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const p384KeyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-384'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const p256Thumbprint = await computeJwkThumbprint(p256KeyPair.publicKey);
      const p384Thumbprint = await computeJwkThumbprint(p384KeyPair.publicKey);

      // THEN
      expect(p256Thumbprint).not.toBe(p384Thumbprint);
    });

    it('should be deterministic across multiple calls', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN
      const thumbprints = await Promise.all([
        computeJwkThumbprint(keyPair.publicKey),
        computeJwkThumbprint(keyPair.publicKey),
        computeJwkThumbprint(keyPair.publicKey),
        computeJwkThumbprint(keyPair.publicKey),
        computeJwkThumbprint(keyPair.publicKey)
      ]);

      // THEN
      const uniqueThumprints = new Set(thumbprints);
      expect(uniqueThumprints.size).toBe(1);
    });
  });
});
