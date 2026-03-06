import { beforeAll, describe, expect, it } from '@jest/globals';
import { WebCryptoProvider } from '#crypto/crypto-provider';

describe('WebCryptoProvider', () => {
  let provider: WebCryptoProvider;

  beforeAll(() => {
    provider = new WebCryptoProvider(crypto);
  });

  describe('exportKey', () => {
    it('should export EC key to JWK format', async () => {
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
      const jwk = await provider.exportKey('jwk', keyPair.publicKey);

      // THEN
      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
    });

    it('should export RSA key to JWK format', async () => {
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
      const jwk = await provider.exportKey('jwk', keyPair.publicKey);

      // THEN
      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('RSA');
      expect(jwk.n).toBeDefined();
      expect(jwk.e).toBeDefined();
    });

    it('should export private key to JWK format', async () => {
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
      const jwk = await provider.exportKey('jwk', keyPair.privateKey);

      // THEN
      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('EC');
      expect(jwk.d).toBeDefined();
    });
  });

  describe('digest', () => {
    it('should compute SHA-256 hash of data', async () => {
      // GIVEN
      const data = new TextEncoder().encode('test data');

      // WHEN
      const hash = await provider.digest('SHA-256', data);

      // THEN
      expect(hash).toBeDefined();
      expect(hash).toBeInstanceOf(ArrayBuffer);
      expect(hash.byteLength).toBe(32);
    });

    it('should produce consistent hashes for same input', async () => {
      // GIVEN
      const data = new TextEncoder().encode('test data');

      // WHEN
      const hash1 = await provider.digest('SHA-256', data);
      const hash2 = await provider.digest('SHA-256', data);

      // THEN
      expect(new Uint8Array(hash1)).toEqual(new Uint8Array(hash2));
    });

    it('should produce different hashes for different input', async () => {
      // GIVEN
      const data1 = new TextEncoder().encode('test data 1');
      const data2 = new TextEncoder().encode('test data 2');

      // WHEN
      const hash1 = await provider.digest('SHA-256', data1);
      const hash2 = await provider.digest('SHA-256', data2);

      // THEN
      expect(new Uint8Array(hash1)).not.toEqual(new Uint8Array(hash2));
    });

    it('should handle empty data', async () => {
      // GIVEN
      const data = new Uint8Array(0);

      // WHEN
      const hash = await provider.digest('SHA-256', data);

      // THEN
      expect(hash).toBeDefined();
      expect(hash.byteLength).toBe(32);
    });

    it('should handle large data', async () => {
      // GIVEN
      const data = new Uint8Array(100000).fill(42);

      // WHEN
      const hash = await provider.digest('SHA-256', data);

      // THEN
      expect(hash).toBeDefined();
      expect(hash.byteLength).toBe(32);
    });
  });

  describe('sign', () => {
    it('should sign data with ECDSA key', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const data = new TextEncoder().encode('test data');
      const algorithm = { name: 'ECDSA', hash: { name: 'SHA-256' } } as EcdsaParams;

      // WHEN
      const signature = await provider.sign(algorithm, keyPair.privateKey, data);

      // THEN
      expect(signature).toBeDefined();
      expect(signature).toBeInstanceOf(ArrayBuffer);
      expect(signature.byteLength).toBeGreaterThan(0);
    });

    it('should sign data with RSA-PSS key', async () => {
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
      const data = new TextEncoder().encode('test data');
      const algorithm = { name: 'RSA-PSS', saltLength: 32 } as RsaPssParams;

      // WHEN
      const signature = await provider.sign(algorithm, keyPair.privateKey, data);

      // THEN
      expect(signature).toBeDefined();
      expect(signature).toBeInstanceOf(ArrayBuffer);
      expect(signature.byteLength).toBe(256); // 2048 bits = 256 bytes
    });

    it('should produce valid signature that can be verified', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const data = new TextEncoder().encode('test data');
      const algorithm = { name: 'ECDSA', hash: { name: 'SHA-256' } } as EcdsaParams;

      // WHEN
      const signature = await provider.sign(algorithm, keyPair.privateKey, data);
      const isValid = await crypto.subtle.verify(algorithm, keyPair.publicKey, signature, data);

      // THEN
      expect(isValid).toBe(true);
    });

    it('should handle empty data', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const data = new Uint8Array(0);
      const algorithm = { name: 'ECDSA', hash: { name: 'SHA-256' } } as EcdsaParams;

      // WHEN
      const signature = await provider.sign(algorithm, keyPair.privateKey, data);

      // THEN
      expect(signature).toBeDefined();
      expect(signature.byteLength).toBeGreaterThan(0);
    });
  });

  describe('getRandomValues', () => {
    it('should fill array with random values', () => {
      // GIVEN
      const array = new Uint8Array(16);
      const originalArray = new Uint8Array(array);

      // WHEN
      const result = provider.getRandomValues(array);

      // THEN
      expect(result).toBe(array);
      expect(result).not.toEqual(originalArray);
      expect(result.some(byte => byte !== 0)).toBe(true);
    });

    it('should fill small array', () => {
      // GIVEN
      const array = new Uint8Array(1);

      // WHEN
      const result = provider.getRandomValues(array);

      // THEN
      expect(result).toBe(array);
    });

    it('should fill large array', () => {
      // GIVEN
      const array = new Uint8Array(1024);

      // WHEN
      const result = provider.getRandomValues(array);

      // THEN
      expect(result).toBe(array);
      expect(result.some(byte => byte !== 0)).toBe(true);
    });

    it('should produce different values on each call', () => {
      // GIVEN
      const array1 = new Uint8Array(16);
      const array2 = new Uint8Array(16);

      // WHEN
      provider.getRandomValues(array1);
      provider.getRandomValues(array2);

      // THEN
      expect(array1).not.toEqual(array2);
    });

    it('should generate from Uint16Array', () => {
      // GIVEN
      const array = new Uint16Array(8);

      // WHEN
      const result = provider.getRandomValues(array);

      // THEN
      expect(result).toBe(array);
      expect(result.some(value => value !== 0)).toBe(true);
    });

    it('should generate from Uint32Array', () => {
      // GIVEN
      const array = new Uint32Array(4);

      // WHEN
      const result = provider.getRandomValues(array);

      // THEN
      expect(result).toBe(array);
      expect(result.some(value => value !== 0)).toBe(true);
    });
  });
});
