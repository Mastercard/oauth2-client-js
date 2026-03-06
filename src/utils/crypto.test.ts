import { describe, expect, it } from '@jest/globals';
import { getAlgorithmFromKey, validateKeyFAPI2 } from '#utils/crypto';

describe('getAlgorithmFromKey', () => {
  describe('should return ES256 for ECDSA P-256 keys', () => {
    it('should detect ES256 algorithm from ECDSA P-256 key', async () => {
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
      const algorithm = getAlgorithmFromKey(keyPair.privateKey);

      // THEN
      expect(algorithm).toBe('ES256');
    });
  });

  describe('should return PS256 for RSA-PSS SHA-256 keys', () => {
    it('should detect PS256 algorithm from RSA-PSS key', async () => {
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
      const algorithm = getAlgorithmFromKey(keyPair.privateKey);

      // THEN
      expect(algorithm).toBe('PS256');
    });
  });

  describe('should throw error for unsupported algorithms', () => {
    it('should throw error for unsupported ECDSA curve', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-384'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN & THEN
      expect(() => getAlgorithmFromKey(keyPair.privateKey)).toThrow('Unsupported ECDSA curve: P-384');
    });

    it('should throw error for unsupported RSA-PSS hash', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-512'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN & THEN
      expect(() => getAlgorithmFromKey(keyPair.privateKey)).toThrow('Unsupported RSA-PSS hash: SHA-512');
    });

    it('should throw error for unsupported key algorithm', async () => {
      // GIVEN
      const key = await crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      );

      // WHEN & THEN
      expect(() => getAlgorithmFromKey(key)).toThrow('Unsupported key algorithm: AES-GCM');
    });
  });
});

describe('validateKeyFAPI2', () => {
  describe('should validate RSA key length requirements', () => {
    it('should accept RSA key with 2048 bits', async () => {
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

      // WHEN & THEN - should not throw
      expect(() => validateKeyFAPI2(keyPair.privateKey, 'test key')).not.toThrow();
    });

    it('should accept RSA key with 4096 bits', async () => {
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

      // WHEN & THEN - should not throw
      expect(() => validateKeyFAPI2(keyPair.privateKey, 'test key')).not.toThrow();
    });

    it('should throw error for RSA key with less than 2048 bits', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 1024,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN & THEN
      expect(() => validateKeyFAPI2(keyPair.privateKey, 'test key')).toThrow(
        'FAPI 2.0 requires RSA keys to have a minimum length of 2048 bits for test key, but key length was: 1024 bits'
      );
    });
  });

  describe('should validate EC key length requirements', () => {
    it('should accept P-256 EC key (256 bits)', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN & THEN - should not throw
      expect(() => validateKeyFAPI2(keyPair.privateKey, 'test key')).not.toThrow();
    });

    it('should accept P-384 EC key (384 bits)', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-384'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN & THEN - should not throw
      expect(() => validateKeyFAPI2(keyPair.privateKey, 'test key')).not.toThrow();
    });

    it('should accept P-521 EC key (521 bits)', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-521'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN & THEN - should not throw
      expect(() => validateKeyFAPI2(keyPair.privateKey, 'test key')).not.toThrow();
    });
  });

  describe('should throw error for unsupported key algorithms', () => {
    it('should throw error for AES-GCM key', async () => {
      // GIVEN
      const key = await crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      );

      // WHEN & THEN
      expect(() => validateKeyFAPI2(key, 'test context')).toThrow(
        'Unsupported key algorithm for test context: AES-GCM'
      );
    });

    it('should throw error for HMAC key', async () => {
      // GIVEN
      const key = await crypto.subtle.generateKey(
        {
          name: 'HMAC',
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN & THEN
      expect(() => validateKeyFAPI2(key, 'test context')).toThrow('Unsupported key algorithm for test context: HMAC');
    });
  });

  describe('should handle different contexts in error messages', () => {
    it('should include context in RSA error message', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 1024,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      // WHEN & THEN
      expect(() => validateKeyFAPI2(keyPair.privateKey, 'DPoP private key')).toThrow(
        'FAPI 2.0 requires RSA keys to have a minimum length of 2048 bits for DPoP private key'
      );
    });

    it('should include context in unsupported algorithm error message', async () => {
      // GIVEN
      const key = await crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      );

      // WHEN & THEN
      expect(() => validateKeyFAPI2(key, 'client assertion')).toThrow(
        'Unsupported key algorithm for client assertion: AES-GCM'
      );
    });
  });
});
