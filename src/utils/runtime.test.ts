import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import type { CryptoProvider, RuntimeEnvironment as RuntimeEnvironmentType } from '#types';
import { RuntimeEnvironment } from '#utils/runtime';

describe('RuntimeEnvironment', () => {
  beforeEach(() => {
    RuntimeEnvironment.reset();
  });

  afterEach(() => {
    RuntimeEnvironment.reset();
  });

  describe('detect', () => {
    it('should detect runtime environment with crypto available', () => {
      // GIVEN - crypto is available in test environment

      // WHEN
      const runtime = RuntimeEnvironment.detect();

      // THEN
      expect(runtime).toBeDefined();
      expect(runtime.crypto).toBeDefined();
      expect(runtime.cryptoProvider).toBeDefined();
      expect(runtime.osName).toBeDefined();
      expect(runtime.osVersion).toBeDefined();
    });

    it('should return the same instance on subsequent calls', () => {
      // GIVEN
      const firstDetect = RuntimeEnvironment.detect();

      // WHEN
      const secondDetect = RuntimeEnvironment.detect();

      // THEN
      expect(secondDetect).toBe(firstDetect);
    });

    it('should have a functioning cryptoProvider', async () => {
      // GIVEN
      const runtime = RuntimeEnvironment.detect();

      // WHEN - test exportKey
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const jwk = await runtime.cryptoProvider.exportKey('jwk', keyPair.publicKey);

      // THEN
      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
    });

    it('should have working digest function', async () => {
      // GIVEN
      const runtime = RuntimeEnvironment.detect();
      const data = new TextEncoder().encode('test data');

      // WHEN
      const hash = await runtime.cryptoProvider.digest('SHA-256', data);

      // THEN
      expect(hash).toBeDefined();
      expect(hash).toBeInstanceOf(ArrayBuffer);
      expect(hash.byteLength).toBe(32); // SHA-256 produces 32 bytes
    });

    it('should have working sign function', async () => {
      // GIVEN
      const runtime = RuntimeEnvironment.detect();
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const data = new TextEncoder().encode('test data');

      // WHEN
      const signature = await runtime.cryptoProvider.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        keyPair.privateKey,
        data
      );

      // THEN
      expect(signature).toBeDefined();
      expect(signature).toBeInstanceOf(ArrayBuffer);
    });

    it('should have working getRandomValues function', () => {
      // GIVEN
      const runtime = RuntimeEnvironment.detect();
      const array = new Uint8Array(16);

      // WHEN
      const result = runtime.cryptoProvider.getRandomValues(array);

      // THEN
      expect(result).toBe(array);
      expect(result.some(byte => byte !== 0)).toBe(true);
    });
  });

  describe('configure', () => {
    it('should allow setting custom runtime environment', () => {
      // GIVEN
      const customCrypto = crypto;
      const cryptoProvider: CryptoProvider = {
        exportKey: async () => ({ kty: 'EC' }),
        digest: async () => new ArrayBuffer(32),
        sign: async () => new ArrayBuffer(64),
        getRandomValues: array => array
      };
      const customRuntime: RuntimeEnvironmentType = {
        crypto: customCrypto,
        cryptoProvider: cryptoProvider,
        osName: 'custom-os',
        osVersion: 'custom-version'
      };

      // WHEN
      RuntimeEnvironment.configure(customRuntime);
      const runtime = RuntimeEnvironment.detect();

      // THEN
      expect(runtime).toBe(customRuntime);
      expect(runtime.osName).toBe('custom-os');
      expect(runtime.osVersion).toBe('custom-version');
      expect(runtime.crypto).toBe(customCrypto);
      expect(runtime.cryptoProvider).toBe(cryptoProvider);
    });

    it('should override auto-detected runtime with custom one', () => {
      // GIVEN
      const autoDetected = RuntimeEnvironment.detect();
      const customRuntime: RuntimeEnvironmentType = {
        crypto: crypto,
        cryptoProvider: {
          exportKey: async () => ({ kty: 'RSA' }),
          digest: async () => new ArrayBuffer(32),
          sign: async () => new ArrayBuffer(256),
          getRandomValues: array => array
        },
        osName: 'override-os',
        osVersion: 'override-version'
      };

      // WHEN
      RuntimeEnvironment.configure(customRuntime);
      const runtime = RuntimeEnvironment.detect();

      // THEN
      expect(runtime).not.toBe(autoDetected);
      expect(runtime).toBe(customRuntime);
      expect(runtime.osName).toBe('override-os');
    });
  });

  describe('reset', () => {
    it('should reset to auto-detected runtime after configuration', () => {
      // GIVEN
      const customRuntime: RuntimeEnvironmentType = {
        crypto: crypto,
        cryptoProvider: {
          exportKey: async () => ({ kty: 'EC' }),
          digest: async () => new ArrayBuffer(32),
          sign: async () => new ArrayBuffer(64),
          getRandomValues: array => array
        },
        osName: 'custom-os',
        osVersion: 'custom-version'
      };
      RuntimeEnvironment.configure(customRuntime);
      const configuredRuntime = RuntimeEnvironment.detect();

      // WHEN
      RuntimeEnvironment.reset();
      const runtime = RuntimeEnvironment.detect();

      // THEN
      expect(runtime).not.toBe(configuredRuntime);
      expect(runtime.osName).not.toBe('custom-os');
    });

    it('should allow reconfiguration after reset', () => {
      // GIVEN
      const firstCustom: RuntimeEnvironmentType = {
        crypto: crypto,
        cryptoProvider: {
          exportKey: async () => ({ kty: 'EC' }),
          digest: async () => new ArrayBuffer(32),
          sign: async () => new ArrayBuffer(64),
          getRandomValues: array => array
        },
        osName: 'first-os',
        osVersion: 'first-version'
      };
      RuntimeEnvironment.configure(firstCustom);
      RuntimeEnvironment.reset();

      const secondCustom: RuntimeEnvironmentType = {
        crypto: crypto,
        cryptoProvider: {
          exportKey: async () => ({ kty: 'RSA' }),
          digest: async () => new ArrayBuffer(32),
          sign: async () => new ArrayBuffer(256),
          getRandomValues: array => array
        },
        osName: 'second-os',
        osVersion: 'second-version'
      };

      // WHEN
      RuntimeEnvironment.configure(secondCustom);
      const runtime = RuntimeEnvironment.detect();

      // THEN
      expect(runtime).toBe(secondCustom);
      expect(runtime.osName).toBe('second-os');
    });

    it('should clear cached instance', () => {
      // GIVEN
      const first = RuntimeEnvironment.detect();

      // WHEN
      RuntimeEnvironment.reset();
      const second = RuntimeEnvironment.detect();

      // THEN
      expect(second).not.toBe(first);
    });
  });

  describe('os detection', () => {
    it('should detect os information in Node.js environment', () => {
      // GIVEN
      const runtime = RuntimeEnvironment.detect();

      // WHEN & THEN
      // In Node.js environment, os module should be available
      expect(runtime.osName).toBeDefined();
      expect(runtime.osVersion).toBeDefined();
      expect(runtime.osName).not.toBe('unknown');
      expect(runtime.osVersion).not.toBe('unknown');
    });
  });
});
