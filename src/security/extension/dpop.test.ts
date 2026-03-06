import { beforeEach, describe, expect, it } from '@jest/globals';
import { DPoPProofGenerator, StaticDPoPKeyProvider } from '#security/extension/dpop';
import type { KeyPair } from '#types';

describe('DPoPProofGenerator', () => {
  let keyPair: KeyPair;
  let dpopKeyProvider: StaticDPoPKeyProvider;

  beforeEach(async () => {
    const keys = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );
    keyPair = { privateKey: keys.privateKey, publicKey: keys.publicKey };
    dpopKeyProvider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);
  });

  describe('generateProof', () => {
    it('should generate DPoP proof JWT', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const method = 'GET';
      const url = 'https://api.example.com/resource';
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();

      // WHEN
      const proof = await generator.generateProof(method, url, keyId);

      // THEN
      expect(proof).toBeDefined();
      expect(typeof proof).toBe('string');
      const parts = proof.split('.');
      expect(parts.length).toBe(3);
    });

    it('should include correct headers in DPoP proof', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();

      // WHEN
      const proof = await generator.generateProof('POST', 'https://api.example.com', keyId);
      const headerPart = proof.split('.')[0];
      const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf-8'));

      // THEN
      expect(header.typ).toBe('dpop+jwt');
      expect(header.alg).toBe('ES256');
      expect(header.jwk).toBeDefined();
      expect(header.jwk.kty).toBe('EC');
      expect(header.jwk.crv).toBeDefined();
      expect(header.jwk.x).toBeDefined();
      expect(header.jwk.y).toBeDefined();
      expect(header.kid).toBe(keyId);
    });

    it('should include required claims in DPoP proof', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const method = 'GET';
      const url = 'https://api.example.com/resource';

      // WHEN
      const proof = await generator.generateProof(method, url, keyId);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.jti).toBeDefined();
      expect(payload.htm).toBe('GET');
      expect(payload.htu).toBe('https://api.example.com/resource');
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
      expect(payload.exp).toBeGreaterThan(payload.iat);
    });

    it('should canonicalize URL for htu claim', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const url = 'https://api.example.com:443/resource?param=value#fragment';

      // WHEN
      const proof = await generator.generateProof('GET', url, keyId);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.htu).toBe('https://api.example.com/resource');
    });

    it('should include port in htu when non-standard', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const url = 'https://api.example.com:8080/resource';

      // WHEN
      const proof = await generator.generateProof('GET', url, keyId);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.htu).toBe('https://api.example.com:8080/resource');
    });

    it('should uppercase HTTP method in htm claim', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();

      // WHEN
      const proof = await generator.generateProof('get', 'https://api.example.com', keyId);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.htm).toBe('GET');
    });

    it('should include ath claim when access token provided', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const accessToken = 'test-access-token';

      // WHEN
      const proof = await generator.generateProof('GET', 'https://api.example.com', keyId, undefined, accessToken);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.ath).toBeDefined();
      expect(typeof payload.ath).toBe('string');
      expect(payload.ath.length).toBe(43); // SHA-256 hash in base64url
    });

    it('should not include ath claim when no access token', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();

      // WHEN
      const proof = await generator.generateProof('GET', 'https://api.example.com', keyId);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.ath).toBeUndefined();
    });

    it('should include nonce claim when provided', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const nonce = 'test-nonce-value';

      // WHEN
      const proof = await generator.generateProof('GET', 'https://api.example.com', keyId, nonce);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.nonce).toBe(nonce);
    });

    it('should use cached nonce when updateNonce was called', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const url = 'https://api.example.com/resource';
      const cachedNonce = 'cached-nonce-value';
      generator.updateNonce(cachedNonce);

      // WHEN
      const proof = await generator.generateProof('GET', url, keyId);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.nonce).toBe(cachedNonce);
    });

    it('should apply clock skew tolerance to exp claim', async () => {
      // GIVEN
      const clockSkewTolerance = 30;
      const generator = new DPoPProofGenerator(dpopKeyProvider, clockSkewTolerance);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const beforeTime = Math.floor(Date.now() / 1000);

      // WHEN
      const proof = await generator.generateProof('GET', 'https://api.example.com', keyId);
      const afterTime = Math.floor(Date.now() / 1000);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.exp).toBeGreaterThanOrEqual(beforeTime + 90 + clockSkewTolerance);
      expect(payload.exp).toBeLessThanOrEqual(afterTime + 90 + clockSkewTolerance);
    });

    it('should handle different HTTP methods', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

      // WHEN & THEN
      for (const method of methods) {
        const proof = await generator.generateProof(method, 'https://api.example.com', keyId);
        const payloadPart = proof.split('.')[1];
        const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));
        expect(payload.htm).toBe(method);
      }
    });

    it('should throw error for invalid URL', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const invalidUrl = 'not-a-valid-url';

      // WHEN & THEN
      await expect(generator.generateProof('GET', invalidUrl, keyId)).rejects.toThrow(
        `Invalid URL for DPoP htu claim: ${invalidUrl}`
      );
    });
  });

  describe('updateNonce', () => {
    it('should update the stored nonce', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();
      const nonce = 'new-nonce-value';

      // WHEN
      generator.updateNonce(nonce);
      const proof = await generator.generateProof('GET', 'https://api.example.com', keyId);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.nonce).toBe(nonce);
    });

    it('should overwrite previously stored nonce', async () => {
      // GIVEN
      const generator = new DPoPProofGenerator(dpopKeyProvider);
      const keyId = await dpopKeyProvider.getCurrentKey().getKeyId();

      // WHEN
      generator.updateNonce('first-nonce');
      generator.updateNonce('second-nonce');
      const proof = await generator.generateProof('GET', 'https://api.example.com', keyId);
      const payloadPart = proof.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(payload.nonce).toBe('second-nonce');
    });
  });
});

describe('StaticDPoPKeyProvider', () => {
  let keyPair: KeyPair;

  beforeEach(async () => {
    const keys = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );
    keyPair = { privateKey: keys.privateKey, publicKey: keys.publicKey };
  });

  describe('constructor', () => {
    it('should create provider with key pair', () => {
      // GIVEN & WHEN
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // THEN
      expect(provider).toBeDefined();
    });
  });

  describe('getCurrentKey', () => {
    it('should return DPoP key', () => {
      // GIVEN
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // WHEN
      const dpopKey = provider.getCurrentKey();

      // THEN
      expect(dpopKey).toBeDefined();
      expect(dpopKey.getKeyPair).toBeDefined();
      expect(dpopKey.getKeyId).toBeDefined();
    });

    it('should return key pair from DPoP key', () => {
      // GIVEN
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // WHEN
      const dpopKey = provider.getCurrentKey();
      const returnedKeyPair = dpopKey.getKeyPair();

      // THEN
      expect(returnedKeyPair.privateKey).toBe(keyPair.privateKey);
      expect(returnedKeyPair.publicKey).toBe(keyPair.publicKey);
    });

    it('should return consistent key ID', async () => {
      // GIVEN
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);
      const dpopKey = provider.getCurrentKey();

      // WHEN
      const keyId1 = await dpopKey.getKeyId();
      const keyId2 = await dpopKey.getKeyId();

      // THEN
      expect(keyId1).toBe(keyId2);
      expect(typeof keyId1).toBe('string');
      expect(keyId1.length).toBe(43); // JWK thumbprint length
    });

    it('should return same DPoP key on multiple calls', () => {
      // GIVEN
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // WHEN
      const dpopKey1 = provider.getCurrentKey();
      const dpopKey2 = provider.getCurrentKey();

      // THEN
      expect(dpopKey1).toBe(dpopKey2);
    });
  });

  describe('getKey', () => {
    it('should return same key regardless of kid parameter', () => {
      // GIVEN
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);
      const currentKey = provider.getCurrentKey();

      // WHEN
      const key1 = provider.getKey('any-kid');
      const key2 = provider.getKey('different-kid');

      // THEN
      expect(key1).toBe(currentKey);
      expect(key2).toBe(currentKey);
    });

    it('should return key with correct key pair', () => {
      // GIVEN
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // WHEN
      const dpopKey = provider.getKey('test-kid');
      const returnedKeyPair = dpopKey.getKeyPair();

      // THEN
      expect(returnedKeyPair.privateKey).toBe(keyPair.privateKey);
      expect(returnedKeyPair.publicKey).toBe(keyPair.publicKey);
    });
  });

  describe('key ID generation', () => {
    it('should generate unique key IDs for different keys', async () => {
      // GIVEN
      const keys1 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const keys2 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

      const provider1 = new StaticDPoPKeyProvider(keys1.privateKey, keys1.publicKey);
      const provider2 = new StaticDPoPKeyProvider(keys2.privateKey, keys2.publicKey);

      // WHEN
      const keyId1 = await provider1.getCurrentKey().getKeyId();
      const keyId2 = await provider2.getCurrentKey().getKeyId();

      // THEN
      expect(keyId1).not.toBe(keyId2);
    });

    it('should generate base64url encoded key ID', async () => {
      // GIVEN
      const provider = new StaticDPoPKeyProvider(keyPair.privateKey, keyPair.publicKey);

      // WHEN
      const keyId = await provider.getCurrentKey().getKeyId();

      // THEN
      expect(keyId).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(keyId).not.toContain('=');
      expect(keyId).not.toContain('+');
      expect(keyId).not.toContain('/');
    });
  });

  describe('with RSA keys', () => {
    it('should work with RSA-PSS keys', async () => {
      // GIVEN
      const rsaKeys = await crypto.subtle.generateKey(
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
      const provider = new StaticDPoPKeyProvider(rsaKeys.privateKey, rsaKeys.publicKey);
      const dpopKey = provider.getCurrentKey();
      const keyId = await dpopKey.getKeyId();

      // THEN
      expect(provider).toBeDefined();
      expect(keyId).toBeDefined();
      expect(typeof keyId).toBe('string');
    });
  });
});
