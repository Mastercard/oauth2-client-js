import { beforeAll, describe, expect, it } from '@jest/globals';
import { JWTSigner, JWTUtils } from '#crypto/jwt';
import type { JWTPayload } from '#types';

describe('JWTUtils', () => {
  describe('generateJti', () => {
    it('should generate a random JTI', () => {
      // GIVEN & WHEN
      const jti = JWTUtils.generateJti();

      // THEN
      expect(jti).toBeDefined();
      expect(typeof jti).toBe('string');
      expect(jti.length).toBeGreaterThan(0);
    });

    it('should generate base64url encoded JTI', () => {
      // GIVEN & WHEN
      const jti = JWTUtils.generateJti();

      // THEN
      expect(jti).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(jti).not.toContain('=');
      expect(jti).not.toContain('+');
      expect(jti).not.toContain('/');
    });

    it('should generate different JTIs on each call', () => {
      // GIVEN & WHEN
      const jti1 = JWTUtils.generateJti();
      const jti2 = JWTUtils.generateJti();
      const jti3 = JWTUtils.generateJti();

      // THEN
      expect(jti1).not.toBe(jti2);
      expect(jti2).not.toBe(jti3);
      expect(jti1).not.toBe(jti3);
    });

    it('should generate JTI with expected length (16 characters for 96 bits)', () => {
      // GIVEN & WHEN
      const jti = JWTUtils.generateJti();

      // THEN
      expect(jti.length).toBe(16);
    });

    it('should generate unique JTIs for multiple calls', () => {
      // GIVEN
      const numberOfCalls = 100;
      const jtis = new Set<string>();

      // WHEN
      for (let i = 0; i < numberOfCalls; i++) {
        jtis.add(JWTUtils.generateJti());
      }

      // THEN
      expect(jtis.size).toBe(numberOfCalls);
    });
  });
});

describe('JWTSigner', () => {
  let signer: JWTSigner;

  beforeAll(() => {
    signer = new JWTSigner();
  });

  describe('signJWT with ECDSA keys', () => {
    it('should sign JWT with ES256 algorithm', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = {
        iss: 'test-issuer',
        sub: 'test-subject',
        aud: 'test-audience',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);

      // THEN
      expect(jwt).toBeDefined();
      expect(typeof jwt).toBe('string');
      const parts = jwt.split('.');
      expect(parts.length).toBe(3);
    });

    it('should include correct header for ES256', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = { iss: 'test' };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);
      const headerPart = jwt.split('.')[0];
      const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf-8'));

      // THEN
      expect(header.alg).toBe('ES256');
      expect(header.typ).toBe('JWT');
    });

    it('should include custom header parameters', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = { iss: 'test' };
      const customHeader = { kid: 'test-key-id' };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey, customHeader);
      const headerPart = jwt.split('.')[0];
      const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf-8'));

      // THEN
      expect(header.kid).toBe('test-key-id');
      expect(header.alg).toBe('ES256');
      expect(header.typ).toBe('JWT');
    });

    it('should encode payload correctly', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = {
        iss: 'test-issuer',
        sub: 'test-subject',
        aud: 'test-audience'
      };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);
      const payloadPart = jwt.split('.')[1];
      const decodedPayload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(decodedPayload.iss).toBe('test-issuer');
      expect(decodedPayload.sub).toBe('test-subject');
      expect(decodedPayload.aud).toBe('test-audience');
    });
  });

  describe('signJWT with RSA-PSS keys', () => {
    it('should sign JWT with PS256 algorithm', async () => {
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
      const payload: JWTPayload = {
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600
      };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);

      // THEN
      expect(jwt).toBeDefined();
      const parts = jwt.split('.');
      expect(parts.length).toBe(3);
    });

    it('should include correct header for PS256', async () => {
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
      const payload: JWTPayload = { iss: 'test' };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);
      const headerPart = jwt.split('.')[0];
      const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf-8'));

      // THEN
      expect(header.alg).toBe('PS256');
      expect(header.typ).toBe('JWT');
    });
  });

  describe('JWT structure', () => {
    it('should produce base64url encoded parts', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = { iss: 'test' };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);
      const parts = jwt.split('.');

      // THEN
      parts.forEach(part => {
        expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(part).not.toContain('=');
        expect(part).not.toContain('+');
        expect(part).not.toContain('/');
      });
    });

    it('should have three parts separated by dots', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = { iss: 'test' };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);

      // THEN
      expect(jwt.split('.').length).toBe(3);
    });
  });

  describe('payload handling', () => {
    it('should handle empty payload', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = {};

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);

      // THEN
      expect(jwt).toBeDefined();
      expect(jwt.split('.').length).toBe(3);
    });

    it('should handle payload with all standard claims', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const now = Math.floor(Date.now() / 1000);
      const payload: JWTPayload = {
        iss: 'issuer',
        sub: 'subject',
        aud: 'audience',
        exp: now + 3600,
        nbf: now,
        iat: now,
        jti: 'unique-id'
      };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);
      const payloadPart = jwt.split('.')[1];
      const decodedPayload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(decodedPayload).toEqual(payload);
    });

    it('should handle payload with array audience', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = {
        aud: ['audience1', 'audience2']
      };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey);
      const payloadPart = jwt.split('.')[1];
      const decodedPayload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf-8'));

      // THEN
      expect(decodedPayload.aud).toEqual(['audience1', 'audience2']);
    });
  });

  describe('header customization', () => {
    it('should allow custom typ header', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload: JWTPayload = { iss: 'test' };
      const customHeader = { typ: 'dpop+jwt' };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey, customHeader);
      const headerPart = jwt.split('.')[0];
      const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf-8'));

      // THEN
      expect(header.typ).toBe('dpop+jwt');
    });

    it('should allow adding jwk to header', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const payload: JWTPayload = { iss: 'test' };
      const customHeader = { jwk };

      // WHEN
      const jwt = await signer.signJWT(payload, keyPair.privateKey, customHeader);
      const headerPart = jwt.split('.')[0];
      const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf-8'));

      // THEN
      expect(header.jwk).toBeDefined();
      expect(header.jwk.kty).toBe('EC');
    });
  });

  describe('signature consistency', () => {
    it('should produce different signatures for same payload with different keys', async () => {
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
      const payload: JWTPayload = { iss: 'test' };

      // WHEN
      const jwt1 = await signer.signJWT(payload, keyPair1.privateKey);
      const jwt2 = await signer.signJWT(payload, keyPair2.privateKey);

      // THEN
      expect(jwt1).not.toBe(jwt2);
    });

    it('should produce different signatures for different payloads', async () => {
      // GIVEN
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
      );
      const payload1: JWTPayload = { iss: 'test1' };
      const payload2: JWTPayload = { iss: 'test2' };

      // WHEN
      const jwt1 = await signer.signJWT(payload1, keyPair.privateKey);
      const jwt2 = await signer.signJWT(payload2, keyPair.privateKey);

      // THEN
      expect(jwt1).not.toBe(jwt2);
    });
  });
});
