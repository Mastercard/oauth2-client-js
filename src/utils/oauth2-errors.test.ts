import { describe, expect, it } from '@jest/globals';
import { isDPoPNonceError } from '#utils/oauth2-errors';

describe('isDPoPNonceError', () => {
  describe('should return false for non-error status codes', () => {
    it('should return false for status 200', () => {
      // GIVEN
      const status = 200;
      const headers = { 'www-authenticate': 'DPoP error="use_dpop_nonce"' };

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(false);
    });

    it('should return false for status 500', () => {
      // GIVEN
      const status = 500;
      const headers = { 'www-authenticate': 'DPoP error="use_dpop_nonce"' };

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(false);
    });

    it('should return false for status 403', () => {
      // GIVEN
      const status = 403;
      const headers = { 'www-authenticate': 'DPoP error="use_dpop_nonce"' };

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(false);
    });
  });

  describe('should detect use_dpop_nonce error from www-authenticate header', () => {
    it('should return true for status 400 with use_dpop_nonce in header', () => {
      // GIVEN
      const status = 400;
      const headers = { 'www-authenticate': 'DPoP error="use_dpop_nonce"' };

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(true);
    });

    it('should return true for status 401 with use_dpop_nonce in header', () => {
      // GIVEN
      const status = 401;
      const headers = { 'www-authenticate': 'DPoP error="use_dpop_nonce"' };

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(true);
    });

    it('should be case sensitive when checking use_dpop_nonce', () => {
      // GIVEN
      const status = 401;
      const headers = { 'www-authenticate': 'DPoP error="USE_DPOP_NONCE"' };

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(false);
    });

    it('should return true when use_dpop_nonce appears anywhere in header', () => {
      // GIVEN
      const status = 400;
      const headers = {
        'www-authenticate': 'Bearer realm="example", error="invalid_token", use_dpop_nonce'
      };

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(true);
    });
  });

  describe('should detect use_dpop_nonce error from response body', () => {
    it('should return true when body contains use_dpop_nonce error', () => {
      // GIVEN
      const status = 400;
      const headers = {};
      const body = JSON.stringify({ error: 'use_dpop_nonce' });

      // WHEN
      const result = isDPoPNonceError(status, headers, body);

      // THEN
      expect(result).toBe(true);
    });

    it('should return true for status 401 when body contains use_dpop_nonce', () => {
      // GIVEN
      const status = 401;
      const headers = {};
      const body = JSON.stringify({ error: 'use_dpop_nonce' });

      // WHEN
      const result = isDPoPNonceError(status, headers, body);

      // THEN
      expect(result).toBe(true);
    });

    it('should handle invalid JSON in body gracefully', () => {
      // GIVEN
      const status = 400;
      const headers = {};
      const body = 'not valid json';

      // WHEN
      const result = isDPoPNonceError(status, headers, body);

      // THEN
      expect(result).toBe(false);
    });

    it('should return false when body has different error', () => {
      // GIVEN
      const status = 400;
      const headers = {};
      const body = JSON.stringify({ error: 'invalid_token' });

      // WHEN
      const result = isDPoPNonceError(status, headers, body);

      // THEN
      expect(result).toBe(false);
    });

    it('should return false when body is undefined', () => {
      // GIVEN
      const status = 400;
      const headers = {};

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(false);
    });
  });

  describe('should return false when no use_dpop_nonce indicator present', () => {
    it('should return false with no www-authenticate header', () => {
      // GIVEN
      const status = 401;
      const headers = {};

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(false);
    });

    it('should return false when www-authenticate does not contain use_dpop_nonce', () => {
      // GIVEN
      const status = 401;
      const headers = { 'www-authenticate': 'Bearer error="invalid_token"' };

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(false);
    });

    it('should return false with empty headers', () => {
      // GIVEN
      const status = 400;
      const headers = {};

      // WHEN
      const result = isDPoPNonceError(status, headers);

      // THEN
      expect(result).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should handle empty body string', () => {
      // GIVEN
      const status = 400;
      const headers = {};
      const body = '';

      // WHEN
      const result = isDPoPNonceError(status, headers, body);

      // THEN
      expect(result).toBe(false);
    });

    it('should check body before header', () => {
      // GIVEN
      const status = 401;
      const headers = { 'www-authenticate': 'DPoP error="use_dpop_nonce"' };
      const body = JSON.stringify({ error: 'different_error' });

      // WHEN
      const result = isDPoPNonceError(status, headers, body);

      // THEN - body is checked first
      expect(result).toBe(true);
    });
  });
});
