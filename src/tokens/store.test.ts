import { beforeEach, describe, expect, it } from '@jest/globals';
import type { AccessToken } from '#types';
import { InMemoryTokenStore } from '#tokens/store';

describe('InMemoryTokenStore', () => {
  let store: InMemoryTokenStore;

  beforeEach(() => {
    store = new InMemoryTokenStore();
  });

  describe('put and get', () => {
    it('should store and retrieve token by jkt and scopes', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read', 'write']),
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'test-jkt'
      };

      // WHEN
      await store.put(accessToken);
      const retrieved = await store.get({ jkt: 'test-jkt', scopes: new Set(['read', 'write']) });

      // THEN
      expect(retrieved).not.toBeNull();
      expect(retrieved?.tokenValue).toBe('test-token');
      expect(retrieved?.jkt).toBe('test-jkt');
    });

    it('should store and retrieve token by scopes only (without jkt)', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read']),
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'test-jkt'
      };

      // WHEN
      await store.put(accessToken);
      const retrieved = await store.get({ scopes: new Set(['read']) });

      // THEN
      expect(retrieved).not.toBeNull();
      expect(retrieved?.tokenValue).toBe('test-token');
    });

    it('should return null for non-existent token', async () => {
      // GIVEN
      const filter = { jkt: 'non-existent', scopes: new Set(['read']) };

      // WHEN
      const result = await store.get(filter);

      // THEN
      expect(result).toBeNull();
    });

    it('should normalize scopes order in key', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read', 'write']),
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'test-jkt'
      };

      // WHEN
      await store.put(accessToken);
      const retrieved = await store.get({ jkt: 'test-jkt', scopes: new Set(['write', 'read']) });

      // THEN
      expect(retrieved).not.toBeNull();
      expect(retrieved?.tokenValue).toBe('test-token');
    });

    it('should differentiate tokens with different scopes', async () => {
      // GIVEN
      const token1: AccessToken = {
        tokenValue: 'token1',
        scopes: new Set(['read']),
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'jkt1'
      };
      const token2: AccessToken = {
        tokenValue: 'token2',
        scopes: new Set(['write']),
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'jkt2'
      };

      // WHEN
      await store.put(token1);
      await store.put(token2);
      const retrieved1 = await store.get({ jkt: 'jkt1', scopes: new Set(['read']) });
      const retrieved2 = await store.get({ jkt: 'jkt2', scopes: new Set(['write']) });

      // THEN
      expect(retrieved1?.tokenValue).toBe('token1');
      expect(retrieved2?.tokenValue).toBe('token2');
    });

    it('should handle empty scope set', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set<string>(),
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'test-jkt'
      };

      // WHEN
      await store.put(accessToken);
      const retrieved = await store.get({ jkt: 'test-jkt', scopes: new Set<string>() });

      // THEN
      expect(retrieved).not.toBeNull();
      expect(retrieved?.tokenValue).toBe('test-token');
    });

    it('should store token without jkt using scope-only key', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read']),
        expiresAt: Date.now() + 3600 * 1000
        // no jkt
      };

      // WHEN
      await store.put(accessToken);
      const retrieved = await store.get({ scopes: new Set(['read']) });

      // THEN
      expect(retrieved).not.toBeNull();
      expect(retrieved?.tokenValue).toBe('test-token');
    });
  });

  describe('token expiration', () => {
    it('should return null for expired token', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read']),
        expiresAt: Date.now() - 1000, // Already expired
        jkt: 'test-jkt'
      };

      // WHEN
      await store.put(accessToken);
      const retrieved = await store.get({ jkt: 'test-jkt', scopes: new Set(['read']) });

      // THEN
      expect(retrieved).toBeNull();
    });

    it('should return null for token expiring within threshold (60 seconds)', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read']),
        expiresAt: Date.now() + 30 * 1000, // Expires in 30 seconds (within 60s threshold)
        jkt: 'test-jkt'
      };

      // WHEN
      await store.put(accessToken);
      const retrieved = await store.get({ jkt: 'test-jkt', scopes: new Set(['read']) });

      // THEN
      expect(retrieved).toBeNull();
    });

    it('should return token if expiring after threshold', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read']),
        expiresAt: Date.now() + 120 * 1000, // Expires in 120 seconds (beyond 60s threshold)
        jkt: 'test-jkt'
      };

      // WHEN
      await store.put(accessToken);
      const retrieved = await store.get({ jkt: 'test-jkt', scopes: new Set(['read']) });

      // THEN
      expect(retrieved).not.toBeNull();
      expect(retrieved?.tokenValue).toBe('test-token');
    });

    it('should remove expired tokens when storing a new token', async () => {
      // GIVEN
      const expiredTime = Date.now() - 10000;
      (store as any).store.set('<none>|read', {
        tokenValue: 'expired-token-1',
        scopes: new Set(['read']),
        expiresAt: expiredTime
      });
      (store as any).store.set('<none>|write', {
        tokenValue: 'expired-token-2',
        scopes: new Set(['write']),
        expiresAt: expiredTime - 5000
      });

      // Add a valid (non-expired) token
      const validExpiry = Date.now() + 3600000;
      (store as any).store.set('<none>|admin', {
        tokenValue: 'valid-token',
        scopes: new Set(['admin']),
        expiresAt: validExpiry
      });

      expect((store as any).store.size).toBe(3);

      // WHEN - store a new token (should trigger cleanup)
      const newToken: AccessToken = {
        tokenValue: 'new-token',
        scopes: new Set(['other']),
        expiresAt: Date.now() + 3600 * 1000
      };
      await store.put(newToken);

      // THEN - expired tokens should be removed, valid token and new token should remain
      expect((store as any).store.size).toBe(2);
      expect((store as any).store.has('<none>|read')).toBe(false);
      expect((store as any).store.has('<none>|write')).toBe(false);
      expect((store as any).store.has('<none>|admin')).toBe(true);
      expect((store as any).store.has('<none>|other')).toBe(true);
    });
  });

  describe('key generation', () => {
    it('should create key with jkt and sorted scopes', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['write', 'read']), // Unsorted
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'my-jkt'
      };

      // WHEN
      await store.put(accessToken);

      // THEN
      expect((store as any).store.has('my-jkt|read write')).toBe(true);
    });

    it('should create key with <none> when jkt is undefined', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read']),
        expiresAt: Date.now() + 3600 * 1000
        // no jkt
      };

      // WHEN
      await store.put(accessToken);

      // THEN
      expect((store as any).store.has('<none>|read')).toBe(true);
    });

    it('should store with both scope-only and jkt+scope keys when jkt present', async () => {
      // GIVEN
      const accessToken: AccessToken = {
        tokenValue: 'test-token',
        scopes: new Set(['read']),
        expiresAt: Date.now() + 3600 * 1000,
        jkt: 'my-jkt'
      };

      // WHEN
      await store.put(accessToken);

      // THEN
      expect((store as any).store.has('<none>|read')).toBe(true);
      expect((store as any).store.has('my-jkt|read')).toBe(true);
    });
  });
});
