import { describe, expect, it } from '@jest/globals';
import { StaticScopeResolver } from '#scope/static';

describe('StaticScopeResolver', () => {
  describe('constructor', () => {
    it('should create resolver with provided scopes', () => {
      // GIVEN
      const scopes = ['read', 'write'];

      // WHEN
      const resolver = new StaticScopeResolver(scopes);

      // THEN
      expect(resolver).toBeDefined();
    });

    it('should handle empty scope array', () => {
      // GIVEN
      const scopes: string[] = [];

      // WHEN
      const resolver = new StaticScopeResolver(scopes);

      // THEN
      expect(resolver).toBeDefined();
    });

    it('should handle single scope', () => {
      // GIVEN
      const scopes = ['read'];

      // WHEN
      const resolver = new StaticScopeResolver(scopes);

      // THEN
      expect(resolver).toBeDefined();
    });
  });

  describe('allScopes', () => {
    it('should return all configured scopes', async () => {
      // GIVEN
      const scopes = ['read', 'write', 'admin'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.allScopes();

      // THEN
      expect(result).toEqual(new Set(scopes));
    });

    it('should return empty set for empty scope array', async () => {
      // GIVEN
      const scopes: string[] = [];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.allScopes();

      // THEN
      expect(result).toEqual(new Set());
      expect(result.size).toBe(0);
    });

    it('should return new Set instance each time', async () => {
      // GIVEN
      const scopes = ['read', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result1 = await resolver.allScopes();
      const result2 = await resolver.allScopes();

      // THEN
      expect(result1).not.toBe(result2);
      expect(result1).toEqual(result2);
    });

    it('should handle duplicate scopes in input', async () => {
      // GIVEN
      const scopes = ['read', 'write', 'read'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.allScopes();

      // THEN
      expect(result.size).toBe(2);
      expect(result).toEqual(new Set(['read', 'write']));
    });

    it('should not allow modification of internal scopes', async () => {
      // GIVEN
      const scopes = ['read', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.allScopes();
      result.add('admin');
      const result2 = await resolver.allScopes();

      // THEN
      expect(result2).toEqual(new Set(['read', 'write']));
      expect(result2).not.toContain('admin');
    });
  });

  describe('resolveScopes', () => {
    it('should return all configured scopes regardless of HTTP method', async () => {
      // GIVEN
      const scopes = ['read', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.resolveScopes('GET', 'https://example.com/api');

      // THEN
      expect(result).toEqual(new Set(scopes));
    });

    it('should return all configured scopes regardless of URL', async () => {
      // GIVEN
      const scopes = ['read', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.resolveScopes('POST', 'https://different.com/path');

      // THEN
      expect(result).toEqual(new Set(scopes));
    });

    it('should return same scopes for different HTTP methods', async () => {
      // GIVEN
      const scopes = ['read', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const getResult = await resolver.resolveScopes('GET', 'https://example.com');
      const postResult = await resolver.resolveScopes('POST', 'https://example.com');
      const deleteResult = await resolver.resolveScopes('DELETE', 'https://example.com');

      // THEN
      expect(getResult).toEqual(postResult);
      expect(postResult).toEqual(deleteResult);
    });

    it('should return same scopes for different URLs', async () => {
      // GIVEN
      const scopes = ['read', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result1 = await resolver.resolveScopes('GET', 'https://api1.example.com/resource');
      const result2 = await resolver.resolveScopes('GET', 'https://api2.example.com/different');

      // THEN
      expect(result1).toEqual(result2);
    });

    it('should return empty set when no scopes configured', async () => {
      // GIVEN
      const scopes: string[] = [];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.resolveScopes('GET', 'https://example.com');

      // THEN
      expect(result).toEqual(new Set());
      expect(result.size).toBe(0);
    });

    it('should return new Set instance each time', async () => {
      // GIVEN
      const scopes = ['read'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result1 = await resolver.resolveScopes('GET', 'https://example.com');
      const result2 = await resolver.resolveScopes('GET', 'https://example.com');

      // THEN
      expect(result1).not.toBe(result2);
      expect(result1).toEqual(result2);
    });

    it('should handle case sensitivity in HTTP methods', async () => {
      // GIVEN
      const scopes = ['read', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const getLower = await resolver.resolveScopes('get', 'https://example.com');
      const getUpper = await resolver.resolveScopes('GET', 'https://example.com');
      const getMixed = await resolver.resolveScopes('Get', 'https://example.com');

      // THEN
      expect(getLower).toEqual(getUpper);
      expect(getUpper).toEqual(getMixed);
    });

    it('should not modify internal scopes when modifying result', async () => {
      // GIVEN
      const scopes = ['read', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result1 = await resolver.resolveScopes('GET', 'https://example.com');
      result1.add('admin');
      const result2 = await resolver.resolveScopes('GET', 'https://example.com');

      // THEN
      expect(result2).toEqual(new Set(['read', 'write']));
      expect(result2).not.toContain('admin');
    });
  });

  describe('consistency', () => {
    it('should return consistent results between allScopes and resolveScopes', async () => {
      // GIVEN
      const scopes = ['read', 'write', 'admin'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const allScopesResult = await resolver.allScopes();
      const resolveScopesResult = await resolver.resolveScopes('GET', 'https://example.com');

      // THEN
      expect(resolveScopesResult).toEqual(allScopesResult);
    });

    it('should maintain scope order deterministically', async () => {
      // GIVEN
      const scopes = ['zebra', 'apple', 'banana'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result1 = await resolver.resolveScopes('GET', 'https://example.com');
      const result2 = await resolver.resolveScopes('POST', 'https://example.com');
      const result3 = await resolver.allScopes();

      // THEN - Set iteration order is insertion order
      expect([...result1]).toEqual([...result2]);
      expect([...result2]).toEqual([...result3]);
    });
  });

  describe('edge cases', () => {
    it('should handle very long scope names', async () => {
      // GIVEN
      const longScope = 'a'.repeat(1000);
      const scopes = ['read', longScope];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.resolveScopes('GET', 'https://example.com');

      // THEN
      expect(result).toContain(longScope);
      expect(result.size).toBe(2);
    });

    it('should handle special characters in scope names', async () => {
      // GIVEN
      const scopes = ['read:user', 'write:admin', 'scope-with-dash'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.resolveScopes('GET', 'https://example.com');

      // THEN
      expect(result).toEqual(new Set(scopes));
    });

    it('should handle empty string scope', async () => {
      // GIVEN
      const scopes = ['read', '', 'write'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.resolveScopes('GET', 'https://example.com');

      // THEN
      expect(result.size).toBe(3);
      expect(result).toContain('');
    });

    it('should handle whitespace in scope names', async () => {
      // GIVEN
      const scopes = ['read', 'write admin', 'scope with spaces'];
      const resolver = new StaticScopeResolver(scopes);

      // WHEN
      const result = await resolver.resolveScopes('GET', 'https://example.com');

      // THEN
      expect(result).toEqual(new Set(scopes));
    });
  });
});
