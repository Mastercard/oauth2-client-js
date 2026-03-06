import { describe, expect, it } from '@jest/globals';
import { buildFullUrl, isAbsoluteHttpsURL } from '#http/url';

describe('isAbsoluteURL', () => {
  describe('should return true for absolute URLs', () => {
    it('should detect HTTPS URLs', () => {
      // GIVEN
      const url = 'https://example.com/path';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(true);
    });

    it('should detect HTTPS URLs with uppercase scheme', () => {
      // GIVEN
      const url = 'HTTPS://example.com/path';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(true);
    });

    it('should return false for HTTP URLs', () => {
      // GIVEN
      const url = 'http://example.com/path';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should return false for FTP URLs', () => {
      // GIVEN
      const url = 'ftp://files.example.com/file.txt';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should handle URLs with ports', () => {
      // GIVEN
      const url = 'https://example.com:8080/path';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(true);
    });

    it('should handle URLs with query parameters', () => {
      // GIVEN
      const url = 'https://example.com/path?param=value';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(true);
    });

    it('should handle URLs with fragments', () => {
      // GIVEN
      const url = 'https://example.com/path#section';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(true);
    });
  });

  describe('should return false for relative URLs', () => {
    it('should detect relative path', () => {
      // GIVEN
      const url = '/path/to/resource';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should detect relative path without leading slash', () => {
      // GIVEN
      const url = 'path/to/resource';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should detect current directory reference', () => {
      // GIVEN
      const url = './path';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should detect parent directory reference', () => {
      // GIVEN
      const url = '../path';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should detect just a filename', () => {
      // GIVEN
      const url = 'file.txt';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should detect query string only', () => {
      // GIVEN
      const url = '?param=value';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should detect fragment only', () => {
      // GIVEN
      const url = '#section';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });

    it('should handle empty string', () => {
      // GIVEN
      const url = '';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should handle URL with username and password', () => {
      // GIVEN
      const url = 'https://user:pass@example.com/path';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(true);
    });

    it('should handle single slash after protocol', () => {
      // GIVEN
      const url = 'file:/path/to/file';

      // WHEN
      const result = isAbsoluteHttpsURL(url);

      // THEN
      expect(result).toBe(false);
    });
  });
});

describe('buildFullUrl', () => {
  describe('should build full URL from base and path', () => {
    it('should combine base and path with slash', () => {
      // GIVEN
      const base = 'https://example.com';
      const path = '/api/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/api/resource');
    });

    it('should handle base with trailing slash', () => {
      // GIVEN
      const base = 'https://example.com/';
      const path = '/api/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/api/resource');
    });

    it('should handle path without leading slash', () => {
      // GIVEN
      const base = 'https://example.com';
      const path = 'api/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/api/resource');
    });

    it('should handle both base trailing slash and path leading slash', () => {
      // GIVEN
      const base = 'https://example.com/';
      const path = '/api/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/api/resource');
    });

    it('should handle base with path', () => {
      // GIVEN
      const base = 'https://example.com/v1';
      const path = '/api/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/v1/api/resource');
    });

    it('should handle complex paths', () => {
      // GIVEN
      const base = 'https://api.example.com/v2';
      const path = '/users/123/profile';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://api.example.com/v2/users/123/profile');
    });

    it('should handle path with query parameters', () => {
      // GIVEN
      const base = 'https://example.com';
      const path = '/api?param=value';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/api?param=value');
    });

    it('should handle path with fragment', () => {
      // GIVEN
      const base = 'https://example.com';
      const path = '/page#section';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/page#section');
    });
  });

  describe('should return path when path is absolute', () => {
    it('should return absolute HTTPS path as-is', () => {
      // GIVEN
      const base = 'https://example.com';
      const path = 'https://other.com/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://other.com/resource');
    });

    it('should ignore base when path is absolute', () => {
      // GIVEN
      const base = 'https://example.com/v1';
      const path = 'https://api.other.com/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://api.other.com/resource');
    });
  });

  describe('should handle undefined or empty base', () => {
    it('should return absolute path when base is undefined', () => {
      // GIVEN
      const base = undefined;
      const path = 'https://example.com/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/resource');
    });

    it('should return relative path unchanged when base is undefined', () => {
      // GIVEN
      const base = undefined;
      const path = '/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('/resource');
    });

    it('should return relative path unchanged when base is empty string', () => {
      // GIVEN
      const base = '';
      const path = '/api/resource';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('/api/resource');
    });

    it('should return path without leading slash unchanged when base is undefined', () => {
      // GIVEN
      const base = undefined;
      const path = 'pets';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('pets');
    });
  });

  describe('edge cases', () => {
    it('should handle base with port', () => {
      // GIVEN
      const base = 'https://example.com:8080';
      const path = '/api';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com:8080/api');
    });

    it('should handle base with authentication', () => {
      // GIVEN
      const base = 'https://user:pass@example.com';
      const path = '/api';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://user:pass@example.com/api');
    });

    it('should handle empty path', () => {
      // GIVEN
      const base = 'https://example.com';
      const path = '';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/');
    });

    it('should handle root path', () => {
      // GIVEN
      const base = 'https://example.com';
      const path = '/';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/');
    });

    it('should handle path with only query string', () => {
      // GIVEN
      const base = 'https://example.com';
      const path = '?param=value';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://example.com/?param=value');
    });

    it('should handle IPv4 address in base', () => {
      // GIVEN
      const base = 'https://192.168.1.1:8080';
      const path = '/api';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('https://192.168.1.1:8080/api');
    });

    it('should handle localhost in base', () => {
      // GIVEN
      const base = 'http://localhost:3000';
      const path = '/api/test';

      // WHEN
      const result = buildFullUrl(base, path);

      // THEN
      expect(result).toBe('http://localhost:3000/api/test');
    });
  });
});
