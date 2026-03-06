import { describe, expect, it } from '@jest/globals';
import { base64urlEncode } from '#crypto/base64';

describe('base64urlEncode', () => {
  describe('should encode string input', () => {
    it('should encode simple ASCII string', () => {
      // GIVEN
      const input = 'hello';

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('aGVsbG8');
    });

    it('should encode UTF-8 string', () => {
      // GIVEN
      const input = 'Hello, 世界';

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('SGVsbG8sIOS4lueVjA');
    });

    it('should encode empty string', () => {
      // GIVEN
      const input = '';

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('');
    });

    it('should encode special characters', () => {
      // GIVEN
      const input = '!@#$%^&*()';

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('IUAjJCVeJiooKQ');
    });
  });

  describe('should encode ArrayBuffer input', () => {
    it('should encode ArrayBuffer', () => {
      // GIVEN
      const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const input = data.buffer;

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('SGVsbG8');
    });

    it('should encode empty ArrayBuffer', () => {
      // GIVEN
      const input = new ArrayBuffer(0);

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('');
    });

    it('should encode ArrayBuffer with binary data', () => {
      // GIVEN
      const data = new Uint8Array([0, 1, 2, 3, 4, 5]);
      const input = data.buffer;

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('AAECAwQF');
    });
  });

  describe('should encode Uint8Array input', () => {
    it('should encode Uint8Array', () => {
      // GIVEN
      const input = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('SGVsbG8');
    });

    it('should encode empty Uint8Array', () => {
      // GIVEN
      const input = new Uint8Array(0);

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('');
    });

    it('should encode Uint8Array with binary data', () => {
      // GIVEN
      const input = new Uint8Array([255, 254, 253, 252]);

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('__79_A');
    });
  });

  describe('should apply base64url transformations', () => {
    it('should replace + with -', () => {
      // GIVEN
      const input = new Uint8Array([251, 239]); // produces + in base64

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).not.toContain('+');
      expect(result).toContain('-');
      expect(result).toBe('--8');
    });

    it('should replace / with _', () => {
      // GIVEN
      const input = new Uint8Array([255, 239]); // produces / in base64

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).not.toContain('/');
      expect(result).toContain('_');
      expect(result).toBe('_-8');
    });

    it('should remove padding =', () => {
      // GIVEN
      const input = 'a'; // single character produces padding

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).not.toContain('=');
      expect(result).toBe('YQ');
    });

    it('should remove multiple padding characters', () => {
      // GIVEN
      const input = 'ab'; // produces == padding

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).not.toContain('=');
      expect(result).toBe('YWI');
    });
  });

  describe('should produce consistent results', () => {
    it('should produce same output for same input', () => {
      // GIVEN
      const input = 'test data';

      // WHEN
      const result1 = base64urlEncode(input);
      const result2 = base64urlEncode(input);

      // THEN
      expect(result1).toBe(result2);
    });

    it('should handle the same data as string and Uint8Array', () => {
      // GIVEN
      const stringInput = 'Hello';
      const arrayInput = new Uint8Array([72, 101, 108, 108, 111]); // "Hello" in UTF-8

      // WHEN
      const stringResult = base64urlEncode(stringInput);
      const arrayResult = base64urlEncode(arrayInput);

      // THEN
      expect(stringResult).toBe(arrayResult);
    });

    it('should handle the same data as ArrayBuffer and Uint8Array', () => {
      // GIVEN
      const data = new Uint8Array([1, 2, 3, 4]);
      const arrayBufferInput = data.buffer;
      const uint8ArrayInput = new Uint8Array([1, 2, 3, 4]);

      // WHEN
      const arrayBufferResult = base64urlEncode(arrayBufferInput);
      const uint8ArrayResult = base64urlEncode(uint8ArrayInput);

      // THEN
      expect(arrayBufferResult).toBe(uint8ArrayResult);
    });
  });

  describe('edge cases', () => {
    it('should handle large data', () => {
      // GIVEN
      const input = new Uint8Array(10000).fill(42);

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBeDefined();
      expect(result.length).toBeGreaterThan(0);
      expect(result).not.toContain('=');
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
    });

    it('should handle single byte', () => {
      // GIVEN
      const input = new Uint8Array([42]);

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBeDefined();
      expect(result.length).toBeGreaterThan(0);
    });

    it('should handle all zero bytes', () => {
      // GIVEN
      const input = new Uint8Array([0, 0, 0, 0]);

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBe('AAAAAA');
    });

    it('should handle all 255 bytes', () => {
      // GIVEN
      const input = new Uint8Array([255, 255, 255, 255]);

      // WHEN
      const result = base64urlEncode(input);

      // THEN
      expect(result).toBeDefined();
      expect(result).not.toContain('=');
    });
  });
});
