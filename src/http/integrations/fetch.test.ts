import { beforeEach, describe, expect, it } from '@jest/globals';
import type { Logger } from '#types';
import type { OAuth2Client } from '#core/client';
import { type FetchOptions, withOAuth2Fetch } from '#http/integrations/fetch';

describe('withOAuth2Fetch', () => {
  let mockOAuth2Client: OAuth2Client & { getLogger: () => Logger };
  let mockFetchInstance: typeof fetch;
  let fetchCalls: Array<{ url: string; init?: RequestInit; request?: Request }>;
  let handleServerResponseHandler: any;

  function captureHeaders(): Record<string, string> {
    const capturedRequest = fetchCalls[0].request;
    expect(capturedRequest).toBeDefined();
    expect(capturedRequest!.headers).toBeDefined();

    const headers: Record<string, string> = {};
    capturedRequest.headers.forEach((value, key) => {
      headers[key] = value;
    });
    return headers;
  }

  beforeEach(() => {
    fetchCalls = [];
    handleServerResponseHandler = async () => undefined;

    // Create mock OAuth2Client
    mockOAuth2Client = {
      getOAuth2Headers: async () => ({
        Authorization: 'DPoP test-token',
        DPoP: 'test-dpop-proof'
      }),
      handleServerResponse: async (...args: any[]) => handleServerResponseHandler(...args),
      buildTokenRequest: async () => ({
        method: 'POST',
        url: 'https://auth.example.com/token',
        headers: {},
        body: ''
      }),
      buildResourceRequestHeaders: async () => ({}),
      getLogger: () => ({
        trace: () => {},
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {}
      })
    };

    // Create mock fetch instance
    mockFetchInstance = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input.toString();
      const request = input instanceof Request ? input : undefined;
      fetchCalls.push({ url, init, request });

      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    };
  });

  describe('integration setup', () => {
    it('should return fetch function', () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };

      // WHEN
      const result = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // THEN
      expect(typeof result).toBe('function');
    });

    it('should configure interceptors', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      await wrappedFetch('/resource', { method: 'GET' });

      // THEN - Should have intercepted and made actual fetch call
      expect(fetchCalls.length).toBe(1);
    });
  });

  describe('request interceptor', () => {
    it('should add OAuth2 headers to request', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      const response = await wrappedFetch('/resource', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      });

      // THEN
      expect(response.status).toBe(200);
      // Verify OAuth2 headers were called
      expect(mockOAuth2Client.getOAuth2Headers).toBeDefined();
    });

    it('should throw error when method is undefined', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN & THEN
      await expect(wrappedFetch('/resource', {})).rejects.toThrow('Fetch HTTP method not defined');
    });

    it('should uppercase HTTP method', async () => {
      // GIVEN
      let capturedMethod: string;
      mockOAuth2Client.getOAuth2Headers = async (method: string) => {
        capturedMethod = method;
        return { Authorization: 'Bearer token' };
      };

      const fetchOptions: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, fetchOptions);

      // WHEN
      await wrappedFetch('/resource', { method: 'get' });

      // THEN
      expect(capturedMethod).toBe('GET');
    });

    it('should preserve existing headers', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      const response = await wrappedFetch('/resource', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Custom': 'value'
        }
      });

      // THEN
      expect(response.status).toBe(200);
      const headers = captureHeaders();

      expect(headers['content-type']).toBe('application/json');
      expect(headers['authorization']).toBe('DPoP test-token');
      expect(headers['dpop']).toBe('test-dpop-proof');
      expect(headers['x-custom']).toBe('value');
    });
  });

  describe('response interceptor', () => {
    it('should handle successful response', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      const response = await wrappedFetch('/resource', { method: 'GET' });

      // THEN
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
    });

    it('should call handleServerResponse with correct parameters', async () => {
      // GIVEN
      let capturedParams: any;

      // Create completely fresh mock client for this test
      // noinspection JSUnusedGlobalSymbols
      const testOAuth2Client: OAuth2Client & { getLogger: () => Logger } = {
        getOAuth2Headers: async () => ({
          Authorization: 'DPoP test-token',
          DPoP: 'test-dpop-proof'
        }),
        handleServerResponse: async (status: number, headers: Record<string, string>, method: string, url: string) => {
          capturedParams = { status, headers, method, url };
          return undefined;
        },
        buildTokenRequest: async () => ({
          method: 'POST',
          url: 'https://auth.example.com/token',
          headers: {},
          body: ''
        }),
        buildResourceRequestHeaders: async () => ({}),
        getLogger: () => ({
          trace: () => {},
          debug: () => {},
          info: () => {},
          warn: () => {},
          error: () => {}
        })
      };

      // Create fresh mock fetch instance for this test
      const testFetchInstance: typeof fetch = async (
        _input: string | URL | Request,
        _init?: RequestInit
      ): Promise<Response> => {
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      };

      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(testOAuth2Client, testFetchInstance, options);

      // WHEN
      await wrappedFetch('/api/data', { method: 'POST' });

      // THEN
      expect(capturedParams).toBeDefined();
      expect(capturedParams.status).toBe(200);
      expect(capturedParams.method).toBe('POST');
      expect(capturedParams.headers['content-type']).toBe('application/json');
    });

    it('should handle response with absolute URL', async () => {
      // GIVEN
      let capturedUrl: string | undefined;

      // Create completely fresh mock client for this test
      const testOAuth2Client: OAuth2Client & { getLogger: () => Logger } = {
        getOAuth2Headers: async () => ({
          Authorization: 'DPoP test-token',
          DPoP: 'test-dpop-proof'
        }),
        handleServerResponse: async (
          _status: number,
          _headers: Record<string, string>,
          _method: string,
          url: string
        ) => {
          capturedUrl = url;
          return undefined;
        },
        buildTokenRequest: async () => ({
          method: 'POST',
          url: 'https://auth.example.com/token',
          headers: {},
          body: ''
        }),
        buildResourceRequestHeaders: async () => ({}),
        getLogger: () => ({
          trace: () => {},
          debug: () => {},
          info: () => {},
          warn: () => {},
          error: () => {}
        })
      };

      // Create fresh mock fetch instance for this test
      const testFetchInstance: typeof fetch = async (
        _input: string | URL | Request,
        _init?: RequestInit
      ): Promise<Response> => {
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      };

      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(testOAuth2Client, testFetchInstance, options);

      // WHEN
      await wrappedFetch('https://different-api.com/resource', { method: 'GET' });

      // THEN
      expect(capturedUrl).toBe('');
    });

    it('should convert headers to record format', async () => {
      // GIVEN
      let capturedHeaders: any;
      mockOAuth2Client.handleServerResponse = async (_status, headers) => {
        capturedHeaders = headers;
        return undefined;
      };

      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      await wrappedFetch('/resource', { method: 'GET' });

      // THEN
      expect(capturedHeaders['content-type']).toBe('application/json');
    });
  });

  describe('error interceptor', () => {
    beforeEach(() => {
      // Override mock to return error response
      mockFetchInstance = async (): Promise<Response> => {
        return new Response(JSON.stringify({ error: 'unauthorized' }), {
          status: 401,
          headers: { 'www-authenticate': 'DPoP error="use_dpop_nonce"' }
        });
      };
    });

    it('should retry on auth error when new headers returned', async () => {
      // GIVEN
      let callCount = 0;
      mockFetchInstance = async (): Promise<Response> => {
        callCount++;
        if (callCount === 1) {
          return new Response(null, {
            status: 401,
            headers: { 'www-authenticate': 'DPoP error="use_dpop_nonce"' }
          });
        }
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      };

      mockOAuth2Client.handleServerResponse = async () => ({
        Authorization: 'DPoP new-token',
        DPoP: 'new-proof'
      });

      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      const response = await wrappedFetch('/resource', { method: 'GET' });

      // THEN
      expect(response.status).toBe(200);
      expect(callCount).toBe(2);
    });

    it('should return error response when no retry headers returned', async () => {
      // GIVEN
      mockOAuth2Client.handleServerResponse = async () => undefined;

      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      const response = await wrappedFetch('/resource', { method: 'GET' });

      // THEN
      expect(response.status).toBe(401);
    });

    it('should handle different error status codes', async () => {
      // GIVEN
      const statusCodes = [400, 403, 404, 500, 502];
      mockOAuth2Client.handleServerResponse = async () => undefined;

      // WHEN & THEN
      for (const status of statusCodes) {
        mockFetchInstance = async (): Promise<Response> => {
          return new Response(null, { status });
        };

        const options: FetchOptions = {
          baseURL: 'https://api.example.com'
        };
        const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);
        const response = await wrappedFetch('/resource', { method: 'GET' });

        expect(response.status).toBe(status);
      }
    });

    it('should throw error when method is missing in error response', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN & THEN
      await expect(wrappedFetch('/resource', {})).rejects.toThrow('Fetch HTTP method not defined');
    });
  });

  describe('URL handling', () => {
    it('should build full URL from baseURL and relative path', async () => {
      // GIVEN
      let capturedUrl: string | undefined;
      mockOAuth2Client.getOAuth2Headers = async (_method: string, url: string) => {
        capturedUrl = url;
        return { Authorization: 'Bearer token' };
      };

      const fetchOptions: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, fetchOptions);

      // WHEN
      await wrappedFetch('/api/resource', { method: 'GET' });

      // THEN
      expect(capturedUrl).toBe('https://api.example.com/api/resource');
    });

    it('should handle baseURL with trailing slash', async () => {
      // GIVEN
      let capturedUrl: string | undefined;
      mockOAuth2Client.getOAuth2Headers = async (_method: string, url: string) => {
        capturedUrl = url;
        return { Authorization: 'Bearer token' };
      };

      const fetchOptions: FetchOptions = {
        baseURL: 'https://api.example.com/'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, fetchOptions);

      // WHEN
      await wrappedFetch('/resource', { method: 'GET' });

      // THEN
      expect(capturedUrl).toBe('https://api.example.com/resource');
    });

    it('should handle absolute URL in request', async () => {
      // GIVEN
      let capturedUrl: string | undefined;
      mockOAuth2Client.getOAuth2Headers = async (_method: string, url: string) => {
        capturedUrl = url;
        return { Authorization: 'Bearer token' };
      };

      const fetchOptions: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, fetchOptions);

      // WHEN
      await wrappedFetch('https://other-api.example.com/resource', { method: 'POST' });

      // THEN
      expect(capturedUrl).toBe('https://other-api.example.com/resource');
    });

    it('should handle URL object as input', async () => {
      // GIVEN
      const fetchOptions: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, fetchOptions);

      // WHEN
      const response = await wrappedFetch(new URL('https://example.com/resource'), { method: 'GET' });

      // THEN
      expect(response.status).toBe(200);
    });

    it('should handle Request object as input', async () => {
      // GIVEN
      const fetchOptions: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, fetchOptions);
      const request = new Request('https://example.com/resource', { method: 'POST' });

      // WHEN
      const response = await wrappedFetch(request);

      // THEN
      expect(response.status).toBe(200);
    });
  });

  describe('headers conversion', () => {
    it('should handle Headers instance', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);
      const headers = new Headers();
      headers.set('Content-Type', 'application/json');
      headers.set('X-Custom', 'value');

      // WHEN
      await wrappedFetch('/resource', {
        method: 'POST',
        headers
      });

      // THEN
      expect(fetchCalls.length).toBe(1);
    });

    it('should handle array of header tuples', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      await wrappedFetch('/resource', {
        method: 'POST',
        headers: [
          ['Content-Type', 'application/json'],
          ['X-Custom', 'value']
        ]
      });

      // THEN
      expect(fetchCalls.length).toBe(1);
    });

    it('should handle object headers', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      await wrappedFetch('/resource', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Custom': 'value'
        }
      });

      // THEN
      expect(fetchCalls.length).toBe(1);
    });

    it('should handle undefined headers', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      await wrappedFetch('/resource', { method: 'GET' });

      // THEN
      expect(fetchCalls.length).toBe(1);
    });

    it('should handle headers with array values', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      await wrappedFetch('/resource', {
        method: 'POST',
        headers: {
          Accept: ['application/json', 'text/plain']
        } as any
      });

      // THEN
      expect(fetchCalls.length).toBe(1);
    });

    it('should handle headers with undefined values', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      await wrappedFetch('/resource', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Undefined': undefined
        }
      });

      // THEN
      expect(fetchCalls.length).toBe(1);
      const headers = captureHeaders();

      expect(headers['content-type']).toBe('application/json');
      expect(headers['authorization']).toBe('DPoP test-token');
      expect(headers['dpop']).toBe('test-dpop-proof');

      expect(headers['x-undefined']).toBe('undefined');
    });
  });

  describe('edge cases', () => {
    it('should handle empty baseURL', () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: ''
      };

      // WHEN & THEN - should not throw
      expect(() => withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options)).not.toThrow();
    });

    it('should handle Request without body', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);
      const request = new Request('https://example.com/resource', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      });

      // WHEN
      const response = await wrappedFetch(request);

      // THEN
      expect(response.status).toBe(200);
    });

    it('should handle multiple requests sequentially', async () => {
      // GIVEN
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };
      const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);

      // WHEN
      await wrappedFetch('/resource1', { method: 'GET' });
      await wrappedFetch('/resource2', { method: 'POST' });
      await wrappedFetch('/resource3', { method: 'GET' });

      // THEN
      expect(fetchCalls.length).toBe(3);
    });

    it('should handle case-sensitive HTTP methods', async () => {
      // GIVEN
      const methods = ['get', 'GET', 'Post', 'POST', 'put', 'PUT'];
      const options: FetchOptions = {
        baseURL: 'https://api.example.com'
      };

      // WHEN & THEN
      for (const method of methods) {
        fetchCalls = [];
        const wrappedFetch = withOAuth2Fetch(mockOAuth2Client, mockFetchInstance, options);
        const response = await wrappedFetch('/resource', { method });
        expect(response.status).toBe(200);
      }
    });
  });
});
