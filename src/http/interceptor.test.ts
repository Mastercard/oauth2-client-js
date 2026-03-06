import { beforeEach, describe, expect, it } from '@jest/globals';
import { OAuth2ClientDelegate } from '#http/interceptor';
import type { Logger } from '#types';
import type { OAuth2Client } from '#core/client';

describe('OAuth2ClientDelegate', () => {
  interface MockRequest {
    headers: Record<string, string>;
    __oauth2_retried__?: boolean;
  }

  interface MockResponse {
    status: number;
    data: any;
  }

  let mockOAuth2Client: OAuth2Client & {
    getLogger: () => Logger;
  };
  let mockAdapter: any;
  let delegate: OAuth2ClientDelegate<MockRequest, MockResponse>;

  beforeEach(() => {
    // Create mock OAuth2Client
    mockOAuth2Client = {
      getOAuth2Headers: async () => ({
        Authorization: 'DPoP test-token',
        DPoP: 'test-dpop-proof'
      }),
      handleServerResponse: async () => undefined,
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

    // Create mock adapter
    mockAdapter = {
      getRequestHeaders: (request: MockRequest) => request.headers,
      attachRequestHeaders: (request: MockRequest, oauth2Headers: Record<string, string>) => {
        Object.assign(request.headers, oauth2Headers);
      },
      retryRequest: async (_url: string, _request: MockRequest) => ({
        status: 200,
        data: { success: true }
      })
    };

    delegate = new OAuth2ClientDelegate(mockOAuth2Client, mockAdapter);
  });

  describe('onInterceptRequest', () => {
    it('should intercept request and attach OAuth2 headers', async () => {
      // GIVEN
      const request: MockRequest = {
        headers: { 'Content-Type': 'application/json' }
      };
      const method = 'GET';
      const url = 'https://api.example.com/resource';

      // WHEN
      await delegate.onInterceptRequest(request, method, url);

      // THEN
      expect(request.headers['Authorization']).toBe('DPoP test-token');
      expect(request.headers['DPoP']).toBe('test-dpop-proof');
      expect(request.headers['Content-Type']).toBe('application/json');
    });

    it('should call getOAuth2Headers with correct parameters', async () => {
      // GIVEN
      const request: MockRequest = {
        headers: { 'X-Custom': 'value' }
      };
      const method = 'POST';
      const url = 'https://api.example.com/data';
      let capturedMethod: string;
      let capturedUrl: string;
      let capturedHeaders: Record<string, string>;

      mockOAuth2Client.getOAuth2Headers = async (m: string, u: string, h?: Record<string, string>) => {
        capturedMethod = m;
        capturedUrl = u;
        capturedHeaders = h ?? {};
        return { Authorization: 'Bearer token' };
      };

      // WHEN
      await delegate.onInterceptRequest(request, method, url);

      // THEN
      expect(capturedMethod).toBe('POST');
      expect(capturedUrl).toBe('https://api.example.com/data');
      expect(capturedHeaders['X-Custom']).toBe('value');
    });

    it('should handle request with empty headers', async () => {
      // GIVEN
      const request: MockRequest = { headers: {} };

      // WHEN
      await delegate.onInterceptRequest(request, 'GET', 'https://api.example.com');

      // THEN
      expect(request.headers['Authorization']).toBeDefined();
    });

    it('should work with different HTTP methods', async () => {
      // GIVEN
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

      // WHEN & THEN
      for (const method of methods) {
        const request: MockRequest = { headers: {} };
        await delegate.onInterceptRequest(request, method, 'https://api.example.com');
        expect(request.headers['Authorization']).toBeDefined();
      }
    });

    it('should preserve existing headers', async () => {
      // GIVEN
      const request: MockRequest = {
        headers: {
          'Content-Type': 'application/json',
          'X-Custom-Header': 'custom-value',
          'User-Agent': 'test-agent'
        }
      };

      // WHEN
      await delegate.onInterceptRequest(request, 'GET', 'https://api.example.com');

      // THEN
      expect(request.headers['Content-Type']).toBe('application/json');
      expect(request.headers['X-Custom-Header']).toBe('custom-value');
      expect(request.headers['User-Agent']).toBe('test-agent');
      expect(request.headers['Authorization']).toBe('DPoP test-token');
    });

    it('should not fail when getOAuth2Headers throws an error', async () => {
      // GIVEN
      const request: MockRequest = {
        headers: { 'Content-Type': 'application/json' }
      };
      const method = 'GET';
      const url = 'https://api.example.com/resource';

      // Mock getOAuth2Headers to throw an error
      mockOAuth2Client.getOAuth2Headers = async () => {
        throw new Error('Failed to generate OAuth2 headers');
      };

      // WHEN - onInterceptRequest should not throw
      await expect(delegate.onInterceptRequest(request, method, url)).resolves.toBeUndefined();

      // THEN - request should not have OAuth2 headers attached (but original headers preserved)
      expect(request.headers['Authorization']).toBeUndefined();
      expect(request.headers['DPoP']).toBeUndefined();
      expect(request.headers['Content-Type']).toBe('application/json');
    });
  });

  describe('handleServerResponse', () => {
    it('should call OAuth2Client handleServerResponse', async () => {
      // GIVEN
      let capturedParams: any;
      mockOAuth2Client.handleServerResponse = async (status, headers, method, url) => {
        capturedParams = { status, headers, method, url };
        return undefined;
      };

      const statusCode = 200;
      const method = 'GET';
      const url = 'https://api.example.com/resource';
      const headers = { 'dpop-nonce': 'test-nonce' };

      // WHEN
      await delegate.handleServerResponse(statusCode, method, url, headers);

      // THEN
      expect(capturedParams).toEqual({
        status: 200,
        headers: { 'dpop-nonce': 'test-nonce' },
        method: 'GET',
        url: 'https://api.example.com/resource'
      });
    });

    it('should handle success responses', async () => {
      // GIVEN
      const statusCode = 200;

      // WHEN & THEN - should not throw
      await expect(
        delegate.handleServerResponse(statusCode, 'GET', 'https://api.example.com', {})
      ).resolves.toBeUndefined();
    });

    it('should handle 4xx error responses', async () => {
      // GIVEN
      const statusCode = 401;

      // WHEN & THEN - should not throw
      await expect(
        delegate.handleServerResponse(statusCode, 'GET', 'https://api.example.com', {})
      ).resolves.toBeUndefined();
    });

    it('should handle responses with DPoP nonce', async () => {
      // GIVEN
      const headers = {
        'dpop-nonce': 'new-nonce-value',
        'www-authenticate': 'DPoP error="use_dpop_nonce"'
      };

      // WHEN & THEN - should not throw
      await expect(
        delegate.handleServerResponse(401, 'GET', 'https://api.example.com', headers)
      ).resolves.toBeUndefined();
    });
  });

  describe('onErrorResponse', () => {
    it('should not retry when request already retried', async () => {
      // GIVEN
      const request: MockRequest = {
        headers: {},
        __oauth2_retried__: true
      };
      const status = 401;

      // WHEN
      const result = await delegate.onErrorResponse(status, 'GET', 'https://api.example.com', {}, request);

      // THEN
      expect(result).toBeUndefined();
    });

    it('should retry request when OAuth2Client returns retry headers', async () => {
      // GIVEN
      const request: MockRequest = { headers: {} };
      mockOAuth2Client.handleServerResponse = async () => ({
        Authorization: 'DPoP new-token',
        DPoP: 'new-proof'
      });

      let retryRequestCalled = false;
      mockAdapter.retryRequest = async () => {
        retryRequestCalled = true;
        return { status: 200, data: 'success' };
      };

      // WHEN
      const result = await delegate.onErrorResponse(
        401,
        'GET',
        'https://api.example.com',
        { 'www-authenticate': 'DPoP error="use_dpop_nonce"' },
        request
      );

      // THEN
      expect(retryRequestCalled).toBe(true);
      expect(result).toEqual({ status: 200, data: 'success' });
    });

    it('should mark request as retried', async () => {
      // GIVEN
      const request: MockRequest = { headers: {} };
      mockOAuth2Client.handleServerResponse = async () => ({
        Authorization: 'DPoP new-token'
      });

      // WHEN
      await delegate.onErrorResponse(401, 'GET', 'https://api.example.com', {}, request);

      // THEN
      expect(request.__oauth2_retried__).toBe(true);
    });

    it('should attach new headers before retrying', async () => {
      // GIVEN
      const request: MockRequest = { headers: { 'X-Original': 'value' } };
      const newHeaders = {
        Authorization: 'DPoP updated-token',
        DPoP: 'updated-proof'
      };
      mockOAuth2Client.handleServerResponse = async () => newHeaders;

      let capturedRequest: MockRequest | undefined;
      mockAdapter.attachRequestHeaders = (req: MockRequest, headers: Record<string, string>) => {
        Object.assign(req.headers, headers);
        capturedRequest = req;
      };

      // WHEN
      await delegate.onErrorResponse(401, 'GET', 'https://api.example.com', {}, request);

      // THEN
      expect(capturedRequest?.headers['Authorization']).toBe('DPoP updated-token');
      expect(capturedRequest?.headers['DPoP']).toBe('updated-proof');
      expect(capturedRequest?.headers['X-Original']).toBe('value');
    });

    it('should not retry when OAuth2Client returns undefined', async () => {
      // GIVEN
      const request: MockRequest = { headers: {} };
      mockOAuth2Client.handleServerResponse = async () => undefined;

      let retryRequestCalled = false;
      mockAdapter.retryRequest = async () => {
        retryRequestCalled = true;
        return { status: 200, data: 'success' };
      };

      // WHEN
      const result = await delegate.onErrorResponse(401, 'GET', 'https://api.example.com', {}, request);

      // THEN
      expect(retryRequestCalled).toBe(false);
      expect(result).toBeUndefined();
    });

    it('should uppercase HTTP method when calling handleServerResponse', async () => {
      // GIVEN
      const request: MockRequest = { headers: {} };
      let capturedMethod: string | undefined;

      mockOAuth2Client.handleServerResponse = async (_status, _headers, method) => {
        capturedMethod = method;
        return undefined;
      };

      // WHEN
      await delegate.onErrorResponse(401, 'get', 'https://api.example.com', {}, request);

      // THEN
      expect(capturedMethod).toBe('GET');
    });

    it('should handle different error status codes', async () => {
      // GIVEN
      const request: MockRequest = { headers: {} };
      const errorCodes = [400, 401, 403, 500];

      // WHEN & THEN
      for (const status of errorCodes) {
        const result = await delegate.onErrorResponse(status, 'GET', 'https://api.example.com', {}, { ...request });
        // Should handle without throwing
        expect(result).toBeUndefined();
      }
    });

    it('should pass URL to retryRequest', async () => {
      // GIVEN
      const request: MockRequest = { headers: {} };
      const testUrl = 'https://api.example.com/specific/endpoint';
      mockOAuth2Client.handleServerResponse = async () => ({ Authorization: 'Bearer token' });

      let capturedUrl: string | undefined;
      mockAdapter.retryRequest = async (url: string) => {
        capturedUrl = url;
        return { status: 200, data: 'success' };
      };

      // WHEN
      await delegate.onErrorResponse(401, 'GET', testUrl, {}, request);

      // THEN
      expect(capturedUrl).toBe(testUrl);
    });
  });

  describe('edge cases', () => {
    it('should handle request with null headers object', async () => {
      // GIVEN
      mockAdapter.getRequestHeaders = () => ({});
      const request: MockRequest = { headers: {} };

      // WHEN & THEN - should not throw
      await expect(delegate.onInterceptRequest(request, 'GET', 'https://api.example.com')).resolves.toBeUndefined();
    });

    it('should handle very long URLs', async () => {
      // GIVEN
      const longUrl = 'https://api.example.com/' + 'a'.repeat(1000);
      const request: MockRequest = { headers: {} };

      // WHEN & THEN - should not throw
      await expect(delegate.onInterceptRequest(request, 'GET', longUrl)).resolves.toBeUndefined();
    });

    it('should handle URLs with special characters', async () => {
      // GIVEN
      const url = 'https://api.example.com/resource?param=value&special=!@#$%';
      const request: MockRequest = { headers: {} };

      // WHEN & THEN - should not throw
      await expect(delegate.onInterceptRequest(request, 'GET', url)).resolves.toBeUndefined();
    });

    it('should handle multiple sequential error responses', async () => {
      // GIVEN
      const request: MockRequest = { headers: {} };
      mockOAuth2Client.handleServerResponse = async () => undefined;

      // WHEN
      const result1 = await delegate.onErrorResponse(401, 'GET', 'https://api.example.com', {}, request);
      const result2 = await delegate.onErrorResponse(401, 'GET', 'https://api.example.com', {}, request);

      // THEN
      expect(result1).toBeUndefined();
      expect(result2).toBeUndefined();
    });
  });
});
