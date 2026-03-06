import { describe, expect, it } from '@jest/globals';
import type { HttpRequest } from '#types';
import { FetchHttpAdapter } from '#http/adapters/fetch';

describe('FetchHttpAdapter', () => {
  describe('constructor', () => {
    it('should create adapter with global fetch by default', () => {
      // GIVEN & WHEN
      const adapter = new FetchHttpAdapter();

      // THEN
      expect(adapter).toBeDefined();
    });

    it('should create adapter with custom fetch implementation', () => {
      // GIVEN
      const customFetch = async (): Promise<Response> => new Response('test');

      // WHEN
      const adapter = new FetchHttpAdapter(customFetch);

      // THEN
      expect(adapter).toBeDefined();
    });
  });

  describe('execute', () => {
    it('should execute GET request successfully', async () => {
      // GIVEN
      const mockResponse = new Response(JSON.stringify({ success: true }), {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/json' }
      });

      const mockFetch = async (_url: string, _init?: RequestInit): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: { Authorization: 'Bearer token' }
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.status).toBe(200);
      expect(response.statusText).toBe('OK');
      expect(response.body).toBe('{"success":true}');
      expect(response.headers['content-type']).toBe('application/json');
    });

    it('should execute POST request with body', async () => {
      // GIVEN
      let capturedBody: BodyInit | null | undefined;
      const mockResponse = new Response('{}', { status: 201 });

      const mockFetch = async (_url: string, init?: RequestInit): Promise<Response> => {
        capturedBody = init?.body;
        return mockResponse;
      };
      const adapter = new FetchHttpAdapter(mockFetch);

      const requestBody = 'param1=value1&param2=value2';
      const request: HttpRequest = {
        method: 'POST',
        url: 'https://api.example.com/test',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: requestBody
      };

      // WHEN
      await adapter.execute(request);

      // THEN
      expect(capturedBody).toBe(requestBody);
    });

    it('should normalize response headers to lowercase', async () => {
      // GIVEN
      const mockResponse = new Response('{}', {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Custom-Header': 'value',
          Authorization: 'Bearer token'
        }
      });

      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.headers['content-type']).toBe('application/json');
      expect(response.headers['x-custom-header']).toBe('value');
      expect(response.headers['authorization']).toBe('Bearer token');
    });

    it('should handle request without headers', async () => {
      // GIVEN
      const mockResponse = new Response('{}', { status: 200 });
      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.status).toBe(200);
    });

    it('should handle request without body', async () => {
      // GIVEN
      const mockResponse = new Response('{}', { status: 200 });
      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.status).toBe(200);
    });

    it('should handle 4xx error responses', async () => {
      // GIVEN
      const mockResponse = new Response(JSON.stringify({ error: 'Not Found' }), {
        status: 404,
        statusText: 'Not Found'
      });

      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.status).toBe(404);
      expect(response.statusText).toBe('Not Found');
      expect(response.body).toContain('Not Found');
    });

    it('should handle 5xx error responses', async () => {
      // GIVEN
      const mockResponse = new Response(JSON.stringify({ error: 'Internal Server Error' }), {
        status: 500,
        statusText: 'Internal Server Error'
      });

      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'POST',
        url: 'https://api.example.com/test',
        headers: {},
        body: '{}'
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.status).toBe(500);
      expect(response.statusText).toBe('Internal Server Error');
    });

    it('should handle empty response body', async () => {
      // GIVEN
      const mockResponse = new Response(null, { status: 204, statusText: 'No Content' });
      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'DELETE',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.status).toBe(204);
      expect(response.body).toBe('');
    });

    it('should pass request headers to fetch', async () => {
      // GIVEN
      let capturedHeaders: HeadersInit | undefined;
      const mockResponse = new Response('{}', { status: 200 });

      const mockFetch = async (_url: string, init?: RequestInit): Promise<Response> => {
        capturedHeaders = init?.headers as HeadersInit;
        return mockResponse;
      };
      const adapter = new FetchHttpAdapter(mockFetch);

      const headers = {
        'Content-Type': 'application/json',
        Authorization: 'Bearer token',
        'X-Custom': 'value'
      };
      const request: HttpRequest = {
        method: 'POST',
        url: 'https://api.example.com/test',
        headers,
        body: '{}'
      };

      // WHEN
      await adapter.execute(request);

      // THEN
      expect(capturedHeaders).toEqual(headers);
    });

    it('should pass request method to fetch', async () => {
      // GIVEN
      let capturedMethod: string | undefined;
      const mockResponse = new Response('{}', { status: 200 });

      const mockFetch = async (_url: string, init?: RequestInit): Promise<Response> => {
        capturedMethod = init?.method;
        return mockResponse;
      };
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'PUT',
        url: 'https://api.example.com/test',
        headers: {},
        body: '{}'
      };

      // WHEN
      await adapter.execute(request);

      // THEN
      expect(capturedMethod).toBe('PUT');
    });

    it('should pass correct URL to fetch', async () => {
      // GIVEN
      let capturedUrl: string | undefined;
      const mockResponse = new Response('{}', { status: 200 });

      const mockFetch = async (url: string, _init?: RequestInit): Promise<Response> => {
        capturedUrl = url;
        return mockResponse;
      };
      const adapter = new FetchHttpAdapter(mockFetch);

      const testUrl = 'https://api.example.com/v1/resource?param=value';
      const request: HttpRequest = {
        method: 'GET',
        url: testUrl,
        headers: {}
      };

      // WHEN
      await adapter.execute(request);

      // THEN
      expect(capturedUrl).toBe(testUrl);
    });

    it('should handle non-JSON response body', async () => {
      // GIVEN
      const textBody = 'Plain text response';
      const mockResponse = new Response(textBody, {
        status: 200,
        headers: { 'Content-Type': 'text/plain' }
      });

      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.body).toBe(textBody);
      expect(response.headers['content-type']).toBe('text/plain');
    });

    it('should throw error when fetch is not available', async () => {
      // GIVEN
      const adapter = new FetchHttpAdapter('not a function' as any);
      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN & THEN
      await expect(adapter.execute(request)).rejects.toThrow('Fetch API is not available in this environment');
    });
  });

  describe('edge cases', () => {
    it('should handle multiple headers with same name', async () => {
      // GIVEN
      const headers = new Headers();
      headers.append('Set-Cookie', 'cookie1=value1');
      headers.append('Set-Cookie', 'cookie2=value2');

      const mockResponse = new Response('{}', {
        status: 200,
        headers: headers
      });

      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('should handle large response body', async () => {
      // GIVEN
      const largeBody = 'x'.repeat(1000000); // 1MB response
      const mockResponse = new Response(largeBody, { status: 200 });

      const mockFetch = async (): Promise<Response> => mockResponse;
      const adapter = new FetchHttpAdapter(mockFetch);

      const request: HttpRequest = {
        method: 'GET',
        url: 'https://api.example.com/test',
        headers: {}
      };

      // WHEN
      const response = await adapter.execute(request);

      // THEN
      expect(response.body.length).toBe(1000000);
    });
  });
});
