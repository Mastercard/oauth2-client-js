import { beforeEach, describe, expect, it } from '@jest/globals';
import type { AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { AxiosError } from 'axios';
import type { Logger } from '#types';
import type { OAuth2Client } from '#core/client';
import { type AxiosOptions, withOAuth2Axios } from '#http/integrations/axios';

describe('withOAuth2Axios', () => {
  let mockOAuth2Client: OAuth2Client & { getLogger: () => Logger };
  let mockAxiosInstance: AxiosInstance;
  let requestInterceptor: any;
  let responseInterceptor: any;
  let errorInterceptor: any;
  let handleServerResponseHandler: any;

  beforeEach(() => {
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

    // Create mock axios instance
    mockAxiosInstance = {
      interceptors: {
        request: {
          use: (onFulfilled: any) => {
            requestInterceptor = onFulfilled;
          }
        },
        response: {
          use: (onFulfilled: any, onRejected: any) => {
            responseInterceptor = onFulfilled;
            errorInterceptor = onRejected;
          }
        }
      }
    } as any;
  });

  describe('integration setup', () => {
    it('should return axios instance', () => {
      // GIVEN
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };

      // WHEN
      const result = withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      // THEN
      expect(result).toBe(mockAxiosInstance);
    });

    it('should register request interceptor', () => {
      // GIVEN
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };

      // WHEN
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      // THEN
      expect(requestInterceptor).toBeDefined();
      expect(typeof requestInterceptor).toBe('function');
    });

    it('should register response interceptors', () => {
      // GIVEN
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };

      // WHEN
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      // THEN
      expect(responseInterceptor).toBeDefined();
      expect(errorInterceptor).toBeDefined();
    });
  });

  describe('request interceptor', () => {
    beforeEach(() => {
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);
    });

    it('should add OAuth2 headers to request', async () => {
      // GIVEN
      const config: InternalAxiosRequestConfig = {
        method: 'GET',
        url: '/resource',
        headers: {} as any
      };

      // WHEN
      const result = await requestInterceptor(config);

      // THEN
      expect(result.headers['Authorization']).toBe('DPoP test-token');
      expect(result.headers['DPoP']).toBe('test-dpop-proof');
    });

    it('should handle absolute URL in request', async () => {
      // GIVEN
      const config: InternalAxiosRequestConfig = {
        method: 'POST',
        url: 'https://other-api.example.com/resource',
        headers: {} as any
      };

      // WHEN
      const result = await requestInterceptor(config);

      // THEN
      expect(result.headers['Authorization']).toBe('DPoP test-token');
    });

    it('should build full URL from baseURL and relative path', async () => {
      // GIVEN
      let capturedUrl: string | undefined;
      mockOAuth2Client.getOAuth2Headers = async (_method: string, url: string) => {
        capturedUrl = url;
        return { Authorization: 'Bearer token' };
      };

      const config: InternalAxiosRequestConfig = {
        method: 'GET',
        url: '/api/resource',
        headers: {} as any
      };

      // WHEN
      await requestInterceptor(config);

      // THEN
      expect(capturedUrl).toBe('https://api.example.com/api/resource');
    });

    it('should throw error when method is undefined', async () => {
      // GIVEN
      const config: InternalAxiosRequestConfig = {
        url: '/resource',
        headers: {} as any
      } as any;

      // WHEN & THEN
      await expect(requestInterceptor(config)).rejects.toThrow('HTTP method not defined');
    });

    it('should uppercase HTTP method', async () => {
      // GIVEN
      let capturedMethod: string | undefined;
      mockOAuth2Client.getOAuth2Headers = async (method: string) => {
        capturedMethod = method;
        return { Authorization: 'Bearer token' };
      };

      const config: InternalAxiosRequestConfig = {
        method: 'get' as any,
        url: '/resource',
        headers: {} as any
      };

      // WHEN
      await requestInterceptor(config);

      // THEN
      expect(capturedMethod).toBe('GET');
    });

    it('should preserve existing headers', async () => {
      // GIVEN
      const config: InternalAxiosRequestConfig = {
        method: 'GET',
        url: '/resource',
        headers: {
          'Content-Type': 'application/json',
          'X-Custom': 'value'
        } as any
      };

      // WHEN
      const result = await requestInterceptor(config);

      // THEN
      expect(result.headers['Content-Type']).toBe('application/json');
      expect(result.headers['X-Custom']).toBe('value');
      expect(result.headers['Authorization']).toBe('DPoP test-token');
    });

    it('should create headers object if not present', async () => {
      // GIVEN
      const config: InternalAxiosRequestConfig = {
        method: 'GET',
        url: '/resource'
      } as any;

      // WHEN
      const result = await requestInterceptor(config);

      // THEN
      expect(result.headers).toBeDefined();
      expect(result.headers['Authorization']).toBe('DPoP test-token');
    });
  });

  describe('response interceptor', () => {
    beforeEach(() => {
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);
    });

    it('should handle successful response', async () => {
      // GIVEN
      const response: AxiosResponse = {
        status: 200,
        statusText: 'OK',
        data: { success: true },
        headers: { 'dpop-nonce': 'test-nonce' },
        config: {
          method: 'GET',
          url: '/resource',
          headers: {} as any
        }
      } as any;

      // WHEN
      const result = await responseInterceptor(response);

      // THEN
      expect(result).toBe(response);
    });

    it('should call handleServerResponse with correct parameters', async () => {
      // GIVEN
      let capturedParams: any;
      mockOAuth2Client.handleServerResponse = async (status, headers, method, url) => {
        capturedParams = { status, headers, method, url };
        return undefined;
      };

      const response: AxiosResponse = {
        status: 200,
        data: {},
        headers: { 'dpop-nonce': 'nonce-value' },
        config: {
          method: 'POST',
          url: '/api/data',
          headers: {} as any
        }
      } as any;

      // WHEN
      await responseInterceptor(response);

      // THEN
      expect(capturedParams.status).toBe(200);
      expect(capturedParams.method).toBe('POST');
      expect(capturedParams.url).toBe('https://api.example.com/api/data');
      expect(capturedParams.headers['dpop-nonce']).toBe('nonce-value');
    });

    it('should handle response with absolute URL', async () => {
      // GIVEN
      let capturedUrl: string | undefined;
      mockOAuth2Client.handleServerResponse = async (_status, _headers, _method, url) => {
        capturedUrl = url;
        return undefined;
      };

      const response: AxiosResponse = {
        status: 200,
        data: {},
        headers: {},
        config: {
          method: 'GET',
          url: 'https://different-api.com/resource',
          headers: {} as any
        }
      } as any;

      // WHEN
      await responseInterceptor(response);

      // THEN
      expect(capturedUrl).toBe('https://different-api.com/resource');
    });

    it('should throw error when method is undefined', async () => {
      // GIVEN
      const response: AxiosResponse = {
        status: 200,
        data: {},
        headers: {},
        config: {
          url: '/resource',
          headers: {} as any
        } as any
      } as any;

      // WHEN & THEN
      await expect(responseInterceptor(response)).rejects.toThrow('HTTP method not defined');
    });

    it('should convert headers to record format', async () => {
      // GIVEN
      let capturedHeaders: any;
      mockOAuth2Client.handleServerResponse = async (_status, headers) => {
        capturedHeaders = headers;
        return undefined;
      };

      const response: AxiosResponse = {
        status: 200,
        data: {},
        headers: {
          'content-type': 'application/json',
          'dpop-nonce': 'nonce'
        },
        config: {
          method: 'GET',
          url: '/resource',
          headers: {} as any
        }
      } as any;

      // WHEN
      await responseInterceptor(response);

      // THEN
      expect(capturedHeaders['content-type']).toBe('application/json');
      expect(capturedHeaders['dpop-nonce']).toBe('nonce');
    });
  });

  describe('error interceptor', () => {
    it('should call delegate onErrorResponse with correct parameters', async () => {
      // GIVEN
      let capturedParams: any;

      // Create fresh mock OAuth2Client for this test
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

      // Re-register interceptors with fresh client (reuse shared mockAxiosInstance)
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(testOAuth2Client, mockAxiosInstance, options);

      const config = {
        method: 'GET',
        url: '/resource',
        headers: {} as any
      };

      const response = {
        status: 401,
        statusText: 'Unauthorized',
        data: {},
        headers: { 'www-authenticate': 'DPoP error="use_dpop_nonce"' },
        config
      } as any;

      const error = new AxiosError('Request failed', 'ERR_BAD_REQUEST', config, null, response);

      // WHEN
      await errorInterceptor(error).catch(() => {});

      // THEN
      expect(capturedParams).toBeDefined();
      expect(capturedParams.status).toBe(401);
      expect(capturedParams.method).toBe('GET');
      expect(capturedParams.headers['www-authenticate']).toBe('DPoP error="use_dpop_nonce"');
    });

    it('should reject error when no retry headers returned', async () => {
      // GIVEN
      mockOAuth2Client.handleServerResponse = async () => undefined;

      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      const error: AxiosError = {
        name: 'AxiosError',
        message: 'Request failed',
        isAxiosError: true,
        config: {
          method: 'GET',
          url: '/resource',
          headers: {} as any
        },
        response: {
          status: 404,
          statusText: 'Not Found',
          data: {},
          headers: {},
          config: {
            method: 'GET',
            url: '/resource',
            headers: {} as any
          }
        },
        toJSON: () => ({})
      } as any;

      // WHEN & THEN
      await expect(errorInterceptor(error)).rejects.toBe(error);
    });

    it('should handle error response status codes', async () => {
      // GIVEN
      mockOAuth2Client.handleServerResponse = async () => undefined;

      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      const error: AxiosError = {
        name: 'AxiosError',
        message: 'Request failed',
        isAxiosError: true,
        config: {
          method: 'GET',
          url: '/resource',
          headers: {} as any
        },
        response: {
          status: 500,
          statusText: 'Internal Server Error',
          data: {},
          headers: {},
          config: {
            method: 'GET',
            url: '/resource',
            headers: {} as any
          }
        },
        toJSON: () => ({})
      } as any;

      // WHEN & THEN
      await expect(errorInterceptor(error)).rejects.toBe(error);
    });

    it('should reject non-Axios errors', async () => {
      // GIVEN
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      const error = new Error('Generic error');

      // WHEN & THEN
      await expect(errorInterceptor(error)).rejects.toBe(error);
    });

    it('should handle different error status codes', async () => {
      // GIVEN
      const statusCodes = [400, 401, 403, 500, 502];
      mockOAuth2Client.handleServerResponse = async () => undefined;

      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      // WHEN & THEN
      for (const status of statusCodes) {
        const error: AxiosError = {
          name: 'AxiosError',
          message: 'Request failed',
          isAxiosError: true,
          config: {
            method: 'GET',
            url: '/resource',
            headers: {} as any
          },
          response: {
            status,
            data: {},
            headers: {},
            config: {
              method: 'GET',
              url: '/resource',
              headers: {} as any
            }
          },
          toJSON: () => ({})
        } as any;

        await expect(errorInterceptor(error)).rejects.toBe(error);
      }
    });

    it('should handle headers with null and undefined values', async () => {
      // GIVEN
      let capturedHeaders: any;

      // Create fresh mock OAuth2Client for this test
      const testOAuth2Client: OAuth2Client & { getLogger: () => Logger } = {
        getOAuth2Headers: async () => ({
          Authorization: 'DPoP test-token',
          DPoP: 'test-dpop-proof'
        }),
        handleServerResponse: async (
          _status: number,
          headers: Record<string, string>,
          _method: string,
          _url: string,
          _isError?: boolean
        ) => {
          capturedHeaders = headers;
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

      // Re-register interceptors with fresh client (reuse shared mockAxiosInstance)
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(testOAuth2Client, mockAxiosInstance, options);

      const config = {
        method: 'GET',
        url: '/resource',
        headers: {} as any
      };

      const response = {
        status: 401,
        data: {},
        headers: {
          'valid-header': 'value',
          'null-header': null,
          'undefined-header': undefined
        },
        config
      } as any;

      const error = new AxiosError('Request failed', 'ERR_BAD_REQUEST', config, null, response);

      // WHEN
      await errorInterceptor(error).catch(() => {});

      // THEN
      expect(capturedHeaders).toBeDefined();
      expect(capturedHeaders['valid-header']).toBe('value');
      expect(capturedHeaders['null-header']).toBeUndefined();
      expect(capturedHeaders['undefined-header']).toBeUndefined();
    });
  });

  describe('input validation', () => {
    it('should handle empty baseURL', () => {
      // GIVEN
      const options: AxiosOptions = {
        baseURL: ''
      };

      // WHEN & THEN - should not throw
      expect(() => withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options)).not.toThrow();
    });

    it('should handle baseURL with trailing slash', async () => {
      // GIVEN
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com/'
      };
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      let capturedUrl: string | undefined;
      mockOAuth2Client.getOAuth2Headers = async (_method: string, url: string) => {
        capturedUrl = url;
        return { Authorization: 'Bearer token' };
      };

      const config: InternalAxiosRequestConfig = {
        method: 'GET',
        url: '/resource',
        headers: {} as any
      };

      // WHEN
      await requestInterceptor(config);

      // THEN
      expect(capturedUrl).toBe('https://api.example.com/resource');
    });

    it('should handle empty URL in config', async () => {
      // GIVEN
      const options: AxiosOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Axios(mockOAuth2Client, mockAxiosInstance, options);

      const config: InternalAxiosRequestConfig = {
        method: 'GET',
        url: '',
        headers: {} as any
      };

      // WHEN
      const result = await requestInterceptor(config);

      // THEN
      expect(result.headers['Authorization']).toBeDefined();
    });
  });
});
