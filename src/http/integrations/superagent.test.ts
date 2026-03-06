import { beforeEach, describe, expect, it } from '@jest/globals';
import type { Logger } from '#types';
import type { OAuth2Client } from '#core/client';
import {
  createOAuth2SuperagentPlugin,
  type SuperAgentOptions,
  withOAuth2Superagent
} from '#http/integrations/superagent';
import type { Response, SuperAgentRequest } from 'superagent';

describe('withOAuth2Superagent', () => {
  let mockOAuth2Client: OAuth2Client & { getLogger: () => Logger };
  let mockSuperagentInstance: any;
  let mockRequests: SuperAgentRequest[];

  beforeEach(() => {
    mockRequests = [];

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

    // Create mock superagent instance
    mockSuperagentInstance = {
      use: (plugin: any) => {
        // Store plugin but don't execute it yet
        if (!mockSuperagentInstance._plugins) {
          mockSuperagentInstance._plugins = [];
        }
        mockSuperagentInstance._plugins.push(plugin);
        return mockSuperagentInstance;
      },
      get: (url: string) => createMockRequest('GET', url),
      post: (url: string) => createMockRequest('POST', url),
      put: (url: string) => createMockRequest('PUT', url),
      patch: (url: string) => createMockRequest('PATCH', url),
      delete: (url: string) => createMockRequest('DELETE', url),
      head: (url: string) => createMockRequest('HEAD', url),
      options: (url: string) => createMockRequest('OPTIONS', url)
    };

    function createMockRequest(method: string, url: string): SuperAgentRequest {
      // noinspection JSUnusedGlobalSymbols
      const mockRequest: any = {
        method,
        url,
        header: {},
        headers: {},
        _data: null,
        qs: null,
        _timeout: null,
        set: function (key: string, value: string) {
          this.header[key] = value;
          return this;
        },
        send: function (data: any) {
          this._data = data;
          return this;
        },
        query: function (params: any) {
          this.qs = params;
          return this;
        },
        timeout: function (ms: number) {
          this._timeout = ms;
          return this;
        },
        then: async function (onfulfilled?: any, _onRejected?: any) {
          const response: Response = {
            status: 200,
            headers: { 'content-type': 'application/json' },
            body: { success: true }
          } as any;

          mockRequests.push(this);

          if (onfulfilled) {
            return onfulfilled(response);
          }
          return response;
        },
        end: function (callback?: any) {
          mockRequests.push(this);
          if (callback) {
            const response: Response = {
              status: 200,
              headers: { 'content-type': 'application/json' },
              body: { success: true }
            } as any;
            callback(null, response);
          }
          return this;
        }
      };

      // Apply plugins immediately after creating the request (matches real SuperAgent behavior)
      if (mockSuperagentInstance._plugins) {
        mockSuperagentInstance._plugins.forEach((plugin: any) => {
          plugin(mockRequest);
        });
      }

      return mockRequest as SuperAgentRequest;
    }
  });

  describe('integration setup', () => {
    it('should return superagent instance', () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };

      // WHEN
      const result = withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // THEN
      expect(result).toBe(mockSuperagentInstance);
    });

    it('should register interceptors using use()', () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };

      // WHEN
      withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // THEN
      expect(mockSuperagentInstance._plugins).toBeDefined();
      expect(mockSuperagentInstance._plugins.length).toBe(2);
    });

    it('should wrap HTTP methods with baseURL', () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      const request = mockSuperagentInstance.get('/resource');

      // THEN
      expect(request.url).toBe('https://api.example.com/resource');
    });
  });

  describe('request handling', () => {
    it('should handle GET requests', async () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      const agent = withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      await agent.get('/resource');

      // THEN
      expect(mockRequests.length).toBeGreaterThan(0);
    });

    it('should handle POST requests', async () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      const agent = withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      await agent.post('/resource').send({ data: 'test' });

      // THEN
      expect(mockRequests.length).toBeGreaterThan(0);
    });

    it('should handle absolute URLs', () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      const request = mockSuperagentInstance.get('https://other-api.com/resource');

      // THEN
      expect(request.url).toBe('https://other-api.com/resource');
    });

    it('should build full URL from baseURL and relative path', () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      const request = mockSuperagentInstance.post('/api/data');

      // THEN
      expect(request.url).toBe('https://api.example.com/api/data');
    });

    it('should handle baseURL with trailing slash', () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com/'
      };
      withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      const request = mockSuperagentInstance.get('/resource');

      // THEN
      expect(request.url).toBe('https://api.example.com/resource');
    });
  });

  describe('callback-based API', () => {
    it('should handle callback-based requests with end()', done => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      const agent = withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      agent.get('/resource').end((err, res) => {
        // THEN
        expect(err).toBeNull();
        expect(res.status).toBe(200);
        done();
      });
    });
  });

  describe('HTTP methods', () => {
    it('should wrap all HTTP methods', () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN & THEN
      const methods = ['get', 'post', 'put', 'delete', 'patch'];
      methods.forEach(method => {
        const request = mockSuperagentInstance[method]('/test');
        expect(request.url).toBe('https://api.example.com/test');
      });
    });
  });

  describe('error handling', () => {
    it('should handle 4xx error responses in promise API', async () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };

      // Mock to return 401 error
      mockSuperagentInstance._plugins = [];
      const errorAgent = withOAuth2Superagent(
        mockOAuth2Client,
        {
          ...mockSuperagentInstance,
          get: (url: string) => {
            const mockRequest: any = {
              method: 'GET',
              url,
              header: {},
              headers: {},
              set: function (key: string, value: string) {
                this.header[key] = value;
                return this;
              },
              then: async function (onfulfilled?: any, _onRejected?: any) {
                if (mockSuperagentInstance._plugins) {
                  mockSuperagentInstance._plugins.forEach((plugin: any) => {
                    plugin(this);
                  });
                }

                const response: any = {
                  status: 401,
                  headers: { 'www-authenticate': 'DPoP error="use_dpop_nonce"' },
                  body: {}
                };

                mockRequests.push(this);

                if (onfulfilled) {
                  return onfulfilled(response);
                }
                return response;
              }
            };
            return mockRequest;
          }
        } as any,
        options
      );

      // WHEN
      const response = await errorAgent.get('/resource');

      // THEN
      expect(response.status).toBe(401);
    });

    it('should handle errors without response property', async () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };

      const errorAgent = withOAuth2Superagent(
        mockOAuth2Client,
        {
          ...mockSuperagentInstance,
          get: (url: string) => {
            const mockRequest: any = {
              method: 'GET',
              url,
              header: {},
              headers: {},
              set: function (key: string, value: string) {
                this.header[key] = value;
                return this;
              },
              then: async function (_onfulfilled?: any, onRejected?: any) {
                if (mockSuperagentInstance._plugins) {
                  mockSuperagentInstance._plugins.forEach((plugin: any) => {
                    plugin(this);
                  });
                }

                // Throw error without response property (network error)
                const error = new Error('Network error');
                mockRequests.push(this);

                if (onRejected) {
                  return onRejected(error);
                }
                throw error;
              }
            };
            return mockRequest;
          }
        } as any,
        options
      );

      // WHEN & THEN
      await expect(errorAgent.get('/resource')).rejects.toThrow('Network error');
    });

    it('should handle errors in callback-based API', done => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };

      const errorAgent = withOAuth2Superagent(
        mockOAuth2Client,
        {
          ...mockSuperagentInstance,
          get: (url: string) => {
            const mockRequest: any = {
              method: 'GET',
              url,
              header: {},
              headers: {},
              set: function (key: string, value: string) {
                this.header[key] = value;
                return this;
              },
              end: function (callback?: any) {
                mockRequests.push(this);
                if (callback) {
                  const error = new Error('Request failed');
                  callback(error, null);
                }
                return this;
              }
            };
            return mockRequest;
          }
        } as any,
        options
      );

      // WHEN
      errorAgent.get('/resource').end((err, _res) => {
        // THEN
        expect(err).toBeDefined();
        expect(err.message).toBe('Request failed');
        done();
      });
    });

    it('should handle 4xx errors in callback-based API', done => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };

      const errorAgent = withOAuth2Superagent(
        mockOAuth2Client,
        {
          ...mockSuperagentInstance,
          get: (url: string) => {
            const mockRequest: any = {
              method: 'GET',
              url,
              header: {},
              headers: {},
              set: function (key: string, value: string) {
                this.header[key] = value;
                return this;
              },
              end: function (callback?: any) {
                mockRequests.push(this);
                if (callback) {
                  const response: any = {
                    status: 403,
                    headers: {},
                    body: {}
                  };
                  callback(null, response);
                }
                return this;
              }
            };
            return mockRequest;
          }
        } as any,
        options
      );

      // WHEN
      errorAgent.get('/resource').end((err, res) => {
        // THEN
        expect(err).toBeNull();
        expect(res.status).toBe(403);
        done();
      });
    });
  });

  describe('input validation', () => {
    it('should handle empty baseURL', () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: ''
      };

      // WHEN & THEN - should not throw
      expect(() => withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options)).not.toThrow();
    });

    it('should preserve request headers', async () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      const agent = withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      await agent.get('/resource').set('X-Custom', 'value');

      // THEN
      expect(mockRequests.length).toBeGreaterThan(0);
      const request = mockRequests[0];
      expect((request as any).header['X-Custom']).toBe('value');
    });

    it('should handle query parameters', async () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      const agent = withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      await agent.get('/resource').query({ param: 'value' });

      // THEN
      expect(mockRequests.length).toBeGreaterThan(0);
      const request = mockRequests[0];
      expect((request as any).qs).toEqual({ param: 'value' });
    });

    it('should handle request body', async () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      const agent = withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      await agent.post('/resource').send({ data: 'test' });

      // THEN
      expect(mockRequests.length).toBeGreaterThan(0);
      const request = mockRequests[0];
      expect((request as any)._data).toEqual({ data: 'test' });
    });

    it('should handle timeout', async () => {
      // GIVEN
      const options: SuperAgentOptions = {
        baseURL: 'https://api.example.com'
      };
      const agent = withOAuth2Superagent(mockOAuth2Client, mockSuperagentInstance, options);

      // WHEN
      await agent.get('/resource').timeout(5000);

      // THEN
      expect(mockRequests.length).toBeGreaterThan(0);
      const request = mockRequests[0];
      expect((request as any)._timeout).toBe(5000);
    });
  });
});

describe('createOAuth2SuperagentPlugin', () => {
  let mockOAuth2Client: OAuth2Client & { getLogger: () => Logger };

  beforeEach(() => {
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
  });

  it('should create plugin function', () => {
    // GIVEN
    const options: SuperAgentOptions = {
      baseURL: 'https://api.example.com'
    };

    // WHEN
    const plugin = createOAuth2SuperagentPlugin(mockOAuth2Client, options);

    // THEN
    expect(typeof plugin).toBe('function');
  });

  it('should modify request URL with baseURL', () => {
    // GIVEN
    const options: SuperAgentOptions = {
      baseURL: 'https://api.example.com'
    };
    const plugin = createOAuth2SuperagentPlugin(mockOAuth2Client, options);

    const mockRequest: any = {
      method: 'GET',
      url: '/resource',
      header: {},
      end: (callback: any) => callback && callback(null, { status: 200 })
    };

    // WHEN
    plugin(mockRequest);

    // THEN
    expect(mockRequest.url).toBe('https://api.example.com/resource');
  });

  it('should not modify absolute URLs', () => {
    // GIVEN
    const options: SuperAgentOptions = {
      baseURL: 'https://api.example.com'
    };
    const plugin = createOAuth2SuperagentPlugin(mockOAuth2Client, options);

    const mockRequest: any = {
      method: 'GET',
      url: 'https://other-api.com/resource',
      header: {},
      end: (callback: any) => callback && callback(null, { status: 200 })
    };

    // WHEN
    plugin(mockRequest);

    // THEN
    expect(mockRequest.url).toBe('https://other-api.com/resource');
  });
});
