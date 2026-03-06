import { afterAll, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import {
  AxiosDecorator,
  FetchDecorator,
  OpenApiAxiosDecorator,
  OpenApiFetchDecorator,
  OpenApiJavascriptDecorator,
  SuperAgentDecorator
} from '#mock-server/test-client-adapters';
import { MockServer } from '#mock-server/mock-server';

/**
 * Tests OAuth2.0 with DPoP nonce flow across 6 different HTTP client adapters
 * (axios, fetch, superagent, openapi-javascript, openapi-axios, openapi-fetch)
 */
describe.each([
  {
    name: 'axios',
    clientDecorator: new AxiosDecorator()
  },
  {
    name: 'fetch',
    clientDecorator: new FetchDecorator()
  },
  {
    name: 'superagent',
    clientDecorator: new SuperAgentDecorator()
  },
  {
    name: 'openapi-superagent',
    clientDecorator: new OpenApiJavascriptDecorator()
  },
  {
    name: 'openapi-axios',
    clientDecorator: new OpenApiAxiosDecorator()
  },
  {
    name: 'openapi-fetch',
    clientDecorator: new OpenApiFetchDecorator()
  }
])('[$name] OAuth2.0 with DPoP Nonce Flow', ({ clientDecorator }) => {
  let authServer: MockServer;
  let resourceServer: MockServer;

  const newDog = {
    color: '',
    dogProperty2: {},
    gender: '',
    status: undefined,
    name: 'Rex',
    breed: 'German Shepherd'
  };

  beforeAll(async () => {
    authServer = new MockServer();
    resourceServer = new MockServer();

    await authServer.start();
    await resourceServer.start();
  });

  afterAll(async () => {
    await authServer.stop();
    await resourceServer.stop();
  });

  beforeEach(() => {
    authServer.reset();
    resourceServer.reset();
  });

  it('should make /pets requests successfully', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    const pets = await client.getPets();

    // [THEN]
    expect(pets.data.count).toBe(2);
  });

  it('should make /pets and subsequent /dogs requests successfully', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    const pets = await client.getPets();
    const dog = await client.addDog(newDog);

    // [THEN]
    expect(pets.data.count).toBe(2);
    expect(dog.data.id).toBe('3');
  });

  it('should make initial request to token endpoint when calling resource server', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    const pets = await client.getPets();

    // [THEN] - token endpoint should be called
    const tokenLogs = authServer.getTokenRequestLogs();
    expect(tokenLogs.length).toBe(2);
    expect(authServer.getTokenRequestCount()).toBe(2);
    expect(pets.data.count).toBe(2);
  });

  it('should make only 1 request to token endpoint when calling resource server and nonce is valid in cache', async () => {
    // [GIVEN] - Create a token store that doesn't persist tokens to force new token requests each time
    const nonCachingTokenStore = {
      get: async () => undefined,
      put: async () => {}
    };
    const client = await clientDecorator.build(authServer, resourceServer, nonCachingTokenStore);
    // Make first request (cache nonce in the client)
    await client.getPets();
    const tokenRequests = authServer.getTokenRequestCount();
    expect(tokenRequests).toBe(2); // nonce challenge + token request with nonce

    // [WHEN] - Make second request (token not in store, nonce cached)
    await client.getPets();

    // [THEN] - token endpoint should be called only once
    expect(authServer.getTokenRequestCount() - tokenRequests).toBe(1);
  });

  it('should receive use_dpop_nonce error on first token request and retry with nonce', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    await client.getPets();

    // [THEN]
    const tokenLogs = authServer.getTokenRequestLogs();

    // First request should not have DPoP nonce
    expect(tokenLogs[0].hasDPoPNonce).toBe(false);

    // Second request should have DPoP nonce (retry after error)
    expect(tokenLogs.length).toBe(2);
    expect(tokenLogs[1].hasDPoPNonce).toBe(true);

    // Verify DPoP header is present in subsequent requests
    expect(tokenLogs[1].headers['dpop']).toBeDefined();

    // Decode JWT to verify nonce is present
    const dpopJwt = tokenLogs[1].headers['dpop']?.toString();
    const parts = dpopJwt!.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    expect(payload.nonce).toBe(authServer.getDPoPNonce());
  });

  it('should call resource server with access token after successful token request', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    const result = (await client.getPets()).data;

    // [THEN]
    const resourceLogs = resourceServer.getResourceRequestLogs();

    // Resource server should be called
    expect(resourceLogs.length).toBe(1);

    // Request should have Authorization header
    expect(resourceLogs[0].authorization).toBeDefined();
    expect(resourceLogs[0].authorization).toContain('DPoP');
    expect(resourceLogs[0].authorization).toContain('mock-access-token');

    // Request should have DPoP header
    expect(resourceLogs[0].dpop).toBeDefined();

    // Response should contain pets
    expect(result.data).toBeDefined();
    expect(result.data.length).toBe(2);
  });

  it('should reuse the same token for subsequent requests with same scope', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    await client.getPets();

    // [THEN]
    const firstTokenCount = authServer.getTokenRequestCount();
    const firstResourceLogs = resourceServer.getResourceRequestLogs();
    const firstAuthHeader = firstResourceLogs[0].authorization;

    await client.getPets();
    const secondTokenCount = authServer.getTokenRequestCount();
    const secondResourceLogs = resourceServer.getResourceRequestLogs();
    const secondAuthHeader = secondResourceLogs[1].authorization;

    // Token endpoint should not be called again for the second resource request
    expect(secondTokenCount).toBe(firstTokenCount);

    // Both requests should use the same access token
    expect(firstAuthHeader).toBe(secondAuthHeader);

    // Resource server should be called twice
    expect(secondResourceLogs.length).toBe(2);
  });

  it('should cache resource server DPoP nonce and use it in subsequent requests', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    await client.getPets();

    // [THEN]
    const firstResourceLogs = resourceServer.getResourceRequestLogs();
    const firstDPoPProof = firstResourceLogs[0].dpop;

    await client.getPets();
    const secondResourceLogs = resourceServer.getResourceRequestLogs();
    const secondDPoPProof = secondResourceLogs[1].dpop;

    // Both requests should have DPoP proofs
    expect(firstDPoPProof).toBeDefined();
    expect(secondDPoPProof).toBeDefined();

    // Second DPoP proof should include the nonce from resource server
    // Decode JWT to check nonce
    const parts = secondDPoPProof!.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    expect(payload.nonce).toBe(resourceServer.getDPoPNonce());
  });

  it('should handle complete flow: token request with nonce retry, then resource request', async () => {
    // [GIVEN]
    const decorator = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    const result = (await decorator.getPets()).data;

    // [THEN]
    const tokenLogs = authServer.getTokenRequestLogs();
    const resourceLogs = resourceServer.getResourceRequestLogs();

    // Token endpoint should be called twice (initial + nonce retry)
    expect(tokenLogs.length).toBe(2);

    // First token request should fail with use_dpop_nonce
    expect(tokenLogs[0].hasDPoPNonce).toBe(false);

    // Second token request should include nonce
    expect(tokenLogs[1].hasDPoPNonce).toBe(true);

    // Resource server should be called once
    expect(resourceLogs.length).toBe(1);

    // Resource request should have both Authorization and DPoP headers
    expect(resourceLogs[0].authorization).toBeDefined();
    expect(resourceLogs[0].dpop).toBeDefined();

    // Result should contain valid data
    expect(result.data).toBeDefined();
    expect(result.data.length).toBe(2);
    expect(result.data[0].name).toBe('Fluffy');
  });

  it('should retry resource server request on nonce error', async () => {
    // [GIVEN]
    resourceServer.enableSimulateNonceError(true);
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN]
    await client.getPets();

    // [THEN] - token endpoint should be called
    const tokenLogs = authServer.getTokenRequestLogs();
    expect(tokenLogs.length).toBe(2);
    expect(authServer.getTokenRequestCount()).toBe(2);
  });

  it('should have consistent handleServerResponse execution flow for nonce error retry', async () => {
    // [GIVEN]
    resourceServer.enableSimulateNonceError(true);
    const client = await clientDecorator.build(authServer, resourceServer);

    // [WHEN] - Make first request (nonce error and retry)
    await client.getPets();

    // [THEN]
    let resourceLogs = resourceServer.getResourceRequestLogs();
    expect(resourceLogs.length).toBe(2);
    expect(resourceLogs[0].url).toBe('/pets'); // First attempt - gets 401 nonce error
    expect(resourceLogs[1].url).toBe('/pets'); // Retry - succeeds with 200

    // Extract nonce from the successful retry response
    const retryDPoPProof = resourceLogs[1].dpop;
    expect(retryDPoPProof).toBeDefined();
    const parts = retryDPoPProof!.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    const cachedNonce = payload.nonce;
    expect(cachedNonce).toBeDefined();

    // [WHEN] - Make second request
    await client.getPets();

    // [THEN] - (no retry needed, nonce was cached)
    resourceLogs = resourceServer.getResourceRequestLogs();
    expect(resourceLogs.length).toBe(3); // 2 from first request + 1 from second request

    // Validate the third call has the cached nonce
    const secondRequestDPoP = resourceLogs[2].dpop;
    expect(secondRequestDPoP).toBeDefined();
    const secondParts = secondRequestDPoP!.split('.');
    const secondPayload = JSON.parse(Buffer.from(secondParts[1], 'base64url').toString('utf-8'));

    // should use the cached nonce
    expect(secondPayload.nonce).toBe(resourceServer.getDPoPNonce());
  });

  it('should allow client to receive server error response when getOAuth2Headers fails', async () => {
    // [GIVEN]
    const failingTokenStore = {
      get: async () => {
        throw new Error('Token store unavailable');
      },
      put: async () => {
        throw new Error('Token store unavailable');
      }
    };

    // Build client with failing token store
    const client = await clientDecorator.build(authServer, resourceServer, failingTokenStore);

    // [WHEN] - Make request (getOAuth2Headers will fail due to TokenStore error)
    let result: any;
    let caughtError: any;
    try {
      result = await client.getPets();
    } catch (error) {
      caughtError = error;
    }

    // [THEN] - Verify resource server was called without OAuth2 headers
    const resourceLogs = resourceServer.getResourceRequestLogs();
    expect(resourceLogs.length).toBe(1);
    expect(resourceLogs[0].authorization).toBeUndefined(); // auth header should be missing

    // Different clients handle errors differently:
    // - axios, openapi-axios: errors on 4xx status
    // - fetch, superagent, openapi-fetch, openapi-superagent: return the response normally
    if (caughtError) {
      if (caughtError.response && caughtError.response.data) {
        expect(caughtError.response.status).toBe(400);
        expect(caughtError.response.data.Errors.Error[0].ReasonCode).toBe('INVALID_AUTH_HEADER');
        expect(caughtError.response.data.Errors.Error[0].Description).toBe(
          'Bad Request - No Authorization header set.'
        );
      } else if (caughtError.response) {
        expect(caughtError.response.status).toBe(400);
      } else {
        expect(caughtError).toBeDefined();
      }
    } else {
      expect(result).toBeDefined();
      expect(result.status).toBe(400);
      expect(result.data.Errors.Error[0].ReasonCode).toBe('INVALID_AUTH_HEADER');
      expect(result.data.Errors.Error[0].Description).toBe('Bad Request - No Authorization header set.');
    }
  });
});
