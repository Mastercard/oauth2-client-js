import { afterAll, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { MockServer } from '#mock-server/mock-server';
import { TestTokenStore } from '#mock-server/test-stores';
import { assertCallOrder, assertResourceServerCall, assertTokenEndpointCall } from '#mock-server/test-helpers';
import {
  AxiosDecorator,
  FetchDecorator,
  OpenApiAxiosDecorator,
  OpenApiFetchDecorator,
  OpenApiJavascriptDecorator,
  SuperAgentDecorator
} from '#mock-server/test-client-adapters';

/**
 * Integration tests for OAuth2 (FAPI 2.0) DPoP nonce flow scenarios
 * Testing token and nonce expiration handling across the complete flow
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
])('[$name] OAuth2 DPoP Nonce Scenarios', ({ clientDecorator }) => {
  let server: MockServer;
  let tokenStore: TestTokenStore;

  beforeAll(async () => {
    server = new MockServer();
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    tokenStore = new TestTokenStore();
    server.reset();
  });

  it('Initial flow with token expiration and cached nonce reuse', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(server, server, tokenStore);

    // [WHEN] Client makes resource request
    const response1 = await client.getPets();

    // [THEN] Assert initial token endpoint flow
    // First token request without DPoP nonce → 400
    assertTokenEndpointCall(server, 0, { hasDPoPNonce: false });
    expect(server.getTokenRequestLogs()[0].requestNumber).toBe(1);

    // Second token request with nonce → 200
    assertTokenEndpointCall(server, 1, {
      hasDPoPNonce: true,
      nonce: server.getDPoPNonce()
    });
    expect(server.getTokenRequestLogs()[1].requestNumber).toBe(2);

    // [THEN] Resource server receives request with valid access token and nonce
    const resourceLogs1 = server.getResourceRequestLogs();
    expect(resourceLogs1.length).toBe(1);
    assertResourceServerCall(server, 0, {
      url: '/pets',
      hasAuthorization: true,
      hasDPoP: true,
      dpopNonce: server.getDPoPNonce(),
      accessToken: 'mock-access-token-2'
    });

    // [THEN] Resource server returns 200
    expect(response1.status).toBe(200);
    expect(response1.data.count).toBe(2);

    // [THEN] Verify call order
    assertCallOrder(server, ['token', 'token', 'resource']);

    // [WHEN] Access token expires locally (nonce still valid)
    const jkt = await client.getJkt();
    tokenStore.expireToken(jkt, new Set(['read:pets']));

    // [WHEN] Client makes another resource request
    const response2 = await client.getPets();

    // [THEN] Auth server receives token request with cached nonce
    const tokenLogs2 = server.getTokenRequestLogs();
    expect(tokenLogs2.length).toBe(3); // Previous 2 + 1 new
    assertTokenEndpointCall(server, 2, {
      hasDPoPNonce: true,
      nonce: server.getDPoPNonce()
    });

    // [THEN] Auth server returns 200 with new access token
    expect(tokenLogs2[2].requestNumber).toBe(3);

    // [THEN] Interceptor requests /pets with latest access token and valid nonce
    const resourceLogs2 = server.getResourceRequestLogs();
    expect(resourceLogs2.length).toBe(2);
    assertResourceServerCall(server, 1, {
      url: '/pets',
      hasAuthorization: true,
      hasDPoP: true,
      dpopNonce: server.getDPoPNonce(),
      accessToken: 'mock-access-token-3'
    });

    expect(response2.status).toBe(200);
    expect(response2.data.count).toBe(2);

    // [THEN] Verify call order
    assertCallOrder(server, ['token', 'token', 'resource', 'token', 'resource']);
  });

  it('Both nonce and access token cached (cache hit)', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(server, server, tokenStore);

    // [WHEN] resource server call
    const response1 = await client.getPets();

    // [THEN] Verify initial flow completed
    expect(response1.status).toBe(200);
    expect(server.getTokenRequestLogs().length).toBe(2);
    expect(server.getResourceRequestLogs().length).toBe(1);

    // [WHEN] Both nonce and access token are still valid in cache
    // Client makes another getPets() request
    const response2 = await client.getPets();

    // [THEN] Resource server returns 200 (no token endpoint called)
    expect(response2.status).toBe(200);
    expect(response2.data.count).toBe(2);

    // Verify no additional token requests were made
    expect(server.getTokenRequestLogs().length).toBe(2);

    // Verify resource server was called again
    expect(server.getResourceRequestLogs().length).toBe(2);
    assertResourceServerCall(server, 1, {
      url: '/pets',
      hasAuthorization: true,
      hasDPoP: true,
      dpopNonce: server.getDPoPNonce() // Uses resource server nonce from previous response
    });

    // [THEN] Verify call order (no new token requests)
    assertCallOrder(server, ['token', 'token', 'resource', 'resource']);
  });

  it('Nonce rejected but access token valid', async () => {
    // [GIVEN]
    const client = await clientDecorator.build(server, server, tokenStore);

    // [WHEN] Resource server request
    const response1 = await client.getPets();

    // [THEN] Verify initial flow completed
    expect(response1.status).toBe(200);
    expect(server.getTokenRequestLogs().length).toBe(2);
    expect(server.getResourceRequestLogs().length).toBe(1);

    // [WHEN] Server rejects the nonce
    // Enable resource server to simulate nonce error on first call
    server.enableSimulateNonceError(true, 1);

    // [WHEN] Client makes resource request
    const response2 = await client.getPets();

    // [THEN] Resource server returns 401 with use_dpop_nonce error and new nonce
    const resourceLogs = server.getResourceRequestLogs();
    expect(resourceLogs.length).toBe(3); // Initial + error + retry

    // First request gets 401
    expect(resourceLogs[1].url).toBe('/pets');

    // [THEN] Interceptor retries resource request with the new nonce
    // The third request should have the new resource server nonce
    assertResourceServerCall(server, 2, {
      url: '/pets',
      hasAuthorization: true,
      hasDPoP: true,
      dpopNonce: server.getDPoPNonce()
    });

    // [THEN] Resource server returns 200
    expect(response2.status).toBe(200);
    expect(response2.data.count).toBe(2);

    // No new token requests should have been made (token still valid)
    expect(server.getTokenRequestLogs().length).toBe(2);

    // [THEN] Verify call order
    assertCallOrder(server, ['token', 'token', 'resource', 'resource', 'resource']);
  });
});
