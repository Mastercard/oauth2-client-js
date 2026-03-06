import { expect } from '@jest/globals';
import { IMockServer } from './mock-server';

function decodeJWT(jwt: string): any {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT');
  }
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
}

export function assertTokenEndpointCall(
  server: IMockServer,
  callIndex: number,
  expectations: {
    hasDPoPNonce?: boolean;
    nonce?: string;
  }
) {
  const tokenLogs = server.getTokenRequestLogs();
  expect(tokenLogs.length).toBeGreaterThan(callIndex);

  const log = tokenLogs[callIndex];

  if (expectations.hasDPoPNonce !== undefined) {
    expect(log.hasDPoPNonce).toBe(expectations.hasDPoPNonce);
  }

  if (expectations.nonce !== undefined) {
    const dpopJwt = log.headers['dpop']?.toString();
    expect(dpopJwt).toBeDefined();
    const payload = decodeJWT(dpopJwt!);
    expect(payload.nonce).toBe(expectations.nonce);
  }
}

export function assertResourceServerCall(
  server: IMockServer,
  callIndex: number,
  expectations: {
    url?: string;
    hasAuthorization?: boolean;
    hasDPoP?: boolean;
    dpopNonce?: string;
    accessToken?: string;
  }
) {
  const resourceLogs = server.getResourceRequestLogs();
  expect(resourceLogs.length).toBeGreaterThan(callIndex);

  const log = resourceLogs[callIndex];

  if (expectations.url !== undefined) {
    expect(log.url).toBe(expectations.url);
  }

  if (expectations.hasAuthorization !== undefined) {
    if (expectations.hasAuthorization) {
      expect(log.authorization).toBeDefined();
    } else {
      expect(log.authorization).toBeUndefined();
    }
  }

  if (expectations.hasDPoP !== undefined) {
    if (expectations.hasDPoP) {
      expect(log.dpop).toBeDefined();
    } else {
      expect(log.dpop).toBeUndefined();
    }
  }

  if (expectations.dpopNonce !== undefined) {
    expect(log.dpop).toBeDefined();
    const payload = decodeJWT(log.dpop!);
    expect(payload.nonce).toBe(expectations.dpopNonce);
  }

  if (expectations.accessToken !== undefined) {
    expect(log.authorization).toBeDefined();
    expect(log.authorization).toContain(expectations.accessToken);
  }
}

export function assertCallOrder(server: IMockServer, expectedOrder: Array<'token' | 'resource'>) {
  const mergedCalls = server.getMergedCallOrder();
  const actualOrder = mergedCalls.map(call => call.type);

  expect(actualOrder).toEqual(expectedOrder);
}
