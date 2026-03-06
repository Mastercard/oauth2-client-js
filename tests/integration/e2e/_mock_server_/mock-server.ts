import { setupServer, SetupServer } from 'msw/node';
import { http, HttpResponse, StrictRequest } from 'msw';

export interface IMockServer {
  start(): Promise<number>;
  stop(): Promise<void>;
  getUrl(): string;
  getCertificate(): { key: string; cert: string };
  reset(): void;
  getTokenRequestCount(): number;
  getTokenRequestLogs(): any[];
  getDPoPNonce(): string;
  setAlwaysRequireNonce(value: boolean): void;
  getResourceRequestLogs(): any[];
  enableSimulateNonceError(enable: boolean, times?: number): void;
  enableSimulateUnauthorizedError(enable: boolean, times?: number): void;
  getMergedCallOrder(): any[];
}

interface TokenRequestLog {
  timestamp: Date;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  hasDPoPNonce: boolean;
  requestNumber: number;
}

interface ResourceRequestLog {
  timestamp: Date;
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  authorization?: string;
  dpop?: string;
  requestNumber: number;
}

export class MockServer implements IMockServer {
  private server: SetupServer;
  private readonly baseUrl: string;
  private static instanceCount = 0;

  private tokenRequestCount = 0;
  private tokenRequestLogs: TokenRequestLog[] = [];
  private resourceRequestLogs: ResourceRequestLog[] = [];
  private dpopNonce = 'mock-server-nonce-12345';
  private resourceRequestCounter = 0;
  private alwaysRequireNonce = false;
  private simulateNonceError: boolean = false;
  private simulateNonceErrorTimes: number = 1;
  private resourceCalledCount = 0;
  private simulateUnauthorizedError: boolean = false;
  private simulateUnauthorizedErrorTimes: number = 1;
  private unauthorizedCalledCount = 0;

  constructor() {
    MockServer.instanceCount++;
    this.baseUrl = `https://mock-server-${MockServer.instanceCount}.test`;

    this.server = setupServer(
      http.post(`${this.baseUrl}/token`, ({ request }) => this.handleTokenRequest(request)),
      http.get(`${this.baseUrl}/pets`, ({ request }) => this.handleResourceRequest(request)),
      http.post(`${this.baseUrl}/dogs`, ({ request }) => this.handleResourceRequest(request))
    );
  }

  async start(): Promise<number> {
    this.server.listen({ onUnhandledRequest: 'bypass' });
    return 0;
  }

  async stop(): Promise<void> {
    this.server.close();
  }

  getUrl(): string {
    return this.baseUrl;
  }

  getCertificate(): { key: string; cert: string } {
    return { key: '', cert: '' };
  }

  reset(): void {
    this.server.resetHandlers();
    this.tokenRequestCount = 0;
    this.tokenRequestLogs = [];
    this.resourceRequestLogs = [];
    this.resourceRequestCounter = 0;
    this.simulateNonceError = false;
    this.resourceCalledCount = 0;
    this.simulateUnauthorizedError = false;
    this.unauthorizedCalledCount = 0;
  }

  private async handleTokenRequest(request: StrictRequest<any>): Promise<HttpResponse<any>> {
    this.tokenRequestCount++;
    const headers = this.extractHeaders(request);
    const body = await request.text();

    let hasDPoPNonce = false;
    const dpopHeader = headers['dpop']?.toString();
    if (dpopHeader) {
      try {
        const parts = dpopHeader.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
          hasDPoPNonce = payload.nonce === this.dpopNonce;
        }
      } catch (e) {
        // Invalid JWT, ignore
      }
    }

    this.tokenRequestLogs.push({
      timestamp: new Date(),
      headers,
      body,
      hasDPoPNonce,
      requestNumber: this.tokenRequestCount
    });

    if (this.tokenRequestCount === 1 && !this.alwaysRequireNonce) {
      return HttpResponse.json(
        {
          error: 'use_dpop_nonce',
          error_description: 'Authorization server requires nonce in DPoP proof'
        },
        { status: 400, headers: { 'DPoP-Nonce': this.dpopNonce } }
      );
    }

    if (!hasDPoPNonce && !this.alwaysRequireNonce) {
      return HttpResponse.json(
        {
          error: 'invalid_dpop_proof',
          error_description: 'DPoP proof missing required nonce'
        },
        { status: 400, headers: { 'DPoP-Nonce': this.dpopNonce } }
      );
    }

    return HttpResponse.json(
      {
        access_token: `mock-access-token-${this.tokenRequestCount}`,
        token_type: 'DPoP',
        expires_in: 3600,
        scope: 'read:pets'
      },
      { status: 200, headers: { 'DPoP-Nonce': this.dpopNonce } }
    );
  }

  private async handleResourceRequest(request: StrictRequest<any>): Promise<HttpResponse<any>> {
    this.resourceRequestCounter++;
    const headers = this.extractHeaders(request);
    const url = new URL(request.url);

    this.resourceRequestLogs.push({
      timestamp: new Date(),
      method: request.method,
      url: url.pathname,
      headers,
      authorization: headers['authorization']?.toString(),
      dpop: headers['dpop']?.toString(),
      requestNumber: this.resourceRequestCounter
    });

    const authorization = headers['authorization'];
    const dpop = headers['dpop'];

    if (!authorization) {
      return HttpResponse.json(
        {
          Errors: {
            Error: [
              {
                Source: 'Gateway',
                ReasonCode: 'INVALID_AUTH_HEADER',
                Description: 'Bad Request - No Authorization header set.',
                Recoverable: false,
                Details: null
              }
            ]
          }
        },
        { status: 400 }
      );
    }

    if (!dpop) {
      return HttpResponse.json(
        {
          Errors: {
            Error: [
              {
                Source: 'Gateway',
                ReasonCode: 'MALFORMED_OAUTH_REQ',
                Description: 'Invalid Request',
                Recoverable: false,
                Details: null
              }
            ]
          }
        },
        { status: 400 }
      );
    }

    if (this.simulateNonceError && this.resourceCalledCount++ < this.simulateNonceErrorTimes) {
      return HttpResponse.json(
        { error: 'use_dpop_nonce' },
        {
          status: 401,
          headers: {
            'DPoP-Nonce': this.dpopNonce,
            'WWW-Authenticate':
              'Dpop error:"use_dpop_nonce", error_description:"Resource server requires nonce in DPoP proof"'
          }
        }
      );
    }

    if (this.simulateUnauthorizedError && this.unauthorizedCalledCount++ < this.simulateUnauthorizedErrorTimes) {
      return HttpResponse.json(
        { error: 'invalid_token', error_description: 'The access token is invalid or expired' },
        {
          status: 401,
          headers: {
            'DPoP-Nonce': this.dpopNonce,
            'WWW-Authenticate': 'DPoP error="invalid_token", error_description="The access token is invalid or expired"'
          }
        }
      );
    }

    if (request.method === 'GET' && url.pathname === '/pets') {
      const pets = [
        { id: '1', name: 'Fluffy', type: 'cat', status: 'available' },
        { id: '2', name: 'Buddy', type: 'dog', status: 'available' }
      ];
      return HttpResponse.json(
        {
          data: pets,
          items: pets,
          count: pets.length,
          offset: 0,
          limit: pets.length,
          total: pets.length
        },
        { status: 200, headers: { 'DPoP-Nonce': this.dpopNonce } }
      );
    } else if (request.method === 'POST' && url.pathname === '/dogs') {
      const body = (await request.json()) as any;
      body.id = '3';
      return HttpResponse.json(body, { status: 201, headers: { 'DPoP-Nonce': this.dpopNonce } });
    }

    return HttpResponse.json({ error: 'not_found' }, { status: 404 });
  }

  private extractHeaders(request: StrictRequest<any>): Record<string, string | string[] | undefined> {
    const headers: Record<string, string | string[] | undefined> = {};
    request.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    return headers;
  }

  getTokenRequestCount(): number {
    return this.tokenRequestCount;
  }

  getTokenRequestLogs(): TokenRequestLog[] {
    return this.tokenRequestLogs;
  }

  getDPoPNonce(): string {
    return this.dpopNonce;
  }

  setAlwaysRequireNonce(value: boolean): void {
    this.alwaysRequireNonce = value;
  }

  getResourceRequestLogs(): ResourceRequestLog[] {
    return this.resourceRequestLogs;
  }

  enableSimulateNonceError(enable: boolean, times: number = 1): void {
    this.simulateNonceError = enable;
    this.simulateNonceErrorTimes = times;
  }

  enableSimulateUnauthorizedError(enable: boolean, times: number = 1): void {
    this.simulateUnauthorizedError = enable;
    this.simulateUnauthorizedErrorTimes = times;
  }

  getMergedCallOrder(): Array<{ type: 'token' | 'resource'; timestamp: Date; requestNumber: number; url?: string }> {
    const tokenCalls = this.tokenRequestLogs.map(log => ({
      type: 'token' as const,
      timestamp: log.timestamp,
      requestNumber: log.requestNumber,
      url: '/token'
    }));

    const resourceCalls = this.resourceRequestLogs.map(log => ({
      type: 'resource' as const,
      timestamp: log.timestamp,
      requestNumber: log.requestNumber,
      url: log.url
    }));

    return [...tokenCalls, ...resourceCalls].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }
}
