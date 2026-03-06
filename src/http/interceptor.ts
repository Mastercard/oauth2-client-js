import { OAuth2Client, OAuth2ClientInternal } from '#core/client';
import type { Logger } from '#types';

/**
 * Adapter interface for HTTP library-specific request/response handling.
 */
interface InterceptorAdapter<RequestType, ResponseType> {
  getRequestHeaders: (request: RequestType) => Record<string, string>;
  attachRequestHeaders: (headers: any, oauth2Headers: Record<string, string>) => void;
  retryRequest: (url: string, request: RequestType) => Promise<ResponseType>;
}

/**
 * Delegate that bridges HTTP library interceptors with {@link OAuth2Client}.
 * This class handles request signing, response processing, and automatic retry on `use_dpop_nonce` errors.
 * See: <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-9">RFC 9449 Section 9</a>
 */
export class OAuth2ClientDelegate<RequestType extends object, ResponseType> {
  private readonly oauth2Client: OAuth2ClientInternal;
  private readonly adapter: InterceptorAdapter<RequestType, ResponseType>;
  private readonly log: Logger;

  constructor(oauth2Client: OAuth2Client, adapter: InterceptorAdapter<RequestType, ResponseType>) {
    this.adapter = adapter;
    this.oauth2Client = oauth2Client as OAuth2ClientInternal;
    this.log = this.oauth2Client.getLogger();
  }

  /** Intercepts outgoing requests to attach OAuth2 headers (`Authorization`, `DPoP`). */
  async onInterceptRequest(request: RequestType, method: string, fullUrl: string): Promise<void> {
    const headers = this.adapter.getRequestHeaders(request);

    // Get OAuth2 headers
    this.debug(`Intercepted request: ${method} ${fullUrl}`);
    this.debug(`Generating OAuth2 headers`);
    try {
      const oauth2Headers = await this.oauth2Client.getOAuth2Headers(method, fullUrl, headers);
      this.info(`OAuth2 headers attached successfully for ${method} ${fullUrl}`);
      this.adapter.attachRequestHeaders(request, oauth2Headers);
    } catch (e) {
      this.error(`Failed to generate OAuth2 headers for ${method} ${fullUrl}: ${e}`);
    }
  }

  /** Processes successful responses to cache `DPoP-Nonce` from headers. */
  async handleServerResponse(
    statusCode: number,
    httpMethod: string,
    fullUrl: string,
    headers: Record<string, string>
  ): Promise<void> {
    // Cache DPoP nonce from response headers
    this.debug(`Handling server response: ${httpMethod} ${fullUrl}`);
    await this.oauth2Client.handleServerResponse(statusCode, headers, httpMethod, fullUrl);
  }

  /**
   * Handles error responses, refreshing tokens and retrying on DPoP nonce errors.
   * Returns the retry response if successful, `undefined` otherwise.
   */
  async onErrorResponse(
    status: number,
    method: string,
    fullUrl: string,
    responseHeaders: Record<string, string>,
    originalRequest: RequestType
  ): Promise<ResponseType | undefined> {
    this.warn(`Error response received from resource server (status ${status})`);
    if ((originalRequest as any).__oauth2_retried__) {
      this.warn('Max retries reached for request, not retrying again');
      return undefined; // Max 1 retry
    }
    // Error received from Resource Server
    const shouldRetryHeaders = await this.oauth2Client.handleServerResponse(
      status,
      responseHeaders,
      method.toUpperCase(),
      fullUrl
    );

    if (shouldRetryHeaders) {
      this.info('Retrying request with updated OAuth2 headers');
      (originalRequest as any).__oauth2_retried__ = true;
      // update headers
      this.adapter.attachRequestHeaders(originalRequest, shouldRetryHeaders);
      // retry request
      return await this.adapter.retryRequest(fullUrl, originalRequest);
    } else {
      this.debug('Not retrying request, no updated headers available');
      return undefined;
    }
  }

  private debug(message: string): void {
    this.log.debug(`[interceptor] ${message}`);
  }

  private info(message: string): void {
    this.log.info(`[interceptor] ${message}`);
  }

  private warn(message: string): void {
    this.log.warn(`[interceptor] ${message}`);
  }

  private error(message: string): void {
    this.log.error(`[interceptor] ${message}`);
  }
}
