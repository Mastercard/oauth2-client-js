import { OAuth2Client } from '#core/client';
import { OAuth2ClientDelegate } from '#http/interceptor';
import { buildFullUrl, isAbsoluteHttpsURL } from '#http/url';

type RequestInterceptorFn = (
  url: string,
  options: OAuth2FetchRequestInit
) => [string, OAuth2FetchRequestInit] | Promise<[string, OAuth2FetchRequestInit]>;

type ResponseInterceptorFn = (response: Response, context: ResponseInterceptorContext) => Response | Promise<Response>;

interface ResponseInterceptorContext {
  url: string;
  options: OAuth2FetchRequestInit;
}

interface OAuth2FetchRequestInit extends RequestInit {
  __oauth2_retryRequest?: Request;
}

class FetchInterceptor {
  private requestInterceptors: Array<RequestInterceptorFn> = [];
  private responseInterceptors: Array<ResponseInterceptorFn> = [];
  private readonly fetchFn: typeof fetch;

  constructor(fetchFn: typeof fetch) {
    this.fetchFn = fetchFn;
  }

  addRequestInterceptor(fn: RequestInterceptorFn): void {
    this.requestInterceptors.push(fn);
  }

  addResponseInterceptor(fn: ResponseInterceptorFn): void {
    this.responseInterceptors.push(fn);
  }

  fetch = async (url: string, options: RequestInit = {}): Promise<Response> => {
    let modifiedUrl = url;
    let modifiedOptions: OAuth2FetchRequestInit = { ...options };

    // Apply request interceptors
    for (const interceptor of this.requestInterceptors) {
      [modifiedUrl, modifiedOptions] = await interceptor(modifiedUrl, modifiedOptions);
    }

    const requestInit: RequestInit = { ...modifiedOptions };
    delete (requestInit as Partial<OAuth2FetchRequestInit>).__oauth2_retryRequest;
    const request = new Request(modifiedUrl, requestInit);
    modifiedOptions.__oauth2_retryRequest = request.clone();

    // Make request
    let response = await this.fetchFn(request);

    // Apply response interceptors
    for (const interceptor of this.responseInterceptors) {
      response = await interceptor(response, { url: modifiedUrl, options: modifiedOptions });
    }

    return response;
  };
}

/**
 * Fetch interceptor implementing OAuth2 flow with FAPI 2.0 profile and DPoP extension
 */
class OAuth2FetchInterceptorFapi2DPoP {
  private readonly delegate: OAuth2ClientDelegate<OAuth2FetchRequestInit, Response>;
  private interceptedFetch?: typeof fetch;

  constructor(oauth2Client: OAuth2Client, fetchInstance: typeof fetch) {
    this.delegate = new OAuth2ClientDelegate(oauth2Client, {
      getRequestHeaders: request => {
        return headersInitToRecord(request.headers);
      },
      attachRequestHeaders: (request, oauth2Headers) => {
        const headers = ensureHeadersInstance(request.headers);
        Object.entries(oauth2Headers).forEach(([key, value]) => {
          headers.set(key, value);
        });
        request.headers = headers;
      },
      retryRequest: (url, request) => {
        const headers = ensureHeadersInstance(request.headers);
        request.headers = headers;
        const retryClone = request.__oauth2_retryRequest;
        const fetchFn = this.interceptedFetch || fetchInstance;
        if (retryClone) {
          delete request.__oauth2_retryRequest;
          const method = request.method;
          if (!method) {
            throw new Error('Fetch HTTP method not defined');
          }
          const retryRequest = new Request(retryClone, {
            headers,
            method
          });
          return fetchFn(retryRequest);
        }
        return fetchFn(url, request);
      }
    });
  }

  setInterceptedFetch(interceptedFetch: typeof fetch): void {
    this.interceptedFetch = interceptedFetch;
  }

  onRequest = async (url: string, options: OAuth2FetchRequestInit): Promise<[string, OAuth2FetchRequestInit]> => {
    if (!options.method) {
      throw new Error('Fetch HTTP method not defined');
    }
    const method = options.method.toUpperCase();
    await this.delegate.onInterceptRequest(options, method, url);
    return [url, options];
  };

  onResponse = async (
    response: Response,
    context: { url: string; options: OAuth2FetchRequestInit }
  ): Promise<Response> => {
    if (response.status >= 400 && response.status < 600) {
      return this.handleError(response, context);
    } else {
      if (!context.options.method) {
        throw new Error('Fetch HTTP method not defined');
      }
      const method = context.options.method.toUpperCase();
      // Handle successful response from resource server
      await this.delegate.handleServerResponse(
        response.status,
        method,
        response.url,
        this.headersToRecord(response.headers)
      );
      return response;
    }
  };

  private async handleError(
    response: Response,
    context: { url: string; options: OAuth2FetchRequestInit }
  ): Promise<Response> {
    if (!context.options.method) {
      throw new Error('Fetch HTTP method not defined');
    }
    const responseHeaders = this.headersToRecord(response.headers);
    const method = context.options.method.toUpperCase();
    const retryResponse = await this.delegate.onErrorResponse(
      response.status,
      method,
      response.url,
      responseHeaders,
      context.options
    );

    if (retryResponse) {
      return retryResponse;
    }

    return response;
  }

  private headersToRecord(headers: Headers): Record<string, string> {
    const result: Record<string, string> = {};
    headers.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }
}

function createFetchWrapper(fetchWithInterceptors: FetchInterceptor, options: FetchOptions): typeof fetch {
  return (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    let url: string;

    if (typeof input === 'string') {
      url = input;
    } else if (input instanceof URL) {
      url = input.toString();
    } else if (input instanceof Request) {
      url = input.url;
      init = init || {
        method: input.method,
        headers: input.headers,
        body: input.body
      };
    } else {
      throw new Error('Invalid input type for fetch');
    }

    if (options.baseURL && !isAbsoluteHttpsURL(url)) {
      url = buildFullUrl(options.baseURL, url);
    }

    return fetchWithInterceptors.fetch(url, init);
  };
}

function headersInitToRecord(headers?: HeadersInit): Record<string, string> {
  const result: Record<string, string> = {};
  if (!headers) {
    return result;
  }

  if (headers instanceof Headers) {
    headers.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }

  if (Array.isArray(headers)) {
    headers.forEach(([key, value]) => {
      result[key] = value;
    });
    return result;
  }

  Object.entries(headers).forEach(([key, value]) => {
    if (value !== undefined) {
      result[key] = Array.isArray(value) ? value.join(', ') : String(value);
    }
  });
  return result;
}

function ensureHeadersInstance(headers?: HeadersInit): Headers {
  if (headers instanceof Headers) {
    return headers;
  }
  return new Headers(headers ?? {});
}

/** Configuration options for the OAuth2-enabled `fetch` wrapper. */
export interface FetchOptions {
  baseURL: string;
}

/**
 * Wraps a `fetch` instance with OAuth2 authentication using FAPI 2.0 and DPoP.
 * Automatically handles token acquisition, DPoP proof generation, and nonce retry.
 */
export function withOAuth2Fetch(
  oauth2Client: OAuth2Client,
  fetchInstance: typeof fetch,
  options: FetchOptions
): typeof fetch {
  const fetchWithInterceptors = new FetchInterceptor(fetchInstance);
  const oauth2FetchInterceptor = new OAuth2FetchInterceptorFapi2DPoP(oauth2Client, fetchInstance);

  fetchWithInterceptors.addRequestInterceptor(oauth2FetchInterceptor.onRequest);
  fetchWithInterceptors.addResponseInterceptor(oauth2FetchInterceptor.onResponse);

  const wrappedFetch = createFetchWrapper(fetchWithInterceptors, options);
  oauth2FetchInterceptor.setInterceptedFetch(wrappedFetch);

  return wrappedFetch;
}
