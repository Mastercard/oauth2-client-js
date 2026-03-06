import { OAuth2ClientDelegate } from '#http/interceptor';
import { OAuth2Client } from '#core/client';
import superagent, { Response, SuperAgentRequest } from 'superagent';
import { buildFullUrl, isAbsoluteHttpsURL } from '#http/url';

/**
 * SuperAgent interceptor implementing OAuth2 flow with FAPI 2.0 profile and DPoP extension
 */
class OAuth2SuperAgentInterceptorFapi2DPoP {
  private readonly delegate: OAuth2ClientDelegate<SuperAgentRequest, Response>;
  private readonly superAgentInstance: ReturnType<typeof superagent.agent>;
  public applyInterceptorToRetry: boolean = false;

  constructor(oauth2Client: OAuth2Client, superAgentInstance: ReturnType<typeof superagent.agent>) {
    this.superAgentInstance = superAgentInstance;

    this.delegate = new OAuth2ClientDelegate(oauth2Client, {
      getRequestHeaders: request => (request as any).header as Record<string, string>,
      attachRequestHeaders: (request, oauth2Headers) => {
        if (!request.headers) request.headers = {};
        Object.assign(request.header, oauth2Headers);
      },
      retryRequest: (url, request) => this.retryRequest(url, request)
    });
  }

  onRequest = (request: SuperAgentRequest): SuperAgentRequest => {
    const originalThen = request.then.bind(request);
    request.then = (onfulfilled?: any, onRejected?: any) => {
      const enhancedPromise = (async () => {
        await this.delegate.onInterceptRequest(request, request.method.toUpperCase(), request.url);
        // Execute the original SuperAgent request
        return await originalThen();
      })();
      return enhancedPromise.then(onfulfilled, onRejected);
    };
    return request;
  };

  onResponse = (request: SuperAgentRequest): SuperAgentRequest => {
    const currentThen = request.then.bind(request);

    request.then = (onfulfilled?: any, onRejected?: any) => {
      const enhancedPromise = (async () => {
        try {
          // Execute the request
          const response = await currentThen();

          if (response.status >= 400 && response.status < 600) {
            return await this.handleError(request, response);
          } else {
            await this.delegate.handleServerResponse(
              response.status,
              request.method.toUpperCase(),
              request.url,
              response.headers as Record<string, string>
            );
            return response;
          }
        } catch (error: any) {
          // Handle errors from the request
          if (error.response) {
            return await this.handleError(request, error.response);
          }

          throw error;
        }
      })();

      return enhancedPromise.then(onfulfilled, onRejected);
    };

    return request;
  };

  intercept = (request: SuperAgentRequest): SuperAgentRequest => {
    const originalEnd = request.end.bind(request);

    request.end = (callback?: any) => {
      this.executeInterceptedRequest(request, originalEnd, callback).catch(err => {
        if (callback) callback(err);
      });
      return request;
    };

    return request;
  };

  private async executeInterceptedRequest(
    request: SuperAgentRequest,
    originalEnd: (callback: (error: any, response: Response) => void) => void,
    callback?: any
  ): Promise<void> {
    try {
      // Add OAuth2 headers before sending request
      await this.delegate.onInterceptRequest(request, request.method.toUpperCase(), request.url);

      // Execute the original request
      originalEnd((error: any, response: Response) => {
        this.handleRequestCompletion(request, error, response, callback);
      });
    } catch (err) {
      if (callback) callback(err);
    }
  }

  private async handleRequestCompletion(
    request: SuperAgentRequest,
    error: any,
    response: Response,
    callback?: any
  ): Promise<void> {
    if (error) {
      await this.handleErrorCompletion(request, error, callback);
    } else {
      await this.handleSuccessCompletion(request, response, callback);
    }
  }

  private async handleErrorCompletion(request: SuperAgentRequest, error: any, callback?: any): Promise<void> {
    if (error.response) {
      try {
        const retryResponse = await this.handleError(request, error.response);
        if (callback) callback(null, retryResponse);
      } catch (err) {
        if (callback) callback(err);
      }
    } else {
      if (callback) callback(error);
    }
  }

  private async handleSuccessCompletion(request: SuperAgentRequest, response: Response, callback?: any): Promise<void> {
    if (response.status >= 400 && response.status < 600) {
      try {
        const retryResponse = await this.handleError(request, response);
        if (callback) callback(null, retryResponse);
      } catch (err) {
        if (callback) callback(err);
      }
    } else {
      try {
        await this.delegate.handleServerResponse(
          response.status,
          request.method.toUpperCase(),
          request.url,
          response.headers as Record<string, string>
        );
        if (callback) callback(null, response);
      } catch (err) {
        if (callback) callback(err);
      }
    }
  }

  private async handleError(request: SuperAgentRequest, response: Response): Promise<Response> {
    const responseHeaders = response.headers as Record<string, string>;
    const retryResponse = await this.delegate.onErrorResponse(
      response.status,
      request.method.toUpperCase(),
      request.url,
      responseHeaders,
      request
    );
    if (retryResponse) {
      return retryResponse;
    }
    return response;
  }

  private async retryRequest(url: string, originalRequest: SuperAgentRequest): Promise<Response> {
    const method = originalRequest.method.toLowerCase();
    const newRequest = (this.superAgentInstance as any)[method](url);
    const originalInternal = originalRequest as any;
    if (originalInternal.__oauth2_retried__) {
      (newRequest as any).__oauth2_retried__ = true;
    }
    if (originalInternal.header) {
      Object.keys(originalInternal.header).forEach(key => {
        newRequest.set(key, originalInternal.header[key]);
      });
    }
    if (originalInternal._data) {
      newRequest.send(originalInternal._data);
    }
    if (originalInternal.qs) {
      newRequest.query(originalInternal.qs);
    }
    if (originalInternal._timeout) {
      newRequest.timeout(originalInternal._timeout);
    }

    if (this.applyInterceptorToRetry) {
      this.onRequest(newRequest);
      this.onResponse(newRequest);
    }

    return await newRequest;
  }
}

/**
 * Creates a SuperAgent plugin for OAuth2 authentication.
 * Can be applied to individual requests via `.use()`.
 */
export function createOAuth2SuperagentPlugin(oauth2Client: OAuth2Client, options: SuperAgentOptions) {
  const retryAgent = options.retryAgent || superagent.agent();

  return (request: SuperAgentRequest) => {
    if (options?.baseURL && !isAbsoluteHttpsURL(request.url)) {
      request.url = buildFullUrl(options.baseURL, request.url);
    }

    const interceptor = new OAuth2SuperAgentInterceptorFapi2DPoP(oauth2Client, retryAgent);
    interceptor.applyInterceptorToRetry = true;

    return interceptor.intercept(request);
  };
}

/** Configuration options for the OAuth2-enabled `superagent` instance. */
export interface SuperAgentOptions {
  baseURL: string;
  retryAgent?: ReturnType<typeof superagent.agent>;
}

/**
 * Configures a `superagent` instance with OAuth2 authentication using FAPI 2.0 and DPoP.
 * Automatically handles token acquisition, DPoP proof generation, and nonce retry.
 */
export function withOAuth2Superagent(
  oauth2Client: OAuth2Client,
  superagentInstance: ReturnType<typeof superagent.agent>,
  options: SuperAgentOptions
): ReturnType<typeof superagent.agent> {
  const interceptor = new OAuth2SuperAgentInterceptorFapi2DPoP(oauth2Client, superagentInstance);

  const methods = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
  methods.forEach(method => {
    const original = (superagentInstance as any)[method].bind(superagentInstance);
    (superagentInstance as any)[method] = (url: string) => {
      let fullUrl = url;
      if (options.baseURL && !isAbsoluteHttpsURL(url)) {
        fullUrl = buildFullUrl(options.baseURL, url);
      }
      return original(fullUrl);
    };
  });

  superagentInstance.use(interceptor.onRequest);
  superagentInstance.use(interceptor.onResponse);
  return superagentInstance;
}
