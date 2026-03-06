import {
  AxiosError,
  AxiosInstance,
  type AxiosRequestConfig,
  AxiosResponse,
  AxiosResponseHeaders,
  InternalAxiosRequestConfig,
  RawAxiosResponseHeaders
} from 'axios';
import { OAuth2Client } from '#core/client';
import { buildFullUrl, isAbsoluteHttpsURL } from '#http/url';
import { OAuth2ClientDelegate } from '#http/interceptor';

/**
 * Axios interceptor implementing OAuth2 flow with FAPI 2.0 profile and DPoP extension
 */
class OAuth2AxiosInterceptorFapi2DPoP {
  private readonly delegate: OAuth2ClientDelegate<InternalAxiosRequestConfig, AxiosResponse>;

  constructor(
    oauth2Client: OAuth2Client,
    axiosInstance: AxiosInstance,
    private options: AxiosOptions
  ) {
    this.delegate = new OAuth2ClientDelegate(oauth2Client, {
      getRequestHeaders: request => this.headersToRecord(request.headers),
      attachRequestHeaders: (request, oauth2Headers) => {
        if (!request.headers) request.headers = {};
        Object.assign(request.headers, oauth2Headers);
      },
      retryRequest: (_url, request) => axiosInstance(request)
    });
  }

  onRequest = async (config: InternalAxiosRequestConfig): Promise<InternalAxiosRequestConfig> => {
    const method = config.method?.toUpperCase();
    if (!method) throw new Error('HTTP method not defined');
    await this.delegate.onInterceptRequest(config, method, this.buildFullUrl(config));
    return config;
  };

  onResponse = async (response: AxiosResponse): Promise<AxiosResponse> => {
    // Handle successful response from resource server (Axios treats 4xx and 5xx as errors, see onError)
    const url = this.buildFullUrl(response.config);
    const requestMethod = response.config.method?.toUpperCase();

    if (!requestMethod) throw new Error('HTTP method not defined');

    await this.delegate.handleServerResponse(
      response.status,
      requestMethod,
      url,
      this.headersToRecord(response.headers)
    );

    return response;
  };

  onError = async (error: Error) => {
    // Error received from Resource Server
    if (error instanceof AxiosError) {
      const axiosError = error as AxiosError;
      if (!axiosError.response || !axiosError.response.config.method || !axiosError.config) {
        throw new Error('Axios server error');
      }
      const response = axiosError.response;
      const responseHeaders = this.headersToRecord(axiosError.response.headers);
      const url = this.buildFullUrl(axiosError.response.config);
      const method = axiosError.response.config.method.toUpperCase();

      const retryResponse = await this.delegate.onErrorResponse(
        response.status,
        method,
        url,
        responseHeaders,
        axiosError.config
      );

      // If a retry response was returned, return it instead of rejecting
      if (retryResponse) {
        return retryResponse;
      }
    }
    return Promise.reject(error);
  };

  private buildFullUrl(config: AxiosRequestConfig): string {
    const url = config.url || '';
    if (isAbsoluteHttpsURL(url)) {
      return url;
    }
    const baseURL = this.options.baseURL;
    return buildFullUrl(baseURL, url);
  }

  private headersToRecord(headers: RawAxiosResponseHeaders | AxiosResponseHeaders): Record<string, string> {
    const result: Record<string, string> = {};
    for (const key in headers) {
      const value = headers[key];
      if (value !== undefined && value !== null) {
        result[key] = String(value);
      }
    }
    return result;
  }
}

/** Configuration options for the OAuth2-enabled `AxiosInstance`. */
export interface AxiosOptions {
  baseURL: string;
}

/**
 * Configures an `AxiosInstance` with OAuth2 authentication using FAPI 2.0 and DPoP.
 * Automatically handles token acquisition, DPoP proof generation, and nonce retry.
 */
export function withOAuth2Axios(
  oauth2Client: OAuth2Client,
  axiosInstance: AxiosInstance,
  options: AxiosOptions
): AxiosInstance {
  const oauth2AxiosInterceptor = new OAuth2AxiosInterceptorFapi2DPoP(oauth2Client, axiosInstance, options);

  axiosInstance.interceptors.request.use(oauth2AxiosInterceptor.onRequest);
  axiosInstance.interceptors.response.use(oauth2AxiosInterceptor.onResponse, oauth2AxiosInterceptor.onError);
  return axiosInstance;
}
