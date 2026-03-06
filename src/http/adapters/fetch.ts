import type { HttpAdapter, HttpRequest, HttpResponse } from '#types';

/**
 * {@link HttpAdapter} implementation using the `fetch` API.
 */
export class FetchHttpAdapter implements HttpAdapter {
  private readonly fetchImpl: typeof fetch | undefined;

  constructor(fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
  }

  async execute(request: HttpRequest): Promise<HttpResponse> {
    const fetchFn = this.fetchImpl;
    if (typeof fetchFn !== 'function') {
      throw new Error(
        'Fetch API is not available in this environment. Provide a fetch implementation when constructing FetchHttpAdapter.'
      );
    }

    const fetchInit: RequestInit = {
      method: request.method,
      body: request.body as BodyInit
    };

    if (request.headers) {
      fetchInit.headers = request.headers;
    }

    const response = await fetchFn(request.url, fetchInit);

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: await response.text()
    };
  }
}
