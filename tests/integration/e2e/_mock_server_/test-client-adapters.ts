import https from 'https';
import { Agent as UndiciAgent } from 'undici';
import { loadP12File } from '#test-utils/test-utils';
import {
  Configuration as ConfigurationFetch,
  DogsApi as DogsApiFetch,
  PetsApi as PetsApiFetch
} from '../../../generated-clients/typescript-fetch';
import {
  Configuration as ConfigurationAxios,
  DogsApi as DogsApiAxios,
  PetsApi as PetsApiAxios
} from '../../../generated-clients/typescript-axios';
import {
  ApiClient as ApiClientJs,
  DogsApi as DogsApiJs,
  PetsApi as PetsApiJs
} from '../../../generated-clients/javascript/src';

import {
  InMemoryTokenStore,
  OAuth2ClientBuilder,
  StaticDPoPKeyProvider,
  StaticScopeResolver,
  withOAuth2Fetch
} from '@mastercard/oauth2-client-js';
import { withOAuth2Axios } from '@mastercard/oauth2-client-js/axios';
import { createOAuth2SuperagentPlugin, withOAuth2Superagent } from '@mastercard/oauth2-client-js/superagent';
import axios, { Axios } from 'axios';
import superagent from 'superagent';
import type { TokenStore } from '#types';
import { OAuth2Client, OAuth2ClientInternal } from '#core/client';
import { IMockServer } from './mock-server';

const createHttpsAgent = (cert: string) =>
  new https.Agent({
    ca: cert
  });

const createUndiciDispatcher = (cert: string) =>
  new UndiciAgent({
    connect: {
      ca: cert
    }
  });

const createFetchWithSelfSignedSupport = (cert: string) => {
  const dispatcher = createUndiciDispatcher(cert);
  return (url: string | URL | Request, init?: RequestInit) => {
    return fetch(url, { ...init, dispatcher } as any);
  };
};

interface Decorator {
  build(authServer: IMockServer, resourceServer: IMockServer, tokenStore?: TokenStore): Promise<Decorator>;
  getPets(): Promise<any>;
  addDog(req: any): Promise<any>;
  getJkt(): Promise<string>;
}

abstract class BaseDecorator implements Decorator {
  protected oauth2Client: OAuth2Client;

  abstract build(authServer: IMockServer, resourceServer: IMockServer, tokenStore?: TokenStore): Promise<Decorator>;

  abstract getPets(): Promise<any>;
  abstract addDog(req: any): Promise<any>;

  async getJkt(): Promise<string> {
    return (this.oauth2Client as OAuth2ClientInternal).getDPoPKeyProvider().getCurrentKey().getKeyId();
  }
}

export class FetchDecorator extends BaseDecorator {
  oauth2Fetch: typeof fetch;
  cert: string;

  async build(authServer: IMockServer, resourceServer: IMockServer, tokenStore?: TokenStore): Promise<Decorator> {
    this.cert = resourceServer.getCertificate().cert;
    this.oauth2Client = await newOAuth2Client(authServer, tokenStore);
    const fetchWithSelfSigned = createFetchWithSelfSignedSupport(this.cert);
    this.oauth2Fetch = withOAuth2Fetch(this.oauth2Client, fetchWithSelfSigned, { baseURL: resourceServer.getUrl() });
    return this;
  }

  async getPets(): Promise<any> {
    const dispatcher = createUndiciDispatcher(this.cert);
    const response = await this.oauth2Fetch('/pets', { method: 'GET', dispatcher } as any);
    const data = await response.json();
    return { status: response.status, data: data, headers: this.headers(response) };
  }

  async addDog(req: any): Promise<any> {
    const dispatcher = createUndiciDispatcher(this.cert);
    const response = await this.oauth2Fetch('/dogs', { method: 'POST', body: JSON.stringify(req), dispatcher } as any);
    return { status: response.status, data: await response.json(), headers: this.headers(response) };
  }

  private headers(response: Response): Record<string, string> {
    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      headers[name] = value;
    });
    return headers;
  }
}

export class AxiosDecorator extends BaseDecorator {
  oauth2Axios: Axios;

  async build(authServer: IMockServer, resourceServer: IMockServer, tokenStore?: TokenStore): Promise<Decorator> {
    const cert = resourceServer.getCertificate().cert;
    const axios = (await import('axios')).default;
    const axiosInstance = axios.create({
      baseURL: resourceServer.getUrl(),
      httpsAgent: createHttpsAgent(cert)
    });
    this.oauth2Client = await newOAuth2Client(authServer, tokenStore);
    this.oauth2Axios = withOAuth2Axios(this.oauth2Client, axiosInstance, { baseURL: resourceServer.getUrl() });
    return this;
  }

  async getPets(): Promise<any> {
    const response = await this.oauth2Axios.get('/pets');
    return { status: response.status, data: response.data, headers: response.headers };
  }

  async addDog(req: any): Promise<any> {
    const response = await this.oauth2Axios.post('/dogs', req);
    return { status: response.status, data: response.data, headers: response.headers };
  }
}

export class SuperAgentDecorator extends BaseDecorator {
  oauth2Superagent: ReturnType<typeof superagent.agent>;
  cert: string;

  async build(authServer: IMockServer, resourceServer: IMockServer, tokenStore?: TokenStore): Promise<Decorator> {
    this.cert = resourceServer.getCertificate().cert;
    const superagent = (await import('superagent')).default;
    this.oauth2Client = await newOAuth2Client(authServer, tokenStore);
    this.oauth2Superagent = withOAuth2Superagent(this.oauth2Client, superagent.agent().ca(this.cert), {
      baseURL: resourceServer.getUrl()
    });
    return this;
  }

  async getPets(): Promise<any> {
    const response = await this.oauth2Superagent.get('/pets').ca(this.cert);
    return { status: response.status, data: response.body, headers: response.headers };
  }

  async addDog(req: any): Promise<any> {
    const response = await this.oauth2Superagent.post('/dogs').send(req).ca(this.cert);
    return { status: response.status, data: response.body, headers: response.headers };
  }
}

export class OpenApiJavascriptDecorator extends BaseDecorator {
  petsApi: PetsApiJs;
  dogsApi: DogsApiJs;

  async build(authServer: IMockServer, resourceServer: IMockServer, tokenStore?: TokenStore): Promise<Decorator> {
    const cert = resourceServer.getCertificate().cert;
    this.oauth2Client = await newOAuth2Client(authServer, tokenStore);
    const requestAgent = createHttpsAgent(cert);
    const retryAgent = superagent.agent().ca(cert);

    const oauth2Plugin = createOAuth2SuperagentPlugin(this.oauth2Client, {
      baseURL: resourceServer.getUrl(),
      retryAgent: retryAgent
    });

    const apiClient = new ApiClientJs(resourceServer.getUrl());
    apiClient.plugins = [oauth2Plugin];
    apiClient.requestAgent = requestAgent;

    this.petsApi = new PetsApiJs(apiClient);
    this.dogsApi = new DogsApiJs(apiClient);
    return this;
  }

  async getPets(): Promise<any> {
    const resp = await this.petsApi.searchPetsWithHttpInfo();
    return { status: resp.response.status, data: resp.response.body, headers: resp.response.headers };
  }

  async addDog(req: any): Promise<any> {
    const resp = await this.dogsApi.addDogWithHttpInfo(req);
    return { status: resp.response.status, data: resp.response.body, headers: resp.response.headers };
  }
}

export class OpenApiAxiosDecorator extends BaseDecorator {
  petsApi: PetsApiAxios;
  dogsApi: DogsApiAxios;

  async build(authServer: IMockServer, resourceServer: IMockServer, tokenStore?: TokenStore): Promise<Decorator> {
    const cert = resourceServer.getCertificate().cert;
    this.oauth2Client = await newOAuth2Client(authServer, tokenStore);
    const axiosInstance = axios.create({
      baseURL: resourceServer.getUrl(),
      httpsAgent: createHttpsAgent(cert)
    });
    const axiosWithOAuth2 = withOAuth2Axios(this.oauth2Client, axiosInstance, { baseURL: resourceServer.getUrl() });
    const config = new ConfigurationAxios();
    this.petsApi = new PetsApiAxios(config, resourceServer.getUrl(), axiosWithOAuth2);
    this.dogsApi = new DogsApiAxios(config, resourceServer.getUrl(), axiosWithOAuth2);
    return this;
  }

  async getPets(): Promise<any> {
    const pets = await this.petsApi.searchPets();
    return { status: pets.status, data: pets.data, headers: pets.headers };
  }

  async addDog(req: any): Promise<any> {
    const dog = await this.dogsApi.addDog(req);
    return { status: dog.status, data: dog.data, headers: dog.headers };
  }
}

export class OpenApiFetchDecorator extends BaseDecorator {
  petsApi: PetsApiFetch;
  dogsApi: DogsApiFetch;

  async build(authServer: IMockServer, resourceServer: IMockServer, tokenStore?: TokenStore): Promise<Decorator> {
    const cert = resourceServer.getCertificate().cert;
    this.oauth2Client = await newOAuth2Client(authServer, tokenStore);
    const fetchWithSelfSigned = createFetchWithSelfSignedSupport(cert);
    const fetch = withOAuth2Fetch(this.oauth2Client, fetchWithSelfSigned, { baseURL: resourceServer.getUrl() });
    const config = new ConfigurationFetch({ fetchApi: fetch, basePath: resourceServer.getUrl() });
    this.petsApi = new PetsApiFetch(config);
    this.dogsApi = new DogsApiFetch(config);
    return this;
  }

  async getPets(): Promise<any> {
    const resp = await this.petsApi.searchPetsRaw({});
    const petList = await resp.value();
    return { status: resp.raw.status, data: { ...petList, data: petList.items }, headers: this.headers(resp) };
  }

  async addDog(req: any): Promise<any> {
    const resp = await this.dogsApi.addDogRaw({ newDog: req });
    const dog = await resp.value();
    return { status: resp.raw.status, data: dog, headers: this.headers(resp) };
  }

  private headers(resp: any): Record<string, string> {
    const headers: Record<string, string> = {};
    resp.raw.headers.forEach((value, name) => {
      headers[name] = value;
    });
    return headers;
  }
}

const newOAuth2Client = async (authServer: IMockServer, tokenStore?: TokenStore) => {
  const P12_FILE = 'tests/_resources_/signing-key.p12';
  const P12_PASSWORD = 'keyalias1';
  const P12_ALIAS = 'keyalias1';
  const p12 = await loadP12File(P12_FILE, P12_PASSWORD, P12_ALIAS);
  const privateKey = p12.privateKey;
  const publicKey = p12.publicKey;

  const authCert = authServer.getCertificate().cert;
  const fetchWithSelfSigned = createFetchWithSelfSignedSupport(authCert);

  const customAdapter: any = {
    execute: async (request: any) => {
      const fetchInit: RequestInit = {
        method: request.method,
        body: request.body as BodyInit
      };

      if (request.headers) {
        fetchInit.headers = request.headers;
      }

      const response = await fetchWithSelfSigned(request.url, fetchInit);

      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value: string, key: string) => {
        responseHeaders[key.toLowerCase()] = value;
      });

      return {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body: await response.text()
      };
    }
  };

  return new OAuth2ClientBuilder()
    .clientId('mock-client-id')
    .kid('mock-key-id')
    .clientKey(privateKey)
    .httpAdapter(customAdapter)
    .tokenEndpoint(`${authServer.getUrl()}/token`)
    .issuer(`${authServer.getUrl()}`)
    .dPoPKeyProvider(new StaticDPoPKeyProvider(privateKey, publicKey))
    .tokenStore(tokenStore ?? new InMemoryTokenStore())
    .clockSkewTolerance(60)
    .scopeResolver(new StaticScopeResolver(['read:pets']))
    .logger(console)
    .build();
};
