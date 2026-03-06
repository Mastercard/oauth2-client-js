# OAuth 2 Client - JavaScript

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-light.svg">
  <img src="https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg" alt="mastercard developers logo">
</picture>

A zero-dependency, OAuth 2.0 client library for accessing Mastercard APIs with **OAuth 2.0**, **FAPI 2.0 Security Profile**, and **DPoP (Demonstrating Proof-of-Possession)** support.

For more information, see [Using OAuth 2.0 to Access Mastercard APIs](https://mstr.cd/43CuHBY).

## Requirements

### License

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

This project is licensed under the Apache License 2.0.

### Node.js

| Version | Status |
|-----------------|---------|
| 20.x, 22.x, 24.x            | [![Node.js](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-nodejs.yaml/badge.svg)](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-nodejs.yaml) |

This library requires Node.js 20 or later.

While Node.js is the primary supported runtime, the library exposes a [`RuntimeEnvironment`](./src/utils/runtime.ts) abstraction for alternative JavaScript runtimes (such as Deno, Bun, or edge environments). Use [`RuntimeEnvironment.configure()`](./src/utils/runtime.ts#L15) to provide a custom crypto provider and platform details when the default auto-detection is not suitable.

### Zero-Dependency

This library has no runtime dependencies. HTTP clients (Axios, Superagent) are declared as optional peer dependencies, allowing you to install only what your application needs. The Fetch API is built into Node.js 18+ and requires no additional installation.

## Usage

### Installation

[![npm](https://img.shields.io/npm/v/@mastercard/oauth2-client-js)](https://www.npmjs.com/package/@mastercard/oauth2-client-js)

To start, add the library to your project:

```bash
npm install @mastercard/oauth2-client-js
```

### Peer Dependencies

Install the HTTP client(s) you plan to use:

```bash
# For Axios
npm install axios

# For Superagent
npm install superagent

# Fetch is built into Node.js 18+, no installation needed
```

### Configuration

The [`OAuth2ClientBuilder`](./src/core/builder.ts) provides a fluent API to configure your client credentials, DPoP keys, token endpoint, and other settings for OAuth 2.0 authentication.

Here's how to build an instance:

```typescript
import {
  OAuth2ClientBuilder,
  StaticDPoPKeyProvider,
  StaticScopeResolver
} from '@mastercard/oauth2-client-js';

const oauth2Client = new OAuth2ClientBuilder()
  .clientId('ZvT0sklPsqzTNgKJIiex5_wppXz0Tj2wl33LUZtXmCQH8dry')
  .kid('302449525fad5309874b16298f3cbaaf0000000000000000')
  .clientKey(clientPrivateKey)
  .tokenEndpoint('https://sandbox.api.mastercard.com/oauth/token')
  .issuer('https://sandbox.api.mastercard.com')
  .scopeResolver(new StaticScopeResolver(['service:scope1', 'service:scope2']))
  .dPoPKeyProvider(new StaticDPoPKeyProvider(dpopPrivateKey, dpopPublicKey))
  .clockSkewTolerance(10)
  .build();
```

Notes:
* All credentials shown here are examples from [Using OAuth 2.0 to Access Mastercard APIs](https://mstr.cd/43CuHBY). Replace them with your own.
* For more information on scope resolvers, DPoP key providers, and token stores, see [API Reference](#api-reference).

## Quick Start

```typescript
// 1. Wrap your HTTP client (e.g.: fetch)
const oauth2Fetch = withOAuth2Fetch(oauth2Client, fetch, {
  baseURL: 'https://api.mastercard.com/service'
});

// 2. Make authenticated requests
const response = await oauth2Fetch('/resource', { method: 'GET' });
const data = await response.json();
```

### Low-Level API

The [`OAuth2Client`](./src/core/client.ts) interface provides methods that handle client assertion generation, DPoP proof creation, token requests, and response handling. For advanced use cases where you need direct access to these primitives, see the [API Reference](docs/API_REFERENCE.md).

### Direct HTTP Client Integration

For a higher-level experience, use the provided HTTP client wrappers that automatically handle OAuth 2.0 authentication. Pick the HTTP client that works best for your application - all implementations provide the same functionality.


#### Fetch

| Version | Status |
|-----------------|---------|
| 20.x, 22.x, 24.x            | [![fetch](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-fetch.yaml/badge.svg)](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-fetch.yaml) |

Native Fetch support (Node.js 18+):

```typescript
import { withOAuth2Fetch } from '@mastercard/oauth2-client-js';

const oauth2Fetch = withOAuth2Fetch(oauth2Client, fetch, {
  baseURL: 'https://api.mastercard.com/service'
});

// Make authenticated requests
const response = await oauth2Fetch('/pets', { method: 'GET' });
```

#### Axios

| Version | Status |
|-----------------|---------|
| 1.9.x, 1.10.x, 1.11.x, 1.12.x, 1.13.x            | [![axios](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-axios.yaml/badge.svg)](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-axios.yaml) |

```typescript
import { withOAuth2Axios } from '@mastercard/oauth2-client-js/axios';
import axios from 'axios';

const axiosInstance = axios.create({
  baseURL: 'https://api.mastercard.com/service'
});

const oauth2Axios = withOAuth2Axios(oauth2Client, axiosInstance);

// Make authenticated requests
const { data } = await oauth2Axios.get('/pets');
```

#### Superagent

| Version | Status |
|-----------------|---------|
| 8.1.x, 9.0.x, 10.0.x, 10.1.x, 10.2.x            | [![superagent](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-superagent.yaml/badge.svg)](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-superagent.yaml) |

```typescript
import { withOAuth2Superagent } from '@mastercard/oauth2-client-js/superagent';
import superagent from 'superagent';

const oauth2Superagent = withOAuth2Superagent(
  oauth2Client,
  superagent.agent(),
  { baseURL: 'https://api.mastercard.com/service' }
);

// Make authenticated requests
const { body } = await oauth2Superagent.get('/pets');
```


### OpenAPI Generated Clients

The library seamlessly integrates with OpenAPI Generator clients:

#### TypeScript Axios Generator: [typescript-axios](https://openapi-generator.tech/docs/generators/typescript-axios)

| Version | Status |
|-----------------|---------|
| 7.0.x, 7.19.x            | [![openapi-axios](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-openapi-axios.yaml/badge.svg)](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-openapi-axios.yaml) |

```typescript
import { withOAuth2Axios } from '@mastercard/oauth2-client-js/axios';
import { Configuration, PetsApi } from './generated-client';
import axios from 'axios';

const baseURL = 'https://api.mastercard.com/petstore';
const axiosInstance = axios.create({ baseURL });

// Wrap axios with OAuth2
const oauth2Axios = withOAuth2Axios(oauth2Client, axiosInstance, { baseURL });

// Use with generated API
const configuration = new Configuration();
const petsApi = new PetsApi(configuration, baseURL, oauth2Axios);

const pets = await petsApi.searchPets();
```

#### TypeScript Fetch Generator: [typescript-fetch](https://openapi-generator.tech/docs/generators/typescript-fetch)

| Version | Status |
|-----------------|---------|
| 7.0.x, 7.19.x            | [![openapi-fetch](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-openapi-fetch.yaml/badge.svg)](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-openapi-fetch.yaml) |

```typescript
import { withOAuth2Fetch } from '@mastercard/oauth2-client-js';
import { Configuration, PetsApi } from './generated-client';

const baseURL = 'https://api.mastercard.com/petstore';

// Wrap fetch with OAuth2
const oauth2Fetch = withOAuth2Fetch(oauth2Client, fetch, { baseURL });

// Use with generated API
const configuration = new Configuration({
  basePath: baseURL,
  fetchApi: oauth2Fetch
});

const petsApi = new PetsApi(configuration);
const pets = await petsApi.searchPets();
```

#### JavaScript Generator (Superagent-based): [javascript](https://openapi-generator.tech/docs/generators/javascript)

| Version | Status |
|-----------------|---------|
| 7.0.x, 7.19.x            | [![openapi-superagent](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-openapi-superagent.yaml/badge.svg)](https://github.com/Mastercard/oauth2-client-js/actions/workflows/ci-openapi-superagent.yaml) |

```typescript
import { createOAuth2SuperagentPlugin } from '@mastercard/oauth2-client-js/superagent';
import { ApiClient, PetsApi } from './generated-client';

const baseURL = 'https://api.mastercard.com/petstore';

// Create OAuth2 plugin
const oauth2Plugin = createOAuth2SuperagentPlugin(oauth2Client, { baseURL });

// Configure API client
const apiClient = new ApiClient(baseURL);
apiClient.plugins = [oauth2Plugin];

const petsApi = new PetsApi(apiClient);
const pets = await petsApi.searchPets();
```

## API Reference

This library is designed to be extended. Common extension points are listed below.

### [`ScopeResolver`](./src/types.ts)

- Implement `ScopeResolver` to control which scopes are requested for a given URL or endpoint
- Use `StaticScopeResolver` for simple fixed-scope cases

### [`DPoPKeyProvider`](./src/types.ts)

- Implement `DPoPKeyProvider` to supply keys for DPoP proofs
- Use `StaticDPoPKeyProvider` for a single, static key pair
- For short-lived DPoP keys, implement a provider that returns different keys over time

### [`TokenStore`](./src/types.ts)

- Implement `TokenStore` to control how access tokens are cached and retrieved
- Use `InMemoryTokenStore` for a simple in-memory cache with automatic expiration

See [API Reference](docs/API_REFERENCE.md) for detailed documentation of classes and functions.

## Development

### Build

```bash
npm run build
```

### Run Tests

```bash
# Unit tests only
npm test

# Integration tests
npm run test:integration

# All tests
npm run test:all
```

### Code Style

```bash
# Format code
npm run format

# Check formatting
npm run format:check

# Lint
npm run lint

# Type check
npm run typecheck
```
