# API Reference

This document provides detailed documentation for the low-level API components of the OAuth2 Client library.

## Table of Contents

- [Core Classes](#core-classes)
  - [OAuth2Client](#oauth2client)
  - [OAuth2ClientBuilder](#oauth2clientbuilder)
- [Interfaces](#interfaces)
  - [TokenStore](#tokenstore)
  - [ScopeResolver](#scoperesolver)
  - [DPoPKeyProvider](#dpopkeyprovider)
  - [Logger](#logger)
- [Providers and Stores](#providers-and-stores)
  - [StaticDPoPKeyProvider](#staticdpopkeyprovider)
  - [StaticScopeResolver](#staticscoperesolver)
  - [InMemoryTokenStore](#inmemorytokenstore)

---

## Core Classes

### `OAuth2Client`

The main interface for OAuth2 authentication. Acts as an orchestrator for adding OAuth2 authentication to API requests.

**Location:** [`src/core/client.ts`](../src/core/client.ts)

**Methods:**

#### `getOAuth2Headers(method, url, headers?)`

Generates OAuth2 headers (`Authorization`, `DPoP`, etc.) for a resource server request.

```typescript
const headers = await oauth2Client.getOAuth2Headers('GET', 'https://api.example.com/resource');
// Returns: { 'Authorization': 'DPoP <token>', 'DPoP': '<proof>', ... }
```

**Parameters:**
- `method: string` - HTTP method (GET, POST, etc.)
- `url: string` - Target URL for the request
- `headers?: Record<string, string>` - Optional existing headers to merge

**Returns:** `Promise<Record<string, string>>` - Headers including Authorization and DPoP proof

---

#### `handleServerResponse(statusCode, responseHeaders, httpMethod, url)`

Processes server response to handle DPoP nonce updates and authentication errors. When a `use_dpop_nonce` error is detected (HTTP 401 with `DPoP-Nonce` header), this method automatically:
1. Caches the new nonce from the response
2. Refreshes the access token if not already cached
3. Returns updated headers (including new `Authorization` and `DPoP` proof) for retry

Returns `undefined` if no retry is needed.

See: [RFC 9449 Section 8](https://datatracker.ietf.org/doc/html/rfc9449#section-8)

```typescript
const retryHeaders = await oauth2Client.handleServerResponse(
  401,
  responseHeaders,
  'GET',
  'https://api.example.com/resource'
);

if (retryHeaders) {
  // Retry the request with updated headers
}
```

**Parameters:**
- `statusCode: number` - HTTP response status code
- `responseHeaders: Record<string, string>` - Response headers
- `httpMethod: string` - Original HTTP method
- `url: string` - Original request URL

**Returns:** `Promise<Record<string, string> | undefined>` - Updated headers for retry, or `undefined` if no retry needed

---

### `OAuth2ClientBuilder`

Fluent builder for constructing `OAuth2Client` instances. Provides validation on build.

**Location:** [`src/core/builder.ts`](../src/core/builder.ts)

**Methods:**

| Method | Description | Required |
|--------|-------------|----------|
| `.clientId(id: string)` | Sets the OAuth2 client identifier | Yes |
| `.clientKey(key: CryptoKey)` | Sets the private key for `private_key_jwt` authentication | Yes |
| `.kid(kid: string)` | Sets the key identifier for the client key | Yes |
| `.tokenEndpoint(url: string)` | Sets the OAuth2 token endpoint URL | Yes |
| `.issuer(url: string)` | Sets the authorization server's issuer identifier | Yes |
| `.scopeResolver(resolver: ScopeResolver)` | Sets the scope resolver | Yes |
| `.dPoPKeyProvider(provider: DPoPKeyProvider)` | Sets the DPoP key provider | Yes |
| `.tokenStore(store: TokenStore)` | Sets the token storage (default: `InMemoryTokenStore`) | No |
| `.httpAdapter(adapter: HttpAdapter)` | Sets the HTTP adapter (default: `FetchHttpAdapter`) | No |
| `.clockSkewTolerance(seconds: number)` | Sets clock skew tolerance in seconds (default: 0) | No |
| `.securityProfile(profile: SecurityProfile)` | Sets the security profile (default: FAPI 2.0) | No |
| `.userAgent(userAgent: string)` | Sets a custom User-Agent header | No |
| `.logger(logger: Logger)` | Sets a custom logger | No |
| `.build()` | Builds and returns the `OAuth2Client` instance | - |

**Example:**

```typescript
import {
  OAuth2ClientBuilder,
  StaticDPoPKeyProvider,
  StaticScopeResolver
} from '@mastercard/oauth2-client-js';

const client = new OAuth2ClientBuilder()
  .clientId('your-client-id')
  .kid('your-key-id')
  .clientKey(clientPrivateKey)
  .tokenEndpoint('https://api.example.com/oauth/token')
  .issuer('https://api.example.com')
  .scopeResolver(new StaticScopeResolver(['scope1', 'scope2']))
  .dPoPKeyProvider(new StaticDPoPKeyProvider(dpopPrivateKey, dpopPublicKey))
  .clockSkewTolerance(10)
  .build();
```

---

## Interfaces

### `TokenStore`

Interface for caching and retrieving OAuth 2.0 access tokens.

```typescript
interface TokenStore {
  put(accessToken: AccessToken): Promise<void>;
  get(filter: AccessTokenFilter): Promise<AccessToken | null>;
}
```

### `ScopeResolver`

Resolves OAuth2 scopes for API requests.

```typescript
interface ScopeResolver {
  resolveScopes(httpMethod: string, url: string): Promise<Set<string>>;
  allScopes(): Promise<Set<string>>;
}
```

### `DPoPKeyProvider`

Provides DPoP key pairs for proof generation.

```typescript
interface DPoPKeyProvider {
  getCurrentKey(): DPoPKey;
  getKey(kid: string): DPoPKey;
}

interface DPoPKey {
  getKeyPair(): KeyPair;
  getKeyId(): Promise<string>;
}
```

### `Logger`

Logging interface for diagnostic output.

```typescript
interface Logger {
  trace(...data: any[]): void;
  debug(...data: any[]): void;
  info(...data: any[]): void;
  warn(...data: any[]): void;
  error(...data: any[]): void;
}
```

---

## Providers and Stores

### `StaticDPoPKeyProvider`

Provides a static DPoP key pair. Suitable for scenarios where key rotation is not required.

**Location:** [`src/security/extension/dpop.ts`](../src/security/extension/dpop.ts)

**Constructor:**

```typescript
const provider = new StaticDPoPKeyProvider(privateKey, publicKey);
```

**Parameters:**
- `privateKey: CryptoKey` - Private key for signing DPoP proofs
- `publicKey: CryptoKey` - Public key (included in DPoP proof header)

**Methods:**

| Method | Description |
|--------|-------------|
| `getCurrentKey()` | Returns the current DPoP key |
| `getKey(kid: string)` | Returns the key by identifier (always returns the same key) |

---

### `StaticScopeResolver`

Returns a fixed set of scopes regardless of the request URL.

**Location:** [`src/scope/static.ts`](../src/scope/static.ts)

**Constructor:**

```typescript
const resolver = new StaticScopeResolver(['read:pets', 'write:pets']);
```

**Methods:**

| Method | Description |
|--------|-------------|
| `resolveScopes(httpMethod, url)` | Returns the configured scopes |
| `allScopes()` | Returns all possible scopes |

---

### `InMemoryTokenStore`

Thread-safe in-memory token cache with automatic expiration cleanup.

**Location:** [`src/tokens/store.ts`](../src/tokens/store.ts)

**Constructor:**

```typescript
const store = new InMemoryTokenStore();
```

**Features:**
- Automatic cleanup of expired tokens during `put` operations
- 60-second expiration threshold (tokens expiring within 60 seconds are considered expired)
- Keys generated from `jkt` (JWK thumbprint) and sorted scopes

**Methods:**

| Method | Description |
|--------|-------------|
| `put(accessToken)` | Stores an access token |
| `get(filter)` | Retrieves a token matching the filter criteria |

---
