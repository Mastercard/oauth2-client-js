import type { AccessToken, AccessTokenFilter, TokenStore } from '#types';

/**
 * In-memory implementation of {@link TokenStore}.
 * This implementation uses a `Map` to store tokens and automatically removes expired tokens
 * during put operations. Tokens are indexed by a combination of their `jkt` and sorted scopes
 * to ensure consistent lookups.
 */
export class InMemoryTokenStore implements TokenStore {
  private static readonly EXPIRATION_THRESHOLD_MS = 60 * 1000; // 60 seconds
  private readonly store = new Map<string, AccessToken>();

  /** Adds an access token to the store. */
  async put(accessToken: AccessToken): Promise<void> {
    this.removeExpiredTokens();

    // Store with scope-only key
    const scopeOnlyKey = this.createKey(undefined, accessToken.scopes);
    this.store.set(scopeOnlyKey, accessToken);

    // Also store with jkt+scope key if jkt is present
    if (accessToken.jkt) {
      const jktScopeKey = this.createKey(accessToken.jkt, accessToken.scopes);
      this.store.set(jktScopeKey, accessToken);
    }
  }

  /**
   * Retrieves an access token matching the specified filter criteria.
   * Returns `null` if no token was found, or if the stored token has expired.
   */
  async get(filter: AccessTokenFilter): Promise<AccessToken | null> {
    const key = this.createKey(filter.jkt, filter.scopes);
    const threshold = Date.now() + InMemoryTokenStore.EXPIRATION_THRESHOLD_MS;

    const existing = this.store.get(key);
    if (!existing) {
      return null;
    }

    // Remove and return null if token is expiring soon
    if (existing.expiresAt < threshold) {
      this.store.delete(key);
      return null;
    }

    return existing;
  }

  /**
   * Creates a normalized cache key from a `jkt` and scopes.
   * Scopes are sorted alphabetically to ensure consistent key generation
   * regardless of the order in which scopes are provided.
   */
  private createKey(jkt: string | undefined, scopes: Set<string>): string {
    const sorted = Array.from(scopes).sort();
    const normalizedScopes = sorted.join(' ');
    return `${jkt ?? '<none>'}|${normalizedScopes}`;
  }

  /**
   * Removes all expired tokens from the store.
   * This method is called during put operations to prevent unbounded memory growth.
   */
  private removeExpiredTokens(): void {
    const now = Date.now();
    for (const [key, accessToken] of this.store.entries()) {
      if (accessToken.expiresAt < now) {
        this.store.delete(key);
      }
    }
  }
}
