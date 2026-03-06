import { InMemoryTokenStore } from '@mastercard/oauth2-client-js';

export class TestTokenStore extends InMemoryTokenStore {
  expireToken(jkt: string | undefined, scopes: Set<string>): void {
    const sorted = Array.from(scopes).sort();
    const normalizedScopes = sorted.join(' ');
    const key = `${jkt ?? '<none>'}|${normalizedScopes}`;
    const entry = (this as any).store.get(key);
    if (entry) {
      // Set expiration to past
      entry.expiresAt = Date.now() - 1000;
    }
  }
}
