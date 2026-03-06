import type { ScopeResolver } from '#types';

/**
 * A {@link ScopeResolver} that always returns a fixed list of scopes regardless of the URL.
 */
export class StaticScopeResolver implements ScopeResolver {
  private readonly scopes: ReadonlySet<string>;

  /**
   * Creates a new {@link StaticScopeResolver} with the given scopes.
   */
  constructor(scopes: string[]) {
    this.scopes = new Set(scopes);
  }

  /** Returns all possible scopes that can be requested. */
  allScopes(): Promise<Set<string>> {
    return Promise.resolve(new Set(this.scopes));
  }

  /** Returns a set of scopes to request (always returns the same scopes regardless of URL). */
  resolveScopes(_httpMethod: string, _url: string): Promise<Set<string>> {
    return Promise.resolve(new Set(this.scopes));
  }
}
