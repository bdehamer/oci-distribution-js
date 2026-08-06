import type { Scheme } from "./challenge.ts";

/**
 * An in-memory cache of the authentication scheme learned for each registry
 * host and the tokens obtained for each `(host, scheme, scope)` combination.
 * This lets steady-state requests attach credentials up front and skip the
 * `401` challenge round-trip.
 */

interface TokenEntry {
  token: string;
  expiresAt?: number;
}

const SEP = "\u0000";

export class AuthCache {
  #schemes = new Map<string, Scheme>();
  #tokens = new Map<string, TokenEntry>();

  /** Returns the scheme previously learned for a host, if any. */
  getScheme(host: string): Scheme | undefined {
    return this.#schemes.get(host);
  }

  /** Records the scheme learned for a host. */
  setScheme(host: string, scheme: Scheme): void {
    this.#schemes.set(host, scheme);
  }

  /**
   * Returns a cached, unexpired token for the given host/scheme/scope key, or
   * `undefined` if absent or expired.
   */
  getToken(host: string, scheme: Scheme, scopeKey: string): string | undefined {
    const key = tokenKey(host, scheme, scopeKey);
    const entry = this.#tokens.get(key);
    if (!entry) {
      return undefined;
    }
    if (entry.expiresAt !== undefined && Date.now() >= entry.expiresAt) {
      this.#tokens.delete(key);
      return undefined;
    }
    return entry.token;
  }

  /**
   * Caches a token for the given host/scheme/scope key. `expiresAt` is an
   * absolute epoch-milliseconds timestamp; omit it for tokens that do not
   * expire (e.g. Basic).
   */
  setToken(
    host: string,
    scheme: Scheme,
    scopeKey: string,
    token: string,
    expiresAt?: number,
  ): void {
    const entry: TokenEntry = { token };
    if (expiresAt !== undefined) {
      entry.expiresAt = expiresAt;
    }
    this.#tokens.set(tokenKey(host, scheme, scopeKey), entry);
  }

  /** Clears cached state for one host, or the entire cache when host is omitted. */
  clear(host?: string): void {
    if (host === undefined) {
      this.#schemes.clear();
      this.#tokens.clear();
      return;
    }
    this.#schemes.delete(host);
    const prefix = `${host}${SEP}`;
    for (const key of this.#tokens.keys()) {
      if (key.startsWith(prefix)) {
        this.#tokens.delete(key);
      }
    }
  }
}

function tokenKey(host: string, scheme: Scheme, scopeKey: string): string {
  return `${host}${SEP}${scheme}${SEP}${scopeKey}`;
}
