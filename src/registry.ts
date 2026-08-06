import { AuthClient, type AuthClientOptions, type FetchLike } from "./auth/client.ts";
import type { AuthCache } from "./auth/cache.ts";
import type { CredentialProvider } from "./auth/credentials.ts";
import { isValidRepository } from "./reference.ts";
import { Repository } from "./repository.ts";

/** The default `User-Agent` sent by the client. */
export const USER_AGENT = "oci-distribution";

/** Options for constructing a {@link Registry}. */
export interface RegistryOptions {
  /** Resolves credentials for a registry host. Defaults to anonymous access. */
  credentials?: CredentialProvider;
  /** Underlying fetch implementation. Defaults to the global `fetch`. */
  fetch?: FetchLike;
  /** Value of the `User-Agent` header. Defaults to `"oci-distribution"`. */
  userAgent?: string;
  /** `client_id` sent to OAuth2 token endpoints. */
  clientId?: string;
  /** Always attempt the OAuth2 token grant when credentials are present. */
  forceOAuth2?: boolean;
  /**
   * Use `http` instead of `https`. Defaults to `true` for loopback hosts
   * (`localhost`, `127.0.0.1`, `::1`) and `false` otherwise. An explicit
   * `http://` / `https://` scheme in the host string also sets this.
   */
  plainHTTP?: boolean;
  /** Extra headers added to every request. */
  headers?: Headers | Record<string, string>;
  /** A shared auth cache. A fresh one is created when omitted. */
  cache?: AuthCache;
}

/**
 * A client for a single OCI registry host. Create {@link Repository} instances
 * from it to perform blob, manifest, tag, and referrer operations.
 */
export class Registry {
  /** The registry host (and optional port), e.g. `ghcr.io`. */
  readonly host: string;
  /** The URL scheme in use, `http` or `https`. */
  readonly scheme: "http" | "https";
  readonly #auth: AuthClient;
  readonly #headers: Headers;

  constructor(host: string, options: RegistryOptions = {}) {
    const parsed = splitHost(host);
    this.host = parsed.host;
    const plain = options.plainHTTP ?? parsed.plainHTTP ?? isLoopback(parsed.host);
    this.scheme = plain ? "http" : "https";
    this.#headers = new Headers(options.headers);

    const authOptions: AuthClientOptions = {
      userAgent: options.userAgent ?? USER_AGENT,
    };
    if (options.credentials !== undefined) authOptions.credentials = options.credentials;
    if (options.fetch !== undefined) authOptions.fetch = options.fetch;
    if (options.clientId !== undefined) authOptions.clientId = options.clientId;
    if (options.forceOAuth2 !== undefined) authOptions.forceOAuth2 = options.forceOAuth2;
    if (options.cache !== undefined) authOptions.cache = options.cache;
    this.#auth = new AuthClient(authOptions);
  }

  /** The underlying authenticating transport. */
  get auth(): AuthClient {
    return this.#auth;
  }

  /** Resolves a path or URL against this registry's base URL. */
  resolveUrl(ref: string): string {
    return new URL(ref, `${this.scheme}://${this.host}`).toString();
  }

  /**
   * Performs an authenticated request against this registry. `ref` may be an
   * absolute URL or a path (e.g. `/v2/...`); `scopes` are authorization scope
   * hints used to pre-authenticate the request.
   */
  do(ref: string, init: RequestInit = {}, scopes: string[] = []): Promise<Response> {
    const headers = new Headers(this.#headers);
    if (init.headers) {
      for (const [key, value] of new Headers(init.headers)) {
        headers.set(key, value);
      }
    }
    return this.#auth.do(this.resolveUrl(ref), { ...init, headers }, { scopes });
  }

  /** Creates a {@link Repository} within this registry. */
  repository(name: string): Repository {
    if (!isValidRepository(name)) {
      throw new TypeError(`invalid repository name: ${JSON.stringify(name)}`);
    }
    return new Repository(this, name);
  }

  /**
   * Checks whether the registry implements the distribution API by requesting
   * `GET /v2/`. Returns true on `200` (supported) or `401` (supported, but
   * authentication is required).
   */
  async ping(): Promise<boolean> {
    const response = await this.do("/v2/", { method: "GET" });
    const ok = response.status === 200 || response.status === 401;
    await response.body?.cancel().catch(() => {});
    return ok;
  }
}

interface HostParts {
  host: string;
  plainHTTP?: boolean;
}

function splitHost(input: string): HostParts {
  if (input.includes("://")) {
    const url = new URL(input);
    return { host: url.host, plainHTTP: url.protocol === "http:" };
  }
  // Strip any path component that may have been included.
  const slash = input.indexOf("/");
  const host = slash >= 0 ? input.slice(0, slash) : input;
  if (host.length === 0) {
    throw new TypeError(`invalid registry host: ${JSON.stringify(input)}`);
  }
  return { host };
}

function isLoopback(host: string): boolean {
  const name = host.replace(/:\d+$/, "").toLowerCase();
  return name === "localhost" || name === "127.0.0.1" || name === "::1" || name === "[::1]";
}
