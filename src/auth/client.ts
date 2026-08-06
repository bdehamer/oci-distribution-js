import { parseChallenge } from "./challenge.ts";
import { AuthCache } from "./cache.ts";
import { mergeScopes, parseScopeParam, scopeKey } from "./scope.ts";
import {
  EMPTY_CREDENTIAL,
  encodeBasicAuth,
  isEmptyCredential,
  type Credential,
  type CredentialProvider,
} from "./credentials.ts";
import { RegistryError, ResponseError } from "../errors.ts";
import type { TokenResponse } from "../types.ts";

/** A `fetch`-compatible function. Defaults to the global `fetch`. */
export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

/** The default `client_id` sent to OAuth2 token endpoints. */
export const DEFAULT_CLIENT_ID = "oci-distribution";

/** Clock skew (ms) subtracted from token lifetimes to refresh slightly early. */
const EXPIRY_SKEW_MS = 10_000;

/** Options for constructing an {@link AuthClient}. */
export interface AuthClientOptions {
  /** Resolves credentials for a registry host. Defaults to anonymous access. */
  credentials?: CredentialProvider;
  /** Underlying fetch implementation. Defaults to the global `fetch`. */
  fetch?: FetchLike;
  /** Value of the `User-Agent` header added to requests. */
  userAgent?: string;
  /** `client_id` sent to OAuth2 token endpoints. */
  clientId?: string;
  /**
   * Always attempt the OAuth2 (POST) token grant when credentials are present,
   * even without an identity token. Some registries require this.
   */
  forceOAuth2?: boolean;
  /** Token/scheme cache. A fresh {@link AuthCache} is used when omitted. */
  cache?: AuthCache;
}

/** Per-request options for {@link AuthClient.do}. */
export interface DoOptions {
  /** Scope hints used to pre-authenticate and to widen the requested token. */
  scopes?: string[];
}

interface BearerToken {
  token: string;
  expiresAt?: number;
}

/**
 * An HTTP transport that transparently authenticates requests to OCI
 * registries. It attaches cached credentials up front and, on a `401`, parses
 * the `WWW-Authenticate` challenge, obtains a Basic or Bearer token, caches it,
 * and retries the request once.
 */
export class AuthClient {
  #credentials: CredentialProvider;
  #fetch: FetchLike;
  #userAgent: string | undefined;
  #clientId: string;
  #forceOAuth2: boolean;
  #cache: AuthCache;

  constructor(options: AuthClientOptions = {}) {
    this.#credentials = options.credentials ?? (() => EMPTY_CREDENTIAL);
    const fetchImpl = options.fetch ?? ((input: string | URL, init?: RequestInit) => fetch(input, init));
    this.#fetch = fetchImpl;
    this.#userAgent = options.userAgent;
    this.#clientId = options.clientId ?? DEFAULT_CLIENT_ID;
    this.#forceOAuth2 = options.forceOAuth2 ?? false;
    this.#cache = options.cache ?? new AuthCache();
  }

  /** The token/scheme cache in use. */
  get cache(): AuthCache {
    return this.#cache;
  }

  /**
   * Performs an authenticated request. Behaves like `fetch`, but injects
   * credentials and handles the registry token challenge. If the caller already
   * set an `Authorization` header, the request is sent unmodified.
   */
  async do(input: string | URL, init: RequestInit = {}, options: DoOptions = {}): Promise<Response> {
    const url = typeof input === "string" ? input : input.toString();
    const target = new URL(url);
    const host = target.host;
    const origin = target.origin;
    const scopes = options.scopes ?? [];

    const headers = new Headers(init.headers);
    if (this.#userAgent && !headers.has("user-agent")) {
      headers.set("user-agent", this.#userAgent);
    }

    // Respect a caller-provided Authorization header.
    if (headers.has("authorization")) {
      return this.#fetch(url, { ...init, headers });
    }

    // Attach cached credentials to avoid a challenge round-trip.
    const scheme = this.#cache.getScheme(host);
    let attemptedKey = "";
    if (scheme === "basic") {
      const token = this.#cache.getToken(host, "basic", "");
      if (token) {
        headers.set("authorization", `Basic ${token}`);
      }
    } else if (scheme === "bearer") {
      attemptedKey = scopeKey(scopes);
      const token = this.#cache.getToken(host, "bearer", attemptedKey);
      if (token) {
        headers.set("authorization", `Bearer ${token}`);
      }
    }

    const response = await this.#fetch(url, { ...init, headers });
    if (response.status !== 401) {
      return response;
    }

    // Only surrender credentials to the origin we intended to talk to.
    if (safeOrigin(response.url) !== null && safeOrigin(response.url) !== origin) {
      return response;
    }

    const wwwAuth = response.headers.get("www-authenticate");
    if (!wwwAuth) {
      return response;
    }
    const challenge = parseChallenge(wwwAuth);
    if (challenge.scheme === "unknown") {
      return response;
    }

    const cred = (await this.#credentials(host)) ?? EMPTY_CREDENTIAL;

    if (challenge.scheme === "basic") {
      if (!cred.username || !cred.password) {
        return response; // no credentials to offer; surface the 401
      }
      await drain(response);
      const token = encodeBasicAuth(cred.username, cred.password);
      this.#cache.setScheme(host, "basic");
      this.#cache.setToken(host, "basic", "", token);
      return this.#fetch(url, { ...init, headers: withAuth(headers, `Basic ${token}`) });
    }

    // Bearer
    const realm = challenge.params["realm"];
    if (!realm) {
      return response;
    }
    const service = challenge.params["service"] ?? "";
    const allScopes = mergeScopes(scopes, parseScopeParam(challenge.params["scope"]));
    const key = allScopes.join(" ");

    // A wider scope may already have a cached token from a prior request.
    if (key !== attemptedKey) {
      const cached = this.#cache.getToken(host, "bearer", key);
      if (cached) {
        await drain(response);
        const retried = await this.#fetch(url, { ...init, headers: withAuth(headers, `Bearer ${cached}`) });
        if (retried.status !== 401) {
          return retried;
        }
        await drain(retried);
        const fresh = await this.#fetchBearerToken(realm, service, allScopes, cred);
        this.#cache.setScheme(host, "bearer");
        this.#cache.setToken(host, "bearer", key, fresh.token, fresh.expiresAt);
        return this.#fetch(url, { ...init, headers: withAuth(headers, `Bearer ${fresh.token}`) });
      }
    }

    await drain(response);
    const fresh = await this.#fetchBearerToken(realm, service, allScopes, cred);
    this.#cache.setScheme(host, "bearer");
    this.#cache.setToken(host, "bearer", key, fresh.token, fresh.expiresAt);
    return this.#fetch(url, { ...init, headers: withAuth(headers, `Bearer ${fresh.token}`) });
  }

  async #fetchBearerToken(
    realm: string,
    service: string,
    scopes: string[],
    cred: Credential,
  ): Promise<BearerToken> {
    if (cred.accessToken) {
      return { token: cred.accessToken };
    }
    const useOAuth2 = !isEmptyCredential(cred) && (!!cred.refreshToken || this.#forceOAuth2);
    return useOAuth2
      ? this.#fetchOAuth2Token(realm, service, scopes, cred)
      : this.#fetchDistributionToken(realm, service, scopes, cred);
  }

  async #fetchDistributionToken(
    realm: string,
    service: string,
    scopes: string[],
    cred: Credential,
  ): Promise<BearerToken> {
    const url = new URL(realm);
    if (service) {
      url.searchParams.set("service", service);
    }
    for (const scope of scopes) {
      url.searchParams.append("scope", scope);
    }

    const headers = new Headers({ accept: "application/json" });
    if (this.#userAgent) {
      headers.set("user-agent", this.#userAgent);
    }
    if (cred.username || cred.password) {
      headers.set("authorization", `Basic ${encodeBasicAuth(cred.username ?? "", cred.password ?? "")}`);
    }

    const response = await this.#fetch(url.toString(), { method: "GET", headers });
    if (!response.ok) {
      throw await ResponseError.fromResponse(response, "GET", url.toString());
    }
    const body = (await response.json()) as TokenResponse;
    const token = body.access_token || body.token;
    if (!token) {
      throw new RegistryError(`token endpoint ${realm} returned no token`);
    }
    return { token, expiresAt: computeExpiry(body) };
  }

  async #fetchOAuth2Token(
    realm: string,
    service: string,
    scopes: string[],
    cred: Credential,
  ): Promise<BearerToken> {
    const form = new URLSearchParams();
    if (cred.refreshToken) {
      form.set("grant_type", "refresh_token");
      form.set("refresh_token", cred.refreshToken);
    } else if (cred.username && cred.password) {
      form.set("grant_type", "password");
      form.set("username", cred.username);
      form.set("password", cred.password);
    } else {
      // Nothing usable for an OAuth2 grant; fall back to the GET flow.
      return this.#fetchDistributionToken(realm, service, scopes, cred);
    }
    form.set("service", service);
    form.set("client_id", this.#clientId);
    if (scopes.length > 0) {
      form.set("scope", scopes.join(" "));
    }

    const headers = new Headers({
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    });
    if (this.#userAgent) {
      headers.set("user-agent", this.#userAgent);
    }

    const response = await this.#fetch(realm, { method: "POST", headers, body: form.toString() });
    if (!response.ok) {
      // Registries lacking OAuth2 support answer 404/405/501; retry via GET.
      if (response.status === 404 || response.status === 405 || response.status === 501) {
        await drain(response);
        return this.#fetchDistributionToken(realm, service, scopes, cred);
      }
      throw await ResponseError.fromResponse(response, "POST", realm);
    }
    const body = (await response.json()) as TokenResponse;
    const token = body.access_token || body.token;
    if (!token) {
      throw new RegistryError(`token endpoint ${realm} returned no token`);
    }
    return { token, expiresAt: computeExpiry(body) };
  }
}

function withAuth(base: Headers, authorization: string): Headers {
  const headers = new Headers(base);
  headers.set("authorization", authorization);
  return headers;
}

function computeExpiry(body: TokenResponse): number | undefined {
  if (typeof body.expires_in === "number" && body.expires_in > 0) {
    return Date.now() + Math.max(body.expires_in * 1000 - EXPIRY_SKEW_MS, 0);
  }
  return undefined;
}

function safeOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

async function drain(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // ignore
  }
}
