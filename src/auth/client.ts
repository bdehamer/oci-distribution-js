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
import { withRetry, type RetryOptions } from "../retry.ts";
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
  /**
   * Retry configuration for transient failures. Pass `false` to disable
   * retries. Defaults to retrying network errors and `429`/`5xx` responses.
   */
  retry?: RetryOptions | false;
}

/** Per-request options for {@link AuthClient.do}. */
export interface DoOptions {
  /** Scope hints used to pre-authenticate and to widen the requested token. */
  scopes?: string[];
  /**
   * When `false`, the request is sent without attaching or negotiating any
   * credentials. Used for requests to hosts named by a server response (e.g. a
   * blob-upload `Location` on a separate storage host), which must never
   * receive registry credentials.
   */
  authenticate?: boolean;
}

interface BearerToken {
  token: string;
  expiresAt?: number;
}

/** Out-parameter for {@link AuthClient.send}: the URL of the final hop. */
interface SendTrace {
  finalUrl?: string;
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
    const baseFetch = options.fetch ?? ((input: string | URL, init?: RequestInit) => fetch(input, init));
    this.#fetch = options.retry === false ? baseFetch : withRetry(baseFetch, options.retry ?? {});
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

    // Unauthenticated request: send as-is, never attaching credentials. Used for
    // requests to hosts named by a server response (e.g. a cross-host blob
    // upload location) that must not receive registry credentials.
    if (options.authenticate === false) {
      return this.#send(url, { ...init, headers });
    }

    // Respect a caller-provided Authorization header.
    if (headers.has("authorization")) {
      return this.#send(url, { ...init, headers });
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

    const trace: SendTrace = {};
    const response = await this.#send(url, { ...init, headers }, { trace });
    if (response.status !== 401) {
      return response;
    }

    // Only surrender credentials to the origin we intended to talk to. Fail
    // closed: if the responding origin is unknown (no final URL) or differs from
    // the target origin — e.g. a 401 served from a host reached via redirect —
    // do not negotiate or attach credentials.
    const responseOrigin = safeOrigin(trace.finalUrl ?? "");
    if (responseOrigin === null || responseOrigin !== origin) {
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
      return this.#send(url, { ...init, headers: withAuth(headers, `Basic ${token}`) });
    }

    // Bearer
    const realm = challenge.params["realm"];
    if (!realm) {
      return response;
    }
    // Refuse to hand credentials to a token endpoint that is not HTTPS (unless
    // it is loopback, for local/test registries). Blocks a malicious registry
    // from steering the Basic/OAuth2 credential to an http://attacker/token realm.
    if (!isSecureTokenEndpoint(realm)) {
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
        const retried = await this.#send(url, { ...init, headers: withAuth(headers, `Bearer ${cached}`) });
        if (retried.status !== 401) {
          return retried;
        }
        await drain(retried);
        const fresh = await this.#fetchBearerToken(realm, service, allScopes, cred);
        this.#cache.setScheme(host, "bearer");
        this.#cache.setToken(host, "bearer", key, fresh.token, fresh.expiresAt);
        return this.#send(url, { ...init, headers: withAuth(headers, `Bearer ${fresh.token}`) });
      }
    }

    await drain(response);
    const fresh = await this.#fetchBearerToken(realm, service, allScopes, cred);
    this.#cache.setScheme(host, "bearer");
    this.#cache.setToken(host, "bearer", key, fresh.token, fresh.expiresAt);
    return this.#send(url, { ...init, headers: withAuth(headers, `Bearer ${fresh.token}`) });
  }

  /**
   * Sends a request, following redirects manually and origin-safely. On a
   * redirect that changes origin, all credential-bearing and non-safelisted
   * headers are stripped before the next hop (and stay stripped for the rest of
   * the chain), so credentials are never sent to a host reached via a
   * server-controlled `Location`. Node's `fetch` strips `Authorization` on
   * cross-origin redirects but not custom headers or request bodies, so this
   * handling is done explicitly.
   */
  async #send(
    url: string,
    init: RequestInit,
    options: { refuseCrossOriginRedirect?: boolean; trace?: SendTrace } = {},
  ): Promise<Response> {
    const originalOrigin = new URL(url).origin;
    let current = url;
    let method = init.method ?? "GET";
    let body = init.body ?? undefined;
    const headers = new Headers(init.headers);
    let crossedOrigin = false;

    for (let redirects = 0; ; redirects++) {
      const sameOrigin = !crossedOrigin && new URL(current).origin === originalOrigin;
      const hopHeaders = sameOrigin ? headers : safelistHeaders(headers);

      const response = await this.#fetch(current, {
        ...init,
        method,
        body,
        headers: hopHeaders,
        redirect: "manual",
      });

      if (!isRedirectStatus(response.status)) {
        if (options.trace) {
          options.trace.finalUrl = current;
        }
        return response;
      }
      if (redirects >= MAX_REDIRECTS) {
        await drain(response);
        throw new RegistryError(`exceeded ${MAX_REDIRECTS} redirects starting at ${url}`);
      }
      const location = response.headers.get("location");
      if (!location) {
        return response; // malformed redirect; let the caller observe it
      }
      const next = new URL(location, current);
      if (next.origin !== originalOrigin) {
        if (options.refuseCrossOriginRedirect) {
          await drain(response);
          throw new RegistryError(
            `refusing to follow cross-origin redirect to ${next.origin}`,
          );
        }
        crossedOrigin = true;
      }
      await drain(response);

      // RFC 9110 method/body rewriting.
      if (response.status === 303 && method !== "GET" && method !== "HEAD") {
        method = "GET";
        body = undefined;
      } else if ((response.status === 301 || response.status === 302) && method === "POST") {
        method = "GET";
        body = undefined;
      }
      current = next.href;
    }
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

    const response = await this.#send(
      url.toString(),
      { method: "GET", headers },
      { refuseCrossOriginRedirect: true },
    );
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

    const response = await this.#send(
      realm,
      { method: "POST", headers, body: form.toString() },
      { refuseCrossOriginRedirect: true },
    );
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

/** Maximum number of redirects followed by {@link AuthClient} per request. */
const MAX_REDIRECTS = 20;

/**
 * Headers safe to forward across an origin-changing redirect. Everything else —
 * including `Authorization`, `Cookie`, `Proxy-Authorization`, and any custom
 * (potentially secret) headers — is dropped when a redirect leaves the original
 * origin.
 */
const SAFE_CROSS_ORIGIN_HEADERS = new Set([
  "accept",
  "accept-encoding",
  "range",
  "user-agent",
  "content-type",
  "content-length",
]);

function safelistHeaders(headers: Headers): Headers {
  const result = new Headers();
  for (const [key, value] of headers) {
    if (SAFE_CROSS_ORIGIN_HEADERS.has(key.toLowerCase())) {
      result.set(key, value);
    }
  }
  return result;
}

function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
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

/**
 * Returns true if a token-endpoint (`realm`) URL is safe to send credentials to:
 * HTTPS always, or plain HTTP only for loopback hosts (local/test registries).
 * Prevents a malicious registry from directing the Basic/OAuth2 credential to a
 * plaintext `http://attacker/token` endpoint.
 */
function isSecureTokenEndpoint(realm: string): boolean {
  let url: URL;
  try {
    url = new URL(realm);
  } catch {
    return false;
  }
  if (url.protocol === "https:") {
    return true;
  }
  if (url.protocol === "http:") {
    const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
  }
  return false;
}

async function drain(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // ignore
  }
}
