import { Buffer } from "node:buffer";

/**
 * Credentials and credential providers for registry authentication.
 *
 * The {@link Credential} shape mirrors the fields used across the container
 * ecosystem (Docker, oras): a username/password pair, an identity/refresh
 * token exchanged at the token endpoint, and/or a registry access token used
 * directly as a bearer token.
 */

/** A set of credentials for a single registry. */
export interface Credential {
  /** Username for the registry. */
  username?: string;
  /** Password (or personal access token) for the registry. */
  password?: string;
  /**
   * Identity token presented to the authorization server to obtain access
   * tokens (the Docker "identity token"). Triggers the OAuth2 grant.
   */
  refreshToken?: string;
  /**
   * Access token sent directly to the registry as a bearer token, bypassing
   * the token exchange entirely.
   */
  accessToken?: string;
}

/** A credential with no fields set; represents anonymous access. */
export const EMPTY_CREDENTIAL: Credential = {};

/**
 * Resolves credentials for a registry host. The `registry` argument is the
 * host (and optional port), e.g. `registry-1.docker.io` or `localhost:5000`.
 * Returning `undefined` or an empty credential means anonymous access.
 */
export type CredentialProvider = (
  registry: string,
) => Credential | undefined | Promise<Credential | undefined>;

/** Returns true if the credential carries no usable secret. */
export function isEmptyCredential(cred: Credential | undefined): cred is undefined {
  return (
    !cred ||
    (!cred.username && !cred.password && !cred.refreshToken && !cred.accessToken)
  );
}

/** Encodes a username and password into an HTTP Basic credential value. */
export function encodeBasicAuth(username: string, password: string): string {
  return Buffer.from(`${username}:${password}`, "utf8").toString("base64");
}

/**
 * Normalizes a registry host for credential matching, collapsing the several
 * aliases used for Docker Hub onto a single canonical host.
 */
export function normalizeRegistry(registry: string): string {
  if (registry === "docker.io" || registry === "index.docker.io" || registry === "registry.hub.docker.com") {
    return "registry-1.docker.io";
  }
  return registry;
}

/**
 * A credential provider that always returns the given credential for the
 * given registry (and anonymous access for any other registry).
 */
export function staticCredential(registry: string, cred: Credential): CredentialProvider {
  const target = normalizeRegistry(registry);
  return (host) => (normalizeRegistry(host) === target ? cred : EMPTY_CREDENTIAL);
}

/**
 * A credential provider for HTTP Basic username/password authentication with a
 * single registry. Convenience wrapper over {@link staticCredential}.
 */
export function basicCredential(
  registry: string,
  username: string,
  password: string,
): CredentialProvider {
  return staticCredential(registry, { username, password });
}

/**
 * Combines several providers into one. The first provider to return a
 * non-empty credential for the requested registry wins; otherwise the result
 * is an empty (anonymous) credential.
 */
export function chainCredentials(...providers: CredentialProvider[]): CredentialProvider {
  return async (registry) => {
    for (const provider of providers) {
      const cred = await provider(registry);
      if (!isEmptyCredential(cred)) {
        return cred;
      }
    }
    return EMPTY_CREDENTIAL;
  };
}
