/**
 * A drop-in-compatible reimplementation of the public API of
 * [`@sigstore/oci`](https://github.com/sigstore/sigstore-js/tree/main/packages/oci),
 * implemented on top of the zero-dependency `oci-distribution` client.
 *
 * This package is intentionally kept separate from the core library so that
 * `oci-distribution` carries no Sigstore-specific surface area. It exists to
 * demonstrate that `oci-distribution` can back a real consumer such as
 * `actions/attest` with only a thin adapter.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Buffer } from "node:buffer";
import {
  Registry,
  parseReference,
  normalizeRegistry,
  type Credential,
  type CredentialProvider,
  type Descriptor,
  type RegistryOptions,
  type RetryOptions,
} from "oci-distribution";

export type { Descriptor };

/** Credentials for a registry, matching `@sigstore/oci`'s `Credentials` type. */
export interface Credentials {
  readonly username: string;
  readonly password: string;
  readonly headers?: { [key: string]: string };
}

/** Per-request options. */
export interface FetchOptions {
  /** Retry configuration forwarded to the underlying client. */
  readonly retry?: RetryOptions | false;
}

/** Options for {@link attachArtifactToImage}. */
export interface AttachArtifactOptions {
  readonly imageName: string;
  readonly imageDigest: string;
  readonly artifact: Buffer | Uint8Array;
  readonly mediaType: string;
  readonly credentials: Credentials;
  readonly annotations?: Record<string, string>;
  readonly fetchOpts?: FetchOptions;
}

/** Options for {@link getImageDigest}. */
export interface GetImageDigestOptions {
  readonly imageName: string;
  readonly imageTag: string;
  readonly credentials: Credentials;
  readonly fetchOpts?: FetchOptions;
}

/** Error thrown when an OCI operation fails, matching `@sigstore/oci`. */
export class OCIError extends Error {
  override name = "OCIError";

  constructor(opts: { message: string; cause?: unknown }) {
    super(opts.message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
  }
}

/**
 * Associates the given artifact with an OCI image, attaching it via the
 * `subject` field / referrers mechanism. Mirrors
 * `@sigstore/oci#attachArtifactToImage`.
 */
export async function attachArtifactToImage(opts: AttachArtifactOptions): Promise<Descriptor> {
  try {
    const repo = repositoryFor(opts.imageName, opts.credentials, opts.fetchOpts);

    // Confirm the subject image exists and resolve its descriptor.
    const subject = await repo.resolve(opts.imageDigest);

    // Upload the artifact blob.
    const layer = await repo.blobs.push({ mediaType: opts.mediaType }, toUint8Array(opts.artifact));

    const annotations = {
      "org.opencontainers.image.created": new Date().toISOString(),
      ...opts.annotations,
    };

    // Attach the artifact manifest. The core client probes the referrers API
    // and falls back to the tag schema when it is unsupported (e.g. AWS ECR).
    return await repo.attachArtifact(subject, opts.mediaType, [layer], { annotations });
  } catch (err) {
    throw new OCIError({ message: "Error uploading artifact to container registry", cause: err });
  }
}

/** Returns the digest of the given image tag. Mirrors `@sigstore/oci#getImageDigest`. */
export async function getImageDigest(opts: GetImageDigestOptions): Promise<string> {
  try {
    const repo = repositoryFor(opts.imageName, opts.credentials, opts.fetchOpts);
    const descriptor = await repo.resolve(opts.imageTag);
    return descriptor.digest;
  } catch (err) {
    throw new OCIError({ message: "Error resolving image digest", cause: err });
  }
}

/**
 * Reads credentials for the registry of the given image from the Docker config
 * file (`~/.docker/config.json`). Mirrors `@sigstore/oci#getRegistryCredentials`.
 *
 * @throws if the config file is missing or has no entry for the registry.
 */
export function getRegistryCredentials(imageName: string): Credentials {
  const { registry } = parseReference(imageName);
  const dockerConfigFile = path.join(os.homedir(), ".docker", "config.json");

  let content: string;
  try {
    content = fs.readFileSync(dockerConfigFile, "utf8");
  } catch (err) {
    throw new Error(`No credential file found at ${dockerConfigFile}`, { cause: err });
  }

  const config = JSON.parse(content) as {
    auths?: Record<string, { auth?: string; identitytoken?: string }>;
    HttpHeaders?: Record<string, string>;
  };

  const target = canonicalize(registry);
  const key = Object.keys(config.auths ?? {}).find((k) => canonicalize(k) === target);
  const creds = key ? config.auths?.[key] : undefined;
  if (!creds || !creds.auth) {
    throw new Error(`No credentials found for registry ${registry}`);
  }

  const { username, password } = fromBasicAuth(creds.auth);
  // Prefer an identity token as the password (primarily for ACR).
  const pass = creds.identitytoken ? creds.identitytoken : password;

  return config.HttpHeaders
    ? { username, password: pass, headers: config.HttpHeaders }
    : { username, password: pass };
}

function repositoryFor(imageName: string, credentials: Credentials, fetchOpts?: FetchOptions) {
  const ref = parseReference(imageName);
  if (!ref.registry) {
    throw new OCIError({ message: `image name must include a registry: ${imageName}` });
  }
  const options: RegistryOptions = { credentials: credentialProvider(ref.registry, credentials) };
  if (credentials.headers) {
    options.headers = credentials.headers;
  }
  if (fetchOpts?.retry !== undefined) {
    options.retry = fetchOpts.retry;
  }
  return new Registry(ref.registry, options).repository(ref.repository);
}

function credentialProvider(registry: string, creds: Credentials): CredentialProvider {
  // A username of "<token>" signals an identity/refresh token (drives OAuth2).
  const credential: Credential =
    creds.username === "<token>"
      ? { refreshToken: creds.password }
      : { username: creds.username, password: creds.password };
  const target = normalizeRegistry(registry);
  return (host) => (normalizeRegistry(host) === target ? credential : {});
}

function toUint8Array(data: Buffer | Uint8Array): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data);
}

// Well-known Docker Hub aliases, collapsed for auth-key matching.
const DOCKER_HUB_ALIASES = new Set(["docker.io", "index.docker.io", "registry-1.docker.io"]);

function canonicalize(value: string): string {
  let host = value.replace(/^https?:\/\//, "");
  host = host.split("/")[0] ?? host;
  return DOCKER_HUB_ALIASES.has(host) ? "docker.io" : host;
}

function fromBasicAuth(auth: string): { username: string; password: string } {
  const decoded = Buffer.from(auth, "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  if (idx < 0) {
    return { username: decoded, password: "" };
  }
  return { username: decoded.slice(0, idx), password: decoded.slice(idx + 1) };
}
