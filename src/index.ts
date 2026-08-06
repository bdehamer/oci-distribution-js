/**
 * A zero-dependency TypeScript client for the OCI Distribution Specification.
 *
 * @see https://github.com/opencontainers/distribution-spec
 * @packageDocumentation
 */

// Core client
export { Registry, USER_AGENT, type RegistryOptions } from "./registry.ts";
export {
  Repository,
  BlobStore,
  ManifestStore,
  TagStore,
  ReferrerStore,
  type BlobPushOptions,
  type ManifestPushOptions,
  type TagListOptions,
  type ReferrerListOptions,
  type PackManifestOptions,
  type FetchedManifest,
} from "./repository.ts";

// Types
export type {
  Descriptor,
  Platform,
  ImageManifest,
  ImageIndex,
  Manifest,
  TagList,
  TokenResponse,
  Bytes,
} from "./types.ts";

// Media types
export * from "./media-types.ts";

// Retry
export { withRetry, type RetryOptions } from "./retry.ts";

// Digest utilities
export {
  calculateDigest,
  verifyDigest,
  parseDigest,
  isDigest,
  tryComputeDigest,
  Digester,
  DEFAULT_ALGORITHM,
  type DigestAlgorithm,
  type ParsedDigest,
} from "./digest.ts";

// Reference parsing
export {
  parseReference,
  stringifyReference,
  referenceTagOrDigest,
  referrersTag,
  isValidRepository,
  isValidTag,
  type Reference,
} from "./reference.ts";

// Errors
export {
  RegistryError,
  ResponseError,
  DigestMismatchError,
  SizeMismatchError,
  NotFoundError,
  ErrorCode,
  parseOCIErrors,
  type OCIErrorInfo,
  type ResponseErrorInit,
} from "./errors.ts";

// Authentication
export {
  AuthClient,
  DEFAULT_CLIENT_ID,
  type AuthClientOptions,
  type DoOptions,
  type FetchLike,
} from "./auth/client.ts";
export { AuthCache } from "./auth/cache.ts";
export { parseChallenge, type Challenge, type Scheme } from "./auth/challenge.ts";
export {
  scopeRepository,
  cleanScopes,
  mergeScopes,
  scopeKey,
  parseScopeParam,
  ACTION_PULL,
  ACTION_PUSH,
  ACTION_DELETE,
} from "./auth/scope.ts";
export {
  EMPTY_CREDENTIAL,
  encodeBasicAuth,
  normalizeRegistry,
  isEmptyCredential,
  staticCredential,
  basicCredential,
  chainCredentials,
  type Credential,
  type CredentialProvider,
} from "./auth/credentials.ts";
export {
  dockerConfigCredential,
  dockerConfigHeaders,
  type DockerConfigOptions,
  type DockerConfigHeadersOptions,
  type HelperResult,
  type HelperRunner,
} from "./auth/docker-config.ts";
