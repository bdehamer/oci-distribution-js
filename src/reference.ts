import { isDigest } from "./digest.ts";
import { parseDigest } from "./digest.ts";

/**
 * Parsing and validation for registry references of the form
 * `registry[:port]/repository[:tag][@digest]`.
 */

/** A parsed reference to content in a registry. */
export interface Reference {
  /** The registry host (and optional port), e.g. `ghcr.io` or `localhost:5000`. */
  registry: string;
  /** The repository name, e.g. `library/ubuntu`. */
  repository: string;
  /** The tag, if the reference included one. */
  tag?: string;
  /** The digest, if the reference included one. */
  digest?: string;
}

/**
 * Repository name grammar from the OCI Distribution Spec.
 * @see https://github.com/opencontainers/distribution-spec — Pulling manifests
 */
const REPOSITORY_RE = /^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$/;

/**
 * Tag grammar from the OCI Distribution Spec (max 128 chars).
 * @see https://github.com/opencontainers/distribution-spec — Pulling manifests
 */
const TAG_RE = /^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$/;

/** Returns true if the string is a valid repository name. */
export function isValidRepository(name: string): boolean {
  return REPOSITORY_RE.test(name);
}

/** Returns true if the string is a valid tag. */
export function isValidTag(tag: string): boolean {
  return TAG_RE.test(tag);
}

/**
 * Returns true if the first path component looks like a registry host, using
 * the same heuristic as Docker/containerd: it contains a `.` or `:`, or equals
 * `localhost`.
 */
function looksLikeRegistry(component: string): boolean {
  return component.includes(".") || component.includes(":") || component === "localhost";
}

/**
 * Parses a reference string into its components.
 *
 * The registry host is only extracted when the first path component looks like
 * a hostname (contains a dot or colon, or is `localhost`); otherwise
 * {@link Reference.registry} is the empty string and the whole value is treated
 * as a repository. A reference may carry a tag, a digest, both, or neither.
 *
 * @throws {TypeError} if the repository, tag, or digest is syntactically invalid.
 */
export function parseReference(input: string): Reference {
  if (input.length === 0) {
    throw new TypeError("reference must not be empty");
  }

  let remainder = input;
  let digest: string | undefined;
  let tag: string | undefined;

  const at = remainder.indexOf("@");
  if (at >= 0) {
    digest = remainder.slice(at + 1);
    remainder = remainder.slice(0, at);
    if (!isDigest(digest)) {
      throw new TypeError(`invalid digest in reference: ${JSON.stringify(digest)}`);
    }
  }

  let registry = "";
  let path = remainder;
  const slash = remainder.indexOf("/");
  if (slash >= 0) {
    const first = remainder.slice(0, slash);
    if (looksLikeRegistry(first)) {
      registry = first;
      path = remainder.slice(slash + 1);
    }
  }

  const colon = path.lastIndexOf(":");
  if (colon >= 0) {
    tag = path.slice(colon + 1);
    path = path.slice(0, colon);
    if (!isValidTag(tag)) {
      throw new TypeError(`invalid tag in reference: ${JSON.stringify(tag)}`);
    }
  }

  if (!isValidRepository(path)) {
    throw new TypeError(`invalid repository name in reference: ${JSON.stringify(path)}`);
  }

  const ref: Reference = { registry, repository: path };
  if (tag !== undefined) {
    ref.tag = tag;
  }
  if (digest !== undefined) {
    ref.digest = digest;
  }
  return ref;
}

/**
 * Returns the tag-or-digest portion of a reference, preferring the digest when
 * both are present. Returns `undefined` when neither is set.
 */
export function referenceTagOrDigest(ref: Reference): string | undefined {
  return ref.digest ?? ref.tag;
}

/** Serializes a reference back into its canonical string form. */
export function stringifyReference(ref: Reference): string {
  let out = ref.registry ? `${ref.registry}/${ref.repository}` : ref.repository;
  if (ref.tag) {
    out += `:${ref.tag}`;
  }
  if (ref.digest) {
    out += `@${ref.digest}`;
  }
  return out;
}

/** Characters not permitted in a tag, replaced with `-` in the referrers tag. */
const TAG_DISALLOWED = /[^a-zA-Z0-9._-]/g;

/**
 * Computes the referrers tag for a subject digest, per the Distribution Spec
 * "Referrers Tag Schema": the algorithm truncated to 32 chars, a `-`, and the
 * encoded portion truncated to 64 chars, with disallowed tag characters
 * replaced by `-`.
 *
 * @example referrersTag("sha256:abcd…") === "sha256-abcd…"
 * @see https://github.com/opencontainers/distribution-spec — Referrers Tag Schema
 */
export function referrersTag(digest: string): string {
  const { algorithm, encoded } = parseDigest(digest);
  const algo = algorithm.slice(0, 32).replace(TAG_DISALLOWED, "-");
  const enc = encoded.slice(0, 64).replace(TAG_DISALLOWED, "-");
  return `${algo}-${enc}`;
}
