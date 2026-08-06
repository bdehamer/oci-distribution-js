import { createHash, timingSafeEqual, type Hash } from "node:crypto";

/**
 * Digest utilities implementing the OCI content-addressable digest format.
 *
 * A digest is `<algorithm>:<encoded>` where, for the registered algorithms
 * `sha256` and `sha512`, `<encoded>` is the lowercase hex of the hash.
 *
 * @see https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests
 */

/** Digest algorithms with a known encoded length. */
export type DigestAlgorithm = "sha256" | "sha512";

/** The default digest algorithm used when none is specified. */
export const DEFAULT_ALGORITHM: DigestAlgorithm = "sha256";

/** Hex length (number of characters) of each registered algorithm's encoding. */
const REGISTERED: Record<string, number> = { sha256: 64, sha512: 128 };

/**
 * Matches a syntactically valid digest per the OCI grammar:
 * `algorithm-component [ separator algorithm-component ]* ":" encoded`.
 */
const DIGEST_RE = /^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+$/;

/** A parsed digest. */
export interface ParsedDigest {
  algorithm: string;
  encoded: string;
}

/** Returns true if the string is a syntactically valid digest. */
export function isDigest(value: string): boolean {
  if (!DIGEST_RE.test(value)) {
    return false;
  }
  const parsed = split(value);
  const expected = REGISTERED[parsed.algorithm];
  if (expected !== undefined) {
    return parsed.encoded.length === expected && /^[a-f0-9]+$/.test(parsed.encoded);
  }
  return true;
}

/**
 * Parses and validates a digest string, throwing if it is malformed or uses a
 * registered algorithm with an incorrect encoded length.
 */
export function parseDigest(value: string): ParsedDigest {
  if (!isDigest(value)) {
    throw new TypeError(`invalid digest: ${JSON.stringify(value)}`);
  }
  return split(value);
}

function split(value: string): ParsedDigest {
  const idx = value.indexOf(":");
  return { algorithm: value.slice(0, idx), encoded: value.slice(idx + 1) };
}

/**
 * Computes the digest of the given bytes.
 *
 * @param data - the content to hash
 * @param algorithm - the digest algorithm (default `sha256`)
 * @returns a digest string, e.g. `sha256:<hex>`
 */
export function calculateDigest(data: Uint8Array, algorithm: DigestAlgorithm = DEFAULT_ALGORITHM): string {
  return `${algorithm}:${createHash(algorithm).update(data).digest("hex")}`;
}

/**
 * Verifies that the given bytes hash to the given digest. Uses a constant-time
 * comparison. Returns false (rather than throwing) if the digest is malformed
 * or uses an algorithm unsupported by the runtime.
 */
export function verifyDigest(data: Uint8Array, digest: string): boolean {
  let parsed: ParsedDigest;
  try {
    parsed = parseDigest(digest);
  } catch {
    return false;
  }
  let actual: Buffer;
  try {
    actual = createHash(parsed.algorithm).update(data).digest();
  } catch {
    return false;
  }
  const expected = Buffer.from(parsed.encoded, "hex");
  if (expected.length !== actual.length || expected.length === 0) {
    return false;
  }
  return timingSafeEqual(actual, expected);
}

/**
 * Computes the digest of the given bytes with an arbitrary algorithm name,
 * returning `undefined` if the runtime does not support that algorithm. Useful
 * for verifying content whose digest may use a non-default algorithm.
 */
export function tryComputeDigest(data: Uint8Array, algorithm: string): string | undefined {
  try {
    return `${algorithm}:${createHash(algorithm).update(data).digest("hex")}`;
  } catch {
    return undefined;
  }
}

/**
 * An incremental digester for streaming content. Feed chunks with {@link update}
 * and read the result with {@link digest} once complete.
 */
export class Digester {
  readonly algorithm: DigestAlgorithm;
  #hash: Hash;
  #size = 0;

  constructor(algorithm: DigestAlgorithm = DEFAULT_ALGORITHM) {
    this.algorithm = algorithm;
    this.#hash = createHash(algorithm);
  }

  /** Adds a chunk of content to the running hash. */
  update(chunk: Uint8Array): this {
    this.#hash.update(chunk);
    this.#size += chunk.byteLength;
    return this;
  }

  /** The number of bytes seen so far. */
  get size(): number {
    return this.#size;
  }

  /** Finalizes and returns the digest string. The digester must not be reused. */
  digest(): string {
    return `${this.algorithm}:${this.#hash.digest("hex")}`;
  }
}
