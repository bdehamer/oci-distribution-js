/**
 * Core OCI Image and Distribution Spec data types.
 *
 * @see https://github.com/opencontainers/image-spec/blob/main/descriptor.md
 * @see https://github.com/opencontainers/image-spec/blob/main/manifest.md
 * @see https://github.com/opencontainers/image-spec/blob/main/image-index.md
 */

/** A platform description, as used in an image index's descriptors. */
export interface Platform {
  architecture: string;
  os: string;
  "os.version"?: string;
  "os.features"?: string[];
  variant?: string;
  features?: string[];
}

/**
 * An OCI Content Descriptor: a reference to content addressed by digest.
 *
 * @see https://github.com/opencontainers/image-spec/blob/main/descriptor.md
 */
export interface Descriptor {
  /** The media type of the referenced content. */
  mediaType: string;
  /** The digest of the content, e.g. `sha256:<hex>`. */
  digest: string;
  /** The size, in bytes, of the raw content. */
  size: number;
  /** Optional list of URLs from which the content may also be downloaded. */
  urls?: string[];
  /** Arbitrary metadata for this descriptor. */
  annotations?: Record<string, string>;
  /** Optional base64-encoded embedding of the referenced content. */
  data?: string;
  /** The type of an artifact, when the descriptor points at an artifact manifest. */
  artifactType?: string;
  /** Describes the minimum runtime requirements, for image manifests. */
  platform?: Platform;
}

/**
 * An OCI Image Manifest (or Docker schema 2 manifest).
 *
 * @see https://github.com/opencontainers/image-spec/blob/main/manifest.md
 */
export interface ImageManifest {
  schemaVersion: 2;
  mediaType?: string;
  /** The type of artifact represented by this manifest, when applicable. */
  artifactType?: string;
  /** A descriptor referencing the configuration object. */
  config: Descriptor;
  /** An array of descriptors referencing the layers. May be empty. */
  layers: Descriptor[];
  /** An optional descriptor referencing another manifest this one refers to. */
  subject?: Descriptor;
  annotations?: Record<string, string>;
}

/**
 * An OCI Image Index (or Docker manifest list).
 *
 * @see https://github.com/opencontainers/image-spec/blob/main/image-index.md
 */
export interface ImageIndex {
  schemaVersion: 2;
  mediaType?: string;
  artifactType?: string;
  /** The manifests referenced by this index. */
  manifests: Descriptor[];
  subject?: Descriptor;
  annotations?: Record<string, string>;
}

/** Either kind of top-level manifest. */
export type Manifest = ImageManifest | ImageIndex;

/**
 * The response body of the tags listing endpoint.
 *
 * @see https://github.com/opencontainers/distribution-spec — Listing Tags
 */
export interface TagList {
  name: string;
  tags: string[];
}

/**
 * A token response from a registry token/authorization endpoint.
 *
 * @see https://distribution.github.io/distribution/spec/auth/token/
 */
export interface TokenResponse {
  token?: string;
  access_token?: string;
  expires_in?: number;
  issued_at?: string;
  refresh_token?: string;
}

/** Content that can be pushed as a blob or manifest body of known length. */
export type Bytes = Uint8Array;
