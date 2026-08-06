/**
 * Media type constants for OCI and Docker artifacts.
 *
 * @see https://github.com/opencontainers/image-spec/blob/main/media-types.md
 */

// --- OCI Image Spec ---
export const MEDIA_TYPE_OCI_IMAGE_INDEX = "application/vnd.oci.image.index.v1+json";
export const MEDIA_TYPE_OCI_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
export const MEDIA_TYPE_OCI_IMAGE_CONFIG = "application/vnd.oci.image.config.v1+json";
export const MEDIA_TYPE_OCI_LAYER = "application/vnd.oci.image.layer.v1.tar";
export const MEDIA_TYPE_OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip";
export const MEDIA_TYPE_OCI_LAYER_ZSTD = "application/vnd.oci.image.layer.v1.tar+zstd";
export const MEDIA_TYPE_OCI_EMPTY = "application/vnd.oci.empty.v1+json";

// --- Docker (Registry v2, schema 2) ---
export const MEDIA_TYPE_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";
export const MEDIA_TYPE_DOCKER_MANIFEST_LIST =
  "application/vnd.docker.distribution.manifest.list.v2+json";
export const MEDIA_TYPE_DOCKER_IMAGE_CONFIG = "application/vnd.docker.container.image.v1+json";
export const MEDIA_TYPE_DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip";
export const MEDIA_TYPE_DOCKER_FOREIGN_LAYER =
  "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";

// --- Generic ---
export const MEDIA_TYPE_OCTET_STREAM = "application/octet-stream";

/**
 * The canonical body of an `application/vnd.oci.empty.v1+json` blob: the two
 * bytes `{}`. Used as the config of artifact manifests that have no config.
 */
export const EMPTY_JSON = "{}";

/**
 * Media types that identify a manifest (image manifest or index), in the order
 * preferred for the default `Accept` header when pulling manifests.
 */
export const MANIFEST_MEDIA_TYPES: readonly string[] = [
  MEDIA_TYPE_OCI_IMAGE_INDEX,
  MEDIA_TYPE_OCI_IMAGE_MANIFEST,
  MEDIA_TYPE_DOCKER_MANIFEST_LIST,
  MEDIA_TYPE_DOCKER_MANIFEST,
];

/** Returns true if the given media type denotes an image index / manifest list. */
export function isIndexMediaType(mediaType: string | undefined): boolean {
  return mediaType === MEDIA_TYPE_OCI_IMAGE_INDEX || mediaType === MEDIA_TYPE_DOCKER_MANIFEST_LIST;
}

/** Returns true if the given media type denotes a single image manifest. */
export function isImageManifestMediaType(mediaType: string | undefined): boolean {
  return mediaType === MEDIA_TYPE_OCI_IMAGE_MANIFEST || mediaType === MEDIA_TYPE_DOCKER_MANIFEST;
}

/** Returns true if the given media type denotes any kind of manifest. */
export function isManifestMediaType(mediaType: string | undefined): boolean {
  return isIndexMediaType(mediaType) || isImageManifestMediaType(mediaType);
}
