import type { Registry } from "./registry.ts";
import type { Descriptor, ImageIndex, ImageManifest, Manifest, TagList } from "./types.ts";
import {
  EMPTY_JSON,
  MANIFEST_MEDIA_TYPES,
  MEDIA_TYPE_OCI_EMPTY,
  MEDIA_TYPE_OCI_IMAGE_INDEX,
  MEDIA_TYPE_OCI_IMAGE_MANIFEST,
} from "./media-types.ts";
import { calculateDigest, isDigest, parseDigest, tryComputeDigest } from "./digest.ts";
import { referrersTag } from "./reference.ts";
import {
  DigestMismatchError,
  NotFoundError,
  RegistryError,
  ResponseError,
  SizeMismatchError,
} from "./errors.ts";
import { ACTION_DELETE, ACTION_PULL, ACTION_PUSH, scopeRepository } from "./auth/scope.ts";

/** Shared per-repository context passed to the content stores. */
interface Ctx {
  registry: Registry;
  name: string;
  path(sub: string): string;
  do(
    ref: string,
    init: RequestInit,
    scopes: string[],
    options?: { authenticate?: boolean },
  ): Promise<Response>;
  pullScope: string;
  pushScope: string;
  deleteScope: string;
}

/** A subset of manifest fields used when normalizing pushed content. */
interface ParsedManifest {
  mediaType?: string;
  artifactType?: string;
  subject?: Descriptor;
  annotations?: Record<string, string>;
  config?: Descriptor;
  manifests?: Descriptor[];
}

/** Options for pushing a blob. */
export interface BlobPushOptions {
  /** Skip the "already exists" HEAD check and always upload. */
  force?: boolean;
}

/** Options for pushing a manifest. */
export interface ManifestPushOptions {
  /** The `Content-Type` to send. Defaults to the manifest's `mediaType`. */
  mediaType?: string;
  /** The artifact type recorded in the returned/referrer descriptor. */
  artifactType?: string;
  /**
   * When the manifest has a `subject` and the registry does not acknowledge it
   * via the `OCI-Subject` header, update the referrers tag-schema index.
   * Defaults to `true`.
   */
  updateReferrers?: boolean;
  /**
   * Force updating the referrers tag-schema index even when the registry does
   * return an `OCI-Subject` header. Needed for registries such as AWS ECR that
   * report a subject but do not actually implement the referrers API.
   */
  forceReferrersTag?: boolean;
}

/** Options for listing tags. */
export interface TagListOptions {
  /** Maximum number of tags to return. */
  n?: number;
  /** Return tags lexically after this value. */
  last?: string;
}

/** Options for listing referrers. */
export interface ReferrerListOptions {
  /** Only return referrers whose `artifactType` matches this value. */
  artifactType?: string;
}

/** Options for {@link Repository.packManifest}. */
export interface PackManifestOptions {
  /** The artifact type of the manifest. */
  artifactType?: string;
  /** The subject this manifest refers to. */
  subject?: Descriptor;
  /** Layer descriptors (already pushed as blobs). */
  layers?: Descriptor[];
  /** The config descriptor. Defaults to the OCI empty config `{}`. */
  config?: Descriptor;
  /** Manifest annotations. */
  annotations?: Record<string, string>;
  /** An optional tag to apply to the pushed manifest. */
  tag?: string;
  /**
   * When a subject is present, probe the referrers API (see
   * {@link ReferrerStore.ping}) and fall back to maintaining the referrers
   * tag-schema index when it is unsupported. Defaults to `true`; this costs one
   * extra request but is required for correctness on registries like AWS ECR
   * that return an `OCI-Subject` header without supporting the referrers API.
   */
  checkReferrersApi?: boolean;
  /**
   * Force (or suppress) the referrers tag-schema update regardless of API
   * support. When set, {@link checkReferrersApi} is not consulted.
   */
  forceReferrersTag?: boolean;
}

/**
 * A repository within a {@link Registry}, exposing blob, manifest, tag, and
 * referrer operations for the OCI Distribution API.
 */
export class Repository {
  readonly registry: Registry;
  readonly name: string;
  /** Blob operations. */
  readonly blobs: BlobStore;
  /** Manifest operations. */
  readonly manifests: ManifestStore;
  /** Tag listing operations. */
  readonly tags: TagStore;
  /** Referrer listing operations. */
  readonly referrers: ReferrerStore;

  constructor(registry: Registry, name: string) {
    this.registry = registry;
    this.name = name;
    const ctx: Ctx = {
      registry,
      name,
      path: (sub) => `/v2/${name}${sub}`,
      do: (ref, init, scopes, options) => registry.do(ref, init, scopes, options),
      pullScope: scopeRepository(name, [ACTION_PULL]),
      pushScope: scopeRepository(name, [ACTION_PUSH, ACTION_PULL]),
      deleteScope: scopeRepository(name, [ACTION_DELETE]),
    };
    this.blobs = new BlobStore(ctx);
    this.manifests = new ManifestStore(ctx);
    this.tags = new TagStore(ctx);
    this.referrers = new ReferrerStore(ctx);
  }

  /** Resolves a tag or digest to a manifest {@link Descriptor} via `HEAD`. */
  resolve(reference: string): Promise<Descriptor> {
    return this.manifests.resolve(reference);
  }

  /** Fetches the raw manifest bytes and descriptor for a tag or digest. */
  fetchManifest(reference: string): Promise<FetchedManifest> {
    return this.manifests.fetch(reference);
  }

  /** Fetches and parses a manifest for a tag or digest. */
  getManifest(reference: string): Promise<{ descriptor: Descriptor; manifest: Manifest }> {
    return this.manifests.get(reference);
  }

  /** Pushes a manifest by tag or digest. */
  pushManifest(
    reference: string | undefined,
    data: Uint8Array,
    options?: ManifestPushOptions,
  ): Promise<Descriptor> {
    return this.manifests.push(reference, data, options);
  }

  /** Pushes a blob. */
  pushBlob(
    descriptor: { mediaType: string; digest?: string; size?: number },
    data: Uint8Array,
    options?: BlobPushOptions,
  ): Promise<Descriptor> {
    return this.blobs.push(descriptor, data, options);
  }

  /**
   * Builds and pushes an OCI artifact manifest that references the given
   * layers, config, subject, and annotations — the general-purpose way to
   * "attach" an artifact to another manifest.
   *
   * If no config is provided, the OCI empty config (`{}` with media type
   * `application/vnd.oci.empty.v1+json`) is pushed and used, matching the
   * layout used by, for example, the Sigstore cosign bundle specification.
   *
   * @returns the descriptor of the pushed artifact manifest.
   */
  async packManifest(options: PackManifestOptions = {}): Promise<Descriptor> {
    const config = options.config ?? (await this.#pushEmptyConfig());
    const manifest: ImageManifest = {
      schemaVersion: 2,
      mediaType: MEDIA_TYPE_OCI_IMAGE_MANIFEST,
      config,
      layers: options.layers ?? [],
    };
    if (options.artifactType) {
      manifest.artifactType = options.artifactType;
    }
    if (options.subject) {
      manifest.subject = options.subject;
    }
    if (options.annotations) {
      manifest.annotations = options.annotations;
    }

    const data = encodeJSON(manifest);
    const pushOptions: ManifestPushOptions = { mediaType: MEDIA_TYPE_OCI_IMAGE_MANIFEST };
    if (options.artifactType) {
      pushOptions.artifactType = options.artifactType;
    }
    if (manifest.subject) {
      if (options.forceReferrersTag !== undefined) {
        pushOptions.forceReferrersTag = options.forceReferrersTag;
      } else if (options.checkReferrersApi !== false) {
        // Probe the referrers API; if unsupported, force the tag-schema update
        // even when the registry reports an OCI-Subject header (e.g. AWS ECR).
        pushOptions.forceReferrersTag = !(await this.referrers.ping());
      }
    }
    return this.manifests.push(options.tag, data, pushOptions);
  }

  /**
   * Convenience wrapper over {@link packManifest} that attaches an artifact of
   * the given type, referencing `layers`, to `subject`.
   */
  attachArtifact(
    subject: Descriptor,
    artifactType: string,
    layers: Descriptor[],
    options: Omit<PackManifestOptions, "subject" | "artifactType" | "layers"> = {},
  ): Promise<Descriptor> {
    return this.packManifest({ ...options, subject, artifactType, layers });
  }

  /** The OCI empty config descriptor (`{}` / `application/vnd.oci.empty.v1+json`). */
  emptyConfigDescriptor(): Descriptor {
    const bytes = encodeText(EMPTY_JSON);
    return { mediaType: MEDIA_TYPE_OCI_EMPTY, digest: calculateDigest(bytes), size: bytes.byteLength };
  }

  async #pushEmptyConfig(): Promise<Descriptor> {
    const bytes = encodeText(EMPTY_JSON);
    const descriptor: Descriptor = {
      mediaType: MEDIA_TYPE_OCI_EMPTY,
      digest: calculateDigest(bytes),
      size: bytes.byteLength,
    };
    await this.blobs.push(descriptor, bytes);
    return descriptor;
  }
}

/** The result of fetching a manifest: its descriptor and raw bytes. */
export interface FetchedManifest {
  descriptor: Descriptor;
  data: Uint8Array;
}

/** Blob operations for a repository. */
export class BlobStore {
  readonly #ctx: Ctx;

  constructor(ctx: Ctx) {
    this.#ctx = ctx;
  }

  /** Returns true if a blob with the given digest exists (`HEAD`). */
  async exists(digest: string): Promise<boolean> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/blobs/${digest}`),
      { method: "HEAD" },
      [this.#ctx.pullScope],
    );
    if (response.status === 200) {
      await drain(response);
      return true;
    }
    if (response.status === 404) {
      await drain(response);
      return false;
    }
    throw await ResponseError.fromResponse(response, "HEAD");
  }

  /**
   * Fetches a blob, returning the raw {@link Response} so the caller can stream
   * the body (`response.body`) or read it whole. Throws on a non-2xx response.
   */
  async fetchResponse(digest: string): Promise<Response> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/blobs/${digest}`),
      { method: "GET" },
      [this.#ctx.pullScope],
    );
    if (response.status === 404) {
      await drain(response);
      throw new NotFoundError(digest);
    }
    if (!response.ok) {
      throw await ResponseError.fromResponse(response, "GET");
    }
    return response;
  }

  /** Fetches a blob fully into memory, verifying it against its digest. */
  async get(digest: string): Promise<Uint8Array> {
    const response = await this.fetchResponse(digest);
    const data = new Uint8Array(await response.arrayBuffer());
    ensureDigest(data, digest);
    return data;
  }

  /**
   * Pushes a blob monolithically (`POST` then `PUT`). If the blob already
   * exists it is not re-uploaded unless `options.force` is set.
   *
   * @returns the blob's descriptor.
   */
  async push(
    descriptor: { mediaType: string; digest?: string; size?: number },
    data: Uint8Array,
    options: BlobPushOptions = {},
  ): Promise<Descriptor> {
    const digest = descriptor.digest ?? calculateDigest(data);
    if (descriptor.size !== undefined && descriptor.size !== data.byteLength) {
      throw new SizeMismatchError(descriptor.size, data.byteLength);
    }
    const size = data.byteLength;

    if (!options.force && (await this.exists(digest))) {
      return { mediaType: descriptor.mediaType, digest, size };
    }

    const post = await this.#ctx.do(
      this.#ctx.path("/blobs/uploads/"),
      { method: "POST", headers: { "content-length": "0" } },
      [this.#ctx.pushScope],
    );
    if (post.status === 201) {
      await drain(post);
      return { mediaType: descriptor.mediaType, digest, size };
    }
    if (post.status !== 202) {
      throw await ResponseError.fromResponse(post, "POST");
    }
    const location = post.headers.get("location");
    await drain(post);
    if (!location) {
      throw new RegistryError("registry did not return an upload location");
    }

    const putUrl = addQuery(this.#ctx.registry.resolveUrl(location), "digest", digest);
    // If the registry offloaded the upload to a different host (a common
    // pattern with pre-signed storage URLs), send the blob there WITHOUT any
    // registry credentials — the host came from a server response and must not
    // receive the registry token or credential headers.
    const crossHost = safeHost(putUrl) !== this.#ctx.registry.host;
    const put = await this.#ctx.do(
      putUrl,
      {
        method: "PUT",
        headers: { "content-type": "application/octet-stream", "content-length": String(size) },
        body: data,
      },
      crossHost ? [] : [this.#ctx.pushScope],
      crossHost ? { authenticate: false } : undefined,
    );
    if (put.status !== 201) {
      throw await ResponseError.fromResponse(put, "PUT");
    }
    await drain(put);
    return { mediaType: descriptor.mediaType, digest, size };
  }

  /**
   * Attempts to mount a blob from another repository in the same registry.
   * Returns the descriptor on success, or `null` if the registry declined to
   * mount (in which case the blob should be pushed normally).
   */
  async mount(descriptor: Descriptor, fromRepository: string): Promise<Descriptor | null> {
    const params = new URLSearchParams({ mount: descriptor.digest, from: fromRepository });
    const response = await this.#ctx.do(
      this.#ctx.path(`/blobs/uploads/?${params.toString()}`),
      { method: "POST", headers: { "content-length": "0" } },
      [this.#ctx.pushScope, scopeRepository(fromRepository, [ACTION_PULL])],
    );
    if (response.status === 201) {
      await drain(response);
      return descriptor;
    }
    if (response.status === 202) {
      const location = response.headers.get("location");
      await drain(response);
      if (location) {
        try {
          const cancel = await this.#ctx.do(
            this.#ctx.registry.resolveUrl(location),
            { method: "DELETE" },
            [this.#ctx.pushScope],
          );
          await drain(cancel);
        } catch {
          // best-effort cleanup
        }
      }
      return null;
    }
    throw await ResponseError.fromResponse(response, "POST");
  }

  /** Deletes a blob by digest. */
  async delete(digest: string): Promise<void> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/blobs/${digest}`),
      { method: "DELETE" },
      [this.#ctx.deleteScope],
    );
    if (response.status === 202 || response.status === 200) {
      await drain(response);
      return;
    }
    throw await ResponseError.fromResponse(response, "DELETE");
  }
}

/** Manifest operations for a repository. */
export class ManifestStore {
  readonly #ctx: Ctx;

  constructor(ctx: Ctx) {
    this.#ctx = ctx;
  }

  /** Returns true if a manifest exists for the tag or digest (`HEAD`). */
  async exists(reference: string): Promise<boolean> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/manifests/${reference}`),
      { method: "HEAD", headers: { accept: acceptManifests() } },
      [this.#ctx.pullScope],
    );
    if (response.status === 200) {
      await drain(response);
      return true;
    }
    if (response.status === 404) {
      await drain(response);
      return false;
    }
    throw await ResponseError.fromResponse(response, "HEAD");
  }

  /** Resolves a tag or digest to a descriptor via `HEAD`. */
  async resolve(reference: string): Promise<Descriptor> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/manifests/${reference}`),
      { method: "HEAD", headers: { accept: acceptManifests() } },
      [this.#ctx.pullScope],
    );
    if (response.status === 404) {
      await drain(response);
      throw new NotFoundError(reference);
    }
    if (!response.ok) {
      throw await ResponseError.fromResponse(response, "HEAD");
    }
    const descriptor = descriptorFromHeaders(response, reference);
    await drain(response);
    return descriptor;
  }

  /** Fetches the raw manifest bytes and descriptor for a tag or digest. */
  async fetch(reference: string): Promise<FetchedManifest> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/manifests/${reference}`),
      { method: "GET", headers: { accept: acceptManifests() } },
      [this.#ctx.pullScope],
    );
    if (response.status === 404) {
      await drain(response);
      throw new NotFoundError(reference);
    }
    if (!response.ok) {
      throw await ResponseError.fromResponse(response, "GET");
    }
    const data = new Uint8Array(await response.arrayBuffer());
    if (isDigest(reference)) {
      ensureDigest(data, reference);
    }
    const digest = contentDigest(response) ?? (isDigest(reference) ? reference : calculateDigest(data));
    const mediaType = mediaTypeOf(response) ?? detectMediaType(data) ?? MEDIA_TYPE_OCI_IMAGE_MANIFEST;
    return { descriptor: { mediaType, digest, size: data.byteLength }, data };
  }

  /** Fetches and parses a manifest for a tag or digest. */
  async get(reference: string): Promise<{ descriptor: Descriptor; manifest: Manifest }> {
    const { descriptor, data } = await this.fetch(reference);
    return { descriptor, manifest: JSON.parse(decodeText(data)) as Manifest };
  }

  /**
   * Pushes a manifest (or index) by tag or digest. When `reference` is omitted
   * the manifest is pushed by its digest.
   *
   * If the manifest carries a `subject` and the registry does not return an
   * `OCI-Subject` header, the referrers tag-schema index for the subject is
   * updated automatically (unless `options.updateReferrers` is `false`).
   */
  async push(
    reference: string | undefined,
    data: Uint8Array,
    options: ManifestPushOptions = {},
  ): Promise<Descriptor> {
    const parsed = tryParseManifest(data);
    const mediaType = options.mediaType ?? parsed?.mediaType ?? MEDIA_TYPE_OCI_IMAGE_MANIFEST;
    const digest = calculateDigest(data);
    const target = reference ?? digest;

    const response = await this.#ctx.do(
      this.#ctx.path(`/manifests/${target}`),
      { method: "PUT", headers: { "content-type": mediaType }, body: data },
      [this.#ctx.pushScope],
    );
    if (response.status !== 201) {
      throw await ResponseError.fromResponse(response, "PUT");
    }
    const returnedDigest = contentDigest(response) ?? digest;
    const ociSubject = response.headers.get("oci-subject");
    await drain(response);

    const artifactType = options.artifactType ?? parsed?.artifactType;
    const descriptor: Descriptor = { mediaType, digest: returnedDigest, size: data.byteLength };
    if (artifactType) {
      descriptor.artifactType = artifactType;
    }
    if (parsed?.annotations) {
      descriptor.annotations = parsed.annotations;
    }

    const subject = parsed?.subject;
    if (
      subject &&
      options.updateReferrers !== false &&
      (options.forceReferrersTag === true || !ociSubject)
    ) {
      await this.#appendReferrer(subject.digest, buildReferrerDescriptor(descriptor, parsed));
    }

    return descriptor;
  }

  /** Deletes a manifest or tag. */
  async delete(reference: string): Promise<void> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/manifests/${reference}`),
      { method: "DELETE" },
      [this.#ctx.deleteScope],
    );
    if (response.status === 202 || response.status === 200) {
      await drain(response);
      return;
    }
    throw await ResponseError.fromResponse(response, "DELETE");
  }

  async #appendReferrer(subjectDigest: string, referrer: Descriptor): Promise<void> {
    const tag = referrersTag(subjectDigest);
    const index = (await this.#fetchIndexOrNull(tag)) ?? emptyIndex();
    if (index.manifests.some((m) => m.digest === referrer.digest)) {
      return;
    }
    index.manifests.push(referrer);
    await this.push(tag, encodeJSON(index), {
      mediaType: MEDIA_TYPE_OCI_IMAGE_INDEX,
      updateReferrers: false,
    });
  }

  async #fetchIndexOrNull(reference: string): Promise<ImageIndex | null> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/manifests/${reference}`),
      { method: "GET", headers: { accept: MEDIA_TYPE_OCI_IMAGE_INDEX } },
      [this.#ctx.pullScope],
    );
    if (response.status === 404) {
      await drain(response);
      return null;
    }
    if (!response.ok) {
      throw await ResponseError.fromResponse(response, "GET");
    }
    const index = JSON.parse(decodeText(new Uint8Array(await response.arrayBuffer()))) as ImageIndex;
    if (!Array.isArray(index.manifests)) {
      throw new RegistryError(`referrers tag ${reference} is not an image index`);
    }
    return index;
  }
}

/** Tag listing operations for a repository. */
export class TagStore {
  readonly #ctx: Ctx;

  constructor(ctx: Ctx) {
    this.#ctx = ctx;
  }

  /** Lists a single page of tags. */
  async list(options: TagListOptions = {}): Promise<TagList> {
    const params = new URLSearchParams();
    if (options.n !== undefined) {
      params.set("n", String(options.n));
    }
    if (options.last) {
      params.set("last", options.last);
    }
    const query = params.toString();
    const response = await this.#ctx.do(
      this.#ctx.path(`/tags/list${query ? `?${query}` : ""}`),
      { method: "GET", headers: { accept: "application/json" } },
      [this.#ctx.pullScope],
    );
    if (!response.ok) {
      throw await ResponseError.fromResponse(response, "GET");
    }
    return (await response.json()) as TagList;
  }

  /** Lists all tags, following `Link` pagination. */
  async listAll(pageSize?: number): Promise<string[]> {
    const tags: string[] = [];
    let next: string | null = this.#ctx.path(`/tags/list${pageSize ? `?n=${pageSize}` : ""}`);
    while (next) {
      const response = await this.#ctx.do(
        next,
        { method: "GET", headers: { accept: "application/json" } },
        [this.#ctx.pullScope],
      );
      if (!response.ok) {
        throw await ResponseError.fromResponse(response, "GET");
      }
      const body = (await response.json()) as TagList;
      if (Array.isArray(body.tags)) {
        tags.push(...body.tags);
      }
      const link = parseNextLink(response.headers.get("link"));
      next = link ? this.#ctx.registry.resolveUrl(link) : null;
    }
    return tags;
  }
}

/** Referrer listing operations for a repository. */
export class ReferrerStore {
  readonly #ctx: Ctx;

  constructor(ctx: Ctx) {
    this.#ctx = ctx;
  }

  /**
   * Lists the referrers of a subject digest as an image index. Uses the
   * referrers API when available, transparently falling back to the referrers
   * tag schema on `404`. Follows `Link` pagination and applies the
   * `artifactType` filter (server-side when supported, client-side otherwise).
   */
  async list(subjectDigest: string, options: ReferrerListOptions = {}): Promise<ImageIndex> {
    const artifactType = options.artifactType;
    const query = artifactType ? `?artifactType=${encodeURIComponent(artifactType)}` : "";
    const first = await this.#ctx.do(
      this.#ctx.path(`/referrers/${subjectDigest}${query}`),
      { method: "GET", headers: { accept: MEDIA_TYPE_OCI_IMAGE_INDEX } },
      [this.#ctx.pullScope],
    );

    if (first.status === 404) {
      await drain(first);
      return this.#fallback(subjectDigest, artifactType);
    }
    if (!first.ok) {
      throw await ResponseError.fromResponse(first, "GET");
    }

    const collected: Descriptor[] = [];
    let response: Response = first;
    for (;;) {
      const index = JSON.parse(decodeText(new Uint8Array(await response.arrayBuffer()))) as ImageIndex;
      if (Array.isArray(index.manifests)) {
        collected.push(...index.manifests);
      }
      const link = parseNextLink(response.headers.get("link"));
      if (!link) {
        break;
      }
      response = await this.#ctx.do(
        this.#ctx.registry.resolveUrl(link),
        { method: "GET", headers: { accept: MEDIA_TYPE_OCI_IMAGE_INDEX } },
        [this.#ctx.pullScope],
      );
      if (!response.ok) {
        throw await ResponseError.fromResponse(response, "GET");
      }
    }

    return buildIndex(filterByArtifactType(collected, artifactType));
  }

  async #fallback(subjectDigest: string, artifactType: string | undefined): Promise<ImageIndex> {
    const tag = referrersTag(subjectDigest);
    const response = await this.#ctx.do(
      this.#ctx.path(`/manifests/${tag}`),
      { method: "GET", headers: { accept: MEDIA_TYPE_OCI_IMAGE_INDEX } },
      [this.#ctx.pullScope],
    );
    if (response.status === 404) {
      await drain(response);
      return emptyIndex();
    }
    if (!response.ok) {
      throw await ResponseError.fromResponse(response, "GET");
    }
    let index: ImageIndex;
    try {
      index = JSON.parse(decodeText(new Uint8Array(await response.arrayBuffer()))) as ImageIndex;
    } catch {
      return emptyIndex();
    }
    const manifests = Array.isArray(index.manifests) ? index.manifests : [];
    return buildIndex(filterByArtifactType(manifests, artifactType));
  }

  /**
   * Probes whether the registry supports the referrers API, by requesting the
   * referrers of the all-zero digest and checking for a `200` response. This is
   * the reliable way to detect support: some registries (notably AWS ECR)
   * return an `OCI-Subject` header on manifest push without actually serving the
   * referrers API.
   */
  async ping(): Promise<boolean> {
    const response = await this.#ctx.do(
      this.#ctx.path(`/referrers/${ZERO_DIGEST}`),
      { method: "GET", headers: { accept: MEDIA_TYPE_OCI_IMAGE_INDEX } },
      [this.#ctx.pullScope],
    );
    const supported = response.status === 200;
    await drain(response);
    return supported;
  }
}

// --- module-scope helpers ---

/** The all-zero sha256 digest, used to probe referrers API support. */
const ZERO_DIGEST = `sha256:${"0".repeat(64)}`;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function encodeText(value: string): Uint8Array {
  return textEncoder.encode(value);
}

function decodeText(data: Uint8Array): string {
  return textDecoder.decode(data);
}

function encodeJSON(value: unknown): Uint8Array {
  return textEncoder.encode(JSON.stringify(value));
}

function acceptManifests(): string {
  return MANIFEST_MEDIA_TYPES.join(", ");
}

function contentDigest(response: Response): string | undefined {
  return response.headers.get("docker-content-digest") ?? undefined;
}

function mediaTypeOf(response: Response): string | undefined {
  const contentType = response.headers.get("content-type");
  return contentType ? contentType.split(";")[0]?.trim() : undefined;
}

function descriptorFromHeaders(response: Response, reference: string): Descriptor {
  const digest = contentDigest(response) ?? (isDigest(reference) ? reference : undefined);
  if (!digest) {
    throw new RegistryError("registry response did not include a content digest");
  }
  const lengthHeader = response.headers.get("content-length");
  const size = lengthHeader ? Number(lengthHeader) : 0;
  const mediaType = mediaTypeOf(response) ?? MEDIA_TYPE_OCI_IMAGE_MANIFEST;
  return { mediaType, digest, size };
}

function detectMediaType(data: Uint8Array): string | undefined {
  const parsed = tryParseManifest(data);
  return parsed?.mediaType;
}

function tryParseManifest(data: Uint8Array): ParsedManifest | undefined {
  try {
    const parsed = JSON.parse(decodeText(data)) as unknown;
    if (typeof parsed === "object" && parsed !== null) {
      return parsed as ParsedManifest;
    }
  } catch {
    // not JSON
  }
  return undefined;
}

function buildReferrerDescriptor(descriptor: Descriptor, manifest: ParsedManifest): Descriptor {
  const referrer: Descriptor = {
    mediaType: descriptor.mediaType,
    digest: descriptor.digest,
    size: descriptor.size,
  };
  const artifactType = manifest.artifactType ?? manifest.config?.mediaType;
  if (artifactType) {
    referrer.artifactType = artifactType;
  }
  if (manifest.annotations) {
    referrer.annotations = manifest.annotations;
  }
  return referrer;
}

function filterByArtifactType(
  descriptors: Descriptor[],
  artifactType: string | undefined,
): Descriptor[] {
  if (!artifactType) {
    return descriptors;
  }
  return descriptors.filter((d) => d.artifactType === artifactType);
}

function buildIndex(manifests: Descriptor[]): ImageIndex {
  return { schemaVersion: 2, mediaType: MEDIA_TYPE_OCI_IMAGE_INDEX, manifests };
}

function emptyIndex(): ImageIndex {
  return buildIndex([]);
}

function ensureDigest(data: Uint8Array, digest: string): void {
  const { algorithm } = parseDigest(digest);
  const actual = tryComputeDigest(data, algorithm);
  if (actual === undefined) {
    return; // algorithm unsupported by the runtime; cannot verify
  }
  if (actual !== digest) {
    throw new DigestMismatchError(digest, actual);
  }
}

function addQuery(url: string, key: string, value: string): string {
  const parsed = new URL(url);
  parsed.searchParams.set(key, value);
  return parsed.toString();
}

function safeHost(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

function parseNextLink(header: string | null): string | null {
  if (!header) {
    return null;
  }
  for (const part of header.split(",")) {
    const match = part.match(/<([^>]+)>\s*;\s*(.+)/);
    if (!match) {
      continue;
    }
    const url = match[1];
    const params = match[2];
    if (url && params && /rel\s*=\s*"?next"?/i.test(params)) {
      return url;
    }
  }
  return null;
}

async function drain(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // ignore
  }
}
