# oci-distribution

A zero-dependency TypeScript client for the [OCI Distribution Specification][dist-spec].
It supports both read and write operations against any standards-compliant OCI
registry, with the standard authentication mechanisms (bearer-token challenge,
HTTP basic, and Docker config files).

- **No production dependencies.** Built entirely on the Node.js standard library
  (`fetch`, `node:crypto`, `node:http`).
- **Full lifecycle.** Pull, push, content discovery (tags & referrers), and
  content management (deletion).
- **Standard auth.** Token challenge (`WWW-Authenticate`), OAuth2 refresh-token
  grant, HTTP basic, and `~/.docker/config.json` (including credential helpers).
- **Resilient.** Automatic retry/backoff for transient failures, Docker Hub host
  canonicalization, and referrers handling that copes with registries (like AWS
  ECR) that report a subject but don't implement the referrers API.
- **OCI 1.1 artifacts.** First-class `subject`/referrers support, so it can be
  used as the foundation for artifact specs such as the
  [Sigstore cosign bundle spec][bundle-spec] (see [below](#building-on-top-the-sigstore-bundle-spec)).

## Requirements

Node.js `^22.22.2 || ^24.15.0 || >=26.0.0`. The package is published as ESM.

## Install

```sh
npm install oci-distribution
```

## Quick start

```ts
import { Registry } from "oci-distribution";

const registry = new Registry("ghcr.io");
const repo = registry.repository("owner/app");

// Resolve a tag to a descriptor (HEAD).
const descriptor = await repo.resolve("latest");

// Fetch and parse a manifest.
const { manifest } = await repo.getManifest("latest");

// Pull the first layer blob (digest-verified).
const firstLayer = (manifest as import("oci-distribution").ImageManifest).layers[0];
const bytes = await repo.blobs.get(firstLayer.digest);
```

## Authentication

Pass a **credential provider** — a function from a registry host to a credential
— via the `credentials` option. Several are built in.

### HTTP basic (username / password)

```ts
import { Registry, basicCredential } from "oci-distribution";

const registry = new Registry("ghcr.io", {
  credentials: basicCredential("ghcr.io", "octocat", process.env.GITHUB_TOKEN!),
});
```

### Docker config file

Reads `~/.docker/config.json` (or `$DOCKER_CONFIG/config.json`), honoring inline
`auths`, `credsStore`, and `credHelpers` (credential helper binaries):

```ts
import { Registry, dockerConfigCredential } from "oci-distribution";

const registry = new Registry("ghcr.io", {
  credentials: dockerConfigCredential(),
});
```

### Combining sources

```ts
import { Registry, chainCredentials, basicCredential, dockerConfigCredential } from "oci-distribution";

const registry = new Registry("ghcr.io", {
  credentials: chainCredentials(
    basicCredential("ghcr.io", "octocat", process.env.GITHUB_TOKEN ?? ""),
    dockerConfigCredential(),
  ),
});
```

### Custom provider

A provider is just a function; it may be async:

```ts
const registry = new Registry("registry.example.com", {
  credentials: async (host) => ({ refreshToken: await fetchIdentityToken(host) }),
});
```

The token-challenge flow (parsing `WWW-Authenticate`, fetching a token from the
authorization server via the distribution `GET` or OAuth2 `POST` grant, caching
it per host and scope, and retrying) is handled automatically. Set
`forceOAuth2: true` to always use the OAuth2 grant when credentials are present.

## Pushing content

Push blobs first, then the manifest that references them:

```ts
import { Registry, MEDIA_TYPE_OCI_IMAGE_MANIFEST, calculateDigest } from "oci-distribution";

const repo = new Registry("ghcr.io", { credentials }).repository("owner/app");

const layer = new TextEncoder().encode("layer contents");
const layerDescriptor = await repo.blobs.push(
  { mediaType: "application/vnd.oci.image.layer.v1.tar" },
  layer,
);

const manifest = new TextEncoder().encode(JSON.stringify({
  schemaVersion: 2,
  mediaType: MEDIA_TYPE_OCI_IMAGE_MANIFEST,
  config: repo.emptyConfigDescriptor(),
  layers: [layerDescriptor],
}));

const manifestDescriptor = await repo.manifests.push("v1", manifest, {
  mediaType: MEDIA_TYPE_OCI_IMAGE_MANIFEST,
});
```

`packManifest` builds and pushes an OCI artifact manifest for you (pushing the
empty `{}` config automatically):

```ts
const descriptor = await repo.packManifest({
  artifactType: "application/vnd.example.thing",
  layers: [layerDescriptor],
  annotations: { "org.opencontainers.image.created": new Date().toISOString() },
  tag: "v1",
});
```

Other write operations: `repo.blobs.mount(descriptor, "other/repo")` (cross-repo
mount), `repo.manifests.delete(ref)`, and `repo.blobs.delete(digest)`.

## Discovery

```ts
// Tags (with automatic Link-header pagination).
const tags = await repo.tags.listAll();

// Referrers of a subject (referrers API, with tag-schema fallback).
const index = await repo.referrers.list(subjectDigest, {
  artifactType: "application/vnd.example.thing",
});
```

## Building on top: the Sigstore bundle spec

The [cosign bundle spec][bundle-spec] stores a Sigstore bundle as an OCI 1.1
artifact attached to an image via `subject`. This client provides every
primitive it needs, so an implementation is a thin layer:

```ts
const BUNDLE = "application/vnd.dev.sigstore.bundle.v0.3+json";

// Publish: store the bundle blob, then attach an artifact manifest to the image.
const layer = await repo.blobs.push({ mediaType: BUNDLE }, bundleBytes);
const artifact = await repo.attachArtifact(imageDescriptor, BUNDLE, [layer], {
  annotations: {
    "dev.sigstore.bundle.content": "dsse-envelope",
    "org.opencontainers.image.created": new Date().toISOString(),
  },
});

// Retrieve: find bundles attached to the image, then pull one back.
const index = await repo.referrers.list(imageDescriptor.digest, { artifactType: BUNDLE });
const { manifest } = await repo.getManifest(index.manifests[0].digest);
const bundle = await repo.blobs.get((manifest as ImageManifest).layers[0].digest);
```

`attachArtifact` / `packManifest` honor the `OCI-Subject` response header and,
by default, probe the referrers API (`repo.referrers.ping()`) so they can fall
back to maintaining the [referrers tag-schema][tag-schema] index when a registry
does not truly support it — including registries such as **AWS ECR** that return
an `OCI-Subject` header without implementing the referrers API. `referrers.list`
transparently falls back on the read side too, so the same code works on
registries regardless of referrers-API support. Set `checkReferrersApi: false`
to skip the probe, or `forceReferrersTag: true` to always maintain the tag index.

### A ready-made `@sigstore/oci` adapter

A thin adapter that exposes the exact public API of
[`@sigstore/oci`](https://github.com/sigstore/sigstore-js/tree/main/packages/oci)
(`attachArtifactToImage`, `getImageDigest`, `getRegistryCredentials`) on top of
this client lives in [`adapters/sigstore-oci`](./adapters/sigstore-oci) — kept
separate so the core library stays free of Sigstore-specific surface area.

## Reliability

- **Retries.** Transient failures (network errors and `429`/`5xx` responses) are
  retried with exponential backoff and jitter, honoring `Retry-After`. Configure
  or disable via the `retry` option: `new Registry(host, { retry: { maxRetries: 5 } })`
  or `{ retry: false }`. Requests with streaming bodies are never retried.
- **Docker Hub canonicalization.** `docker.io`, `index.docker.io`, and
  `registry.hub.docker.com` are canonicalized to `registry-1.docker.io`.

## Security

Credentials are only ever sent to the registry host they belong to:

- **Exact-host credential selection.** All credential providers select by exact
  host match (after canonicalization), never a substring match, so credentials
  configured for `ghcr.io` are never offered to `ghcr.io.evil.example` or
  `cr.io`.
- **No client-wide credential defaults.** Tokens are attached per request, keyed
  by the target URL's host. A request to a host the client learned from a server
  response — e.g. a blob-upload `Location` pointing at a separate storage host —
  is sent **without** the registry token or any custom registry headers.
- **Origin-safe redirects.** Redirects are followed manually; when a redirect
  changes origin, `Authorization`, cookies, and any non-safelisted (custom)
  headers are stripped, and the request body is never replayed to a different
  origin during token exchange. (Node's `fetch` strips `Authorization` on
  cross-origin redirects but not custom headers or request bodies.)
- **Digest verification.** Blobs and digest-referenced manifests are verified
  against their digests (`DigestMismatchError` on mismatch).

## API overview

| Area | Entry points |
| --- | --- |
| Client | `Registry`, `Registry#repository`, `Registry#ping` |
| Repository | `Repository#{blobs,manifests,tags,referrers}`, `resolve`, `fetchManifest`, `getManifest`, `pushManifest`, `pushBlob`, `packManifest`, `attachArtifact` |
| Blobs | `exists`, `get`, `fetchResponse`, `push`, `mount`, `delete` |
| Manifests | `exists`, `resolve`, `fetch`, `get`, `push`, `delete` |
| Auth | `AuthClient`, `AuthCache`, `parseChallenge`, credential providers |
| Digests | `calculateDigest`, `verifyDigest`, `parseDigest`, `Digester` |
| References | `parseReference`, `stringifyReference`, `referrersTag` |

## Development

```sh
npm run build       # compile to dist/ (tsc)
npm run typecheck   # type-check src + tests
npm test            # run the test suite (node:test)
```

Downloaded blobs and digest-referenced manifests are verified against their
digests; a mismatch throws `DigestMismatchError`. Non-2xx responses throw
`ResponseError`, which parses the OCI structured error body.

## License

[Apache-2.0](./LICENSE)

[dist-spec]: https://github.com/opencontainers/distribution-spec
[bundle-spec]: https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md
[tag-schema]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema
