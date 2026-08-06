# @oci-distribution/sigstore-oci

A drop-in-compatible reimplementation of the public API of
[`@sigstore/oci`](https://github.com/sigstore/sigstore-js/tree/main/packages/oci),
implemented on top of the zero-dependency [`oci-distribution`](../../) client.

It exists to demonstrate that `oci-distribution` can back a real consumer — such
as [`actions/attest`](https://github.com/actions/attest), which uses
`@sigstore/oci` to push Sigstore bundles to a registry — with only a thin
adapter. It is **kept deliberately separate** from the core library so that
`oci-distribution` itself carries no Sigstore-specific surface area.

## Exposed API

Matches `@sigstore/oci`:

- `attachArtifactToImage(opts): Promise<Descriptor>`
- `getImageDigest(opts): Promise<string>`
- `getRegistryCredentials(imageName): Credentials`
- `OCIError`, `Credentials`, `Descriptor`

## How it maps onto `oci-distribution`

| `@sigstore/oci` | `oci-distribution` |
| --- | --- |
| `attachArtifactToImage` | `repo.resolve(digest)` + `repo.blobs.push` + `repo.attachArtifact` |
| `getImageDigest` | `repo.resolve(tag).digest` |
| `Credentials` (`<token>` username) | `Credential` (`refreshToken`) → OAuth2 grant |
| Docker Hub aliasing | `Registry` canonicalizes to `registry-1.docker.io` |
| AWS ECR referrers quirk | `attachArtifact` probes the referrers API and falls back to the tag schema |

## Usage

```ts
import {
  attachArtifactToImage,
  getRegistryCredentials,
} from "@oci-distribution/sigstore-oci";

const credentials = getRegistryCredentials("ghcr.io/owner/app");

const descriptor = await attachArtifactToImage({
  imageName: "ghcr.io/owner/app",
  imageDigest: "sha256:…",
  artifact: bundleBytes, // JSON-serialized Sigstore bundle
  mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
  credentials,
  annotations: { "dev.sigstore.bundle.content": "dsse-envelope" },
});
```

## Development

This package depends on the core library via a local `file:../..` reference, so
build the core first:

```sh
# from the repository root
npm run build

# then, in this directory
cd adapters/sigstore-oci
npm install
npm run typecheck
npm test
npm run build
```
