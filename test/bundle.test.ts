import { test } from "node:test";
import assert from "node:assert/strict";
import { Registry } from "../src/registry.ts";
import type { ImageManifest } from "../src/types.ts";
import { createMockRegistry } from "./helpers/mock-registry.ts";

/**
 * End-to-end exercise of the Sigstore cosign BUNDLE_SPEC publish + retrieve
 * flow, built entirely on the generic OCI primitives this client exposes. Runs
 * once against a registry that supports the referrers API and once against one
 * that does not (to exercise the referrers tag-schema fallback).
 */

const BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

async function runBundleScenario(referrersApi: boolean): Promise<void> {
  const server = await createMockRegistry({ referrersApi });
  try {
    const repo = new Registry(server.host).repository("project/app");

    // A stand-in for the image being signed; any manifest works as a subject.
    const subject = await repo.packManifest({ annotations: { role: "image" } });

    // 1. Publish: store the bundle JSON as a blob.
    const bundle = enc(JSON.stringify({ mediaType: BUNDLE_MEDIA_TYPE, messageSignature: { signature: "..." } }));
    const layer = await repo.pushBlob({ mediaType: BUNDLE_MEDIA_TYPE }, bundle);

    // 2. Publish: attach an artifact manifest referencing the bundle to the subject.
    const artifact = await repo.attachArtifact(subject, BUNDLE_MEDIA_TYPE, [layer], {
      annotations: {
        "dev.sigstore.bundle.content": "message-signature",
        "org.opencontainers.image.created": "2024-03-07T18:17:38.000Z",
      },
    });

    // 3. Retrieve: list referrers filtered by the bundle artifact type.
    const index = await repo.referrers.list(subject.digest, { artifactType: BUNDLE_MEDIA_TYPE });
    assert.equal(index.manifests.length, 1);
    const referrer = index.manifests[0];
    assert.ok(referrer);
    assert.equal(referrer.digest, artifact.digest);
    assert.equal(referrer.artifactType, BUNDLE_MEDIA_TYPE);
    assert.equal(referrer.annotations?.["dev.sigstore.bundle.content"], "message-signature");

    // 4. Retrieve: fetch the artifact manifest and pull the bundle blob back.
    const { manifest } = await repo.getManifest(artifact.digest);
    const image = manifest as ImageManifest;
    assert.equal(image.artifactType, BUNDLE_MEDIA_TYPE);
    assert.equal(image.subject?.digest, subject.digest);
    const bundleLayer = image.layers[0];
    assert.ok(bundleLayer);

    const retrieved = await repo.blobs.get(bundleLayer.digest);
    assert.deepEqual(retrieved, bundle);
  } finally {
    await server.close();
  }
}

test("cosign bundle publish + retrieve via the referrers API", async () => {
  await runBundleScenario(true);
});

test("cosign bundle publish + retrieve via the referrers tag-schema fallback", async () => {
  await runBundleScenario(false);
});

test("filtering excludes referrers of other artifact types", async () => {
  const server = await createMockRegistry({ referrersApi: true });
  try {
    const repo = new Registry(server.host).repository("project/app");
    const subject = await repo.packManifest({});

    const bundle = enc('{"mediaType":"' + BUNDLE_MEDIA_TYPE + '"}');
    const bundleLayer = await repo.pushBlob({ mediaType: BUNDLE_MEDIA_TYPE }, bundle);
    await repo.attachArtifact(subject, BUNDLE_MEDIA_TYPE, [bundleLayer]);

    const sbom = enc('{"sbom":true}');
    const sbomLayer = await repo.pushBlob({ mediaType: "application/spdx+json" }, sbom);
    await repo.attachArtifact(subject, "application/vnd.example.sbom", [sbomLayer]);

    const all = await repo.referrers.list(subject.digest);
    assert.equal(all.manifests.length, 2);

    const bundlesOnly = await repo.referrers.list(subject.digest, { artifactType: BUNDLE_MEDIA_TYPE });
    assert.equal(bundlesOnly.manifests.length, 1);
    assert.equal(bundlesOnly.manifests[0]?.artifactType, BUNDLE_MEDIA_TYPE);
  } finally {
    await server.close();
  }
});
