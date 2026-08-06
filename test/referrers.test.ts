import { test } from "node:test";
import assert from "node:assert/strict";
import { Registry } from "../src/registry.ts";
import { createMockRegistry } from "./helpers/mock-registry.ts";

const BUNDLE = "application/vnd.dev.sigstore.bundle.v0.3+json";
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

test("canonicalizes Docker Hub aliases to registry-1.docker.io", () => {
  assert.equal(new Registry("docker.io").host, "registry-1.docker.io");
  assert.equal(new Registry("index.docker.io").host, "registry-1.docker.io");
  assert.equal(new Registry("registry.hub.docker.com").host, "registry-1.docker.io");
  assert.equal(new Registry("docker.io").scheme, "https");
  assert.equal(new Registry("ghcr.io").host, "ghcr.io");
});

test("referrers.ping reflects API support", async () => {
  const supported = await createMockRegistry({ referrersApi: true });
  const unsupported = await createMockRegistry({ referrersApi: false });
  const ecr = await createMockRegistry({ emulateEcr: true });
  try {
    assert.equal(await new Registry(supported.host).repository("a/b").referrers.ping(), true);
    assert.equal(await new Registry(unsupported.host).repository("a/b").referrers.ping(), false);
    assert.equal(await new Registry(ecr.host).repository("a/b").referrers.ping(), false);
  } finally {
    await Promise.all([supported.close(), unsupported.close(), ecr.close()]);
  }
});

test("ECR quirk: packManifest falls back to the tag schema despite the OCI-Subject header", async () => {
  const server = await createMockRegistry({ emulateEcr: true });
  try {
    const repo = new Registry(server.host).repository("project/app");
    const subject = await repo.packManifest({ annotations: { role: "image" } });

    const layer = await repo.pushBlob({ mediaType: BUNDLE }, enc('{"bundle":true}'));
    // Default checkReferrersApi pings the API (404 on ECR) and forces the tag update.
    await repo.attachArtifact(subject, BUNDLE, [layer]);

    const index = await repo.referrers.list(subject.digest, { artifactType: BUNDLE });
    assert.equal(index.manifests.length, 1);
    assert.equal(index.manifests[0]?.artifactType, BUNDLE);
  } finally {
    await server.close();
  }
});

test("ECR quirk: trusting the OCI-Subject header alone loses the referrer", async () => {
  const server = await createMockRegistry({ emulateEcr: true });
  try {
    const repo = new Registry(server.host).repository("project/app");
    const subject = await repo.packManifest({ annotations: { role: "image-2" } });

    const layer = await repo.pushBlob({ mediaType: BUNDLE }, enc('{"bundle":true}'));
    // Opting out of the referrers-API check reproduces the ECR failure mode:
    // the header is trusted, the tag index is never written, and the referrer
    // is undiscoverable.
    await repo.attachArtifact(subject, BUNDLE, [layer], { checkReferrersApi: false });

    const index = await repo.referrers.list(subject.digest, { artifactType: BUNDLE });
    assert.equal(index.manifests.length, 0);
  } finally {
    await server.close();
  }
});
