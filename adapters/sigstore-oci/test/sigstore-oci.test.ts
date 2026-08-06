import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Buffer } from "node:buffer";
import { Registry } from "oci-distribution";
import {
  attachArtifactToImage,
  getImageDigest,
  getRegistryCredentials,
  OCIError,
} from "../src/index.ts";
import { createMockRegistry } from "../../../test/helpers/mock-registry.ts";

const BUNDLE = "application/vnd.dev.sigstore.bundle.v0.3+json";
const anon = { username: "", password: "" };

test("attachArtifactToImage attaches a bundle that is discoverable via referrers", async () => {
  const server = await createMockRegistry({});
  try {
    const repo = new Registry(server.host).repository("project/app");
    const subject = await repo.packManifest({ tag: "v1", annotations: { role: "image" } });

    const descriptor = await attachArtifactToImage({
      imageName: `${server.host}/project/app`,
      imageDigest: subject.digest,
      artifact: Buffer.from(JSON.stringify({ mediaType: BUNDLE, messageSignature: {} })),
      mediaType: BUNDLE,
      credentials: anon,
      annotations: { "dev.sigstore.bundle.content": "message-signature" },
    });

    assert.ok(descriptor.digest.startsWith("sha256:"));
    assert.equal(descriptor.artifactType, BUNDLE);

    const index = await repo.referrers.list(subject.digest, { artifactType: BUNDLE });
    assert.equal(index.manifests.length, 1);
    assert.equal(index.manifests[0]?.digest, descriptor.digest);
    assert.equal(
      index.manifests[0]?.annotations?.["dev.sigstore.bundle.content"],
      "message-signature",
    );
  } finally {
    await server.close();
  }
});

test("attachArtifactToImage works on ECR-like registries via the tag fallback", async () => {
  const server = await createMockRegistry({ emulateEcr: true });
  try {
    const repo = new Registry(server.host).repository("project/app");
    const subject = await repo.packManifest({ annotations: { role: "image" } });

    await attachArtifactToImage({
      imageName: `${server.host}/project/app`,
      imageDigest: subject.digest,
      artifact: Buffer.from('{"bundle":true}'),
      mediaType: BUNDLE,
      credentials: anon,
    });

    const index = await repo.referrers.list(subject.digest, { artifactType: BUNDLE });
    assert.equal(index.manifests.length, 1);
  } finally {
    await server.close();
  }
});

test("getImageDigest resolves a tag to its digest", async () => {
  const server = await createMockRegistry({});
  try {
    const repo = new Registry(server.host).repository("project/app");
    const subject = await repo.packManifest({ tag: "v1" });

    const digest = await getImageDigest({
      imageName: `${server.host}/project/app`,
      imageTag: "v1",
      credentials: anon,
    });
    assert.equal(digest, subject.digest);
  } finally {
    await server.close();
  }
});

test("attachArtifactToImage wraps failures in OCIError", async () => {
  const server = await createMockRegistry({});
  try {
    await assert.rejects(
      () =>
        attachArtifactToImage({
          imageName: `${server.host}/project/missing`,
          imageDigest: `sha256:${"0".repeat(64)}`,
          artifact: Buffer.from("x"),
          mediaType: BUNDLE,
          credentials: anon,
        }),
      OCIError,
    );
  } finally {
    await server.close();
  }
});

test("getRegistryCredentials reads the docker config for the registry", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "adapter-home-"));
  fs.mkdirSync(path.join(home, ".docker"));
  const auth = Buffer.from("alice:s3cret").toString("base64");
  fs.writeFileSync(
    path.join(home, ".docker", "config.json"),
    JSON.stringify({ auths: { "ghcr.io": { auth } } }),
  );
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  try {
    const creds = getRegistryCredentials("ghcr.io/owner/repo");
    assert.equal(creds.username, "alice");
    assert.equal(creds.password, "s3cret");
  } finally {
    if (prevHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = prevHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
});
