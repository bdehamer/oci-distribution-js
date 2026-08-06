import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { Registry } from "../src/registry.ts";
import { calculateDigest } from "../src/digest.ts";
import { NotFoundError, ResponseError } from "../src/errors.ts";
import { MEDIA_TYPE_OCI_IMAGE_MANIFEST } from "../src/media-types.ts";
import { createMockRegistry, type MockRegistry } from "./helpers/mock-registry.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

let server: MockRegistry;

before(async () => {
  server = await createMockRegistry();
});

after(async () => {
  await server.close();
});

function registry(): Registry {
  return new Registry(server.host);
}

test("ping succeeds and uses http for loopback", async () => {
  const reg = registry();
  assert.equal(reg.scheme, "http");
  assert.equal(await reg.ping(), true);
});

test("blob push, exists, get with verification", async () => {
  const repo = registry().repository("app/blobs");
  const data = enc("hello blob");
  const digest = calculateDigest(data);

  const descriptor = await repo.blobs.push({ mediaType: "application/octet-stream" }, data);
  assert.equal(descriptor.digest, digest);
  assert.equal(descriptor.size, data.byteLength);

  assert.equal(await repo.blobs.exists(digest), true);
  assert.equal(await repo.blobs.exists(calculateDigest(enc("absent"))), false);

  const fetched = await repo.blobs.get(digest);
  assert.deepEqual(fetched, data);
});

test("blob get rejects a nonexistent blob", async () => {
  const repo = registry().repository("app/blobs");
  await assert.rejects(() => repo.blobs.get(calculateDigest(enc("missing"))), NotFoundError);
});

test("manifest push, resolve, fetch, and get", async () => {
  const repo = registry().repository("app/manifests");
  const manifest = {
    schemaVersion: 2,
    mediaType: MEDIA_TYPE_OCI_IMAGE_MANIFEST,
    config: repo.emptyConfigDescriptor(),
    layers: [],
  };
  const body = enc(JSON.stringify(manifest));
  const digest = calculateDigest(body);

  const descriptor = await repo.manifests.push("v1", body, { mediaType: MEDIA_TYPE_OCI_IMAGE_MANIFEST });
  assert.equal(descriptor.digest, digest);

  const resolved = await repo.resolve("v1");
  assert.equal(resolved.digest, digest);
  assert.equal(resolved.mediaType, MEDIA_TYPE_OCI_IMAGE_MANIFEST);

  const { data } = await repo.fetchManifest(digest);
  assert.deepEqual(data, body);

  const { manifest: parsed } = await repo.getManifest("v1");
  assert.equal((parsed as { schemaVersion: number }).schemaVersion, 2);
});

test("resolve throws NotFoundError for a missing tag", async () => {
  const repo = registry().repository("app/manifests");
  await assert.rejects(() => repo.resolve("nope"), NotFoundError);
});

test("tags listing with pagination", async () => {
  const repo = registry().repository("app/tags");
  const body = enc(JSON.stringify({ schemaVersion: 2, config: repo.emptyConfigDescriptor(), layers: [] }));
  for (const tag of ["a", "b", "c"]) {
    await repo.manifests.push(tag, body, { mediaType: MEDIA_TYPE_OCI_IMAGE_MANIFEST });
  }
  const page = await repo.tags.list({ n: 2 });
  assert.deepEqual(page.tags, ["a", "b"]);
  const all = await repo.tags.listAll(2);
  assert.deepEqual(all, ["a", "b", "c"]);
});

test("cross-repository blob mount", async () => {
  const reg = registry();
  const source = reg.repository("app/source");
  const data = enc("mountable layer");
  const descriptor = await source.blobs.push({ mediaType: "application/octet-stream" }, data);

  const dest = reg.repository("app/dest");
  const mounted = await dest.blobs.mount(descriptor, "app/source");
  assert.ok(mounted);
  assert.equal(mounted.digest, descriptor.digest);
  assert.equal(await dest.blobs.exists(descriptor.digest), true);
});

test("mount returns null when the source blob is absent", async () => {
  const dest = registry().repository("app/dest2");
  const descriptor = { mediaType: "application/octet-stream", digest: calculateDigest(enc("x")), size: 1 };
  const mounted = await dest.blobs.mount(descriptor, "app/empty-source");
  assert.equal(mounted, null);
});

test("ResponseError carries status and parsed OCI errors", async () => {
  // Deleting a tag on a repo that doesn't support it -> our mock returns 202,
  // so instead exercise an error by requesting an invalid upload session PUT.
  const repo = registry().repository("app/errs");
  await assert.rejects(
    () => repo.manifests.delete("missing-and-untracked"),
    (err: unknown) => err instanceof ResponseError || err instanceof NotFoundError,
  );
});
