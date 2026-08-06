import { test } from "node:test";
import assert from "node:assert/strict";
import { Registry } from "../src/registry.ts";
import { calculateDigest } from "../src/digest.ts";
import { createMockRegistry } from "./helpers/mock-registry.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

/**
 * Exercises the token-challenge flow against a real (in-process) HTTP registry
 * that requires a bearer token, validating that the client discovers the token
 * endpoint from the `WWW-Authenticate` header, obtains a token, and retries.
 */
test("authenticates against a registry that requires a bearer token", async () => {
  const server = await createMockRegistry({ requireAuth: true });
  try {
    const reg = new Registry(server.host, {
      credentials: () => ({ username: "user", password: "pass" }),
    });

    assert.equal(await reg.ping(), true);

    const repo = reg.repository("secure/app");
    const data = enc("authenticated blob");
    const descriptor = await repo.blobs.push({ mediaType: "application/octet-stream" }, data);
    assert.equal(descriptor.digest, calculateDigest(data));

    const roundTrip = await repo.blobs.get(descriptor.digest);
    assert.deepEqual(roundTrip, data);
  } finally {
    await server.close();
  }
});

test("without required auth the same registry still serves anonymously", async () => {
  const server = await createMockRegistry({ requireAuth: false });
  try {
    const reg = new Registry(server.host);
    assert.equal(await reg.ping(), true);
  } finally {
    await server.close();
  }
});
