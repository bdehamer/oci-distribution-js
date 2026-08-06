import { test } from "node:test";
import assert from "node:assert/strict";
import {
  calculateDigest,
  verifyDigest,
  parseDigest,
  isDigest,
  tryComputeDigest,
  Digester,
} from "../src/digest.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

test("calculateDigest matches known sha256 values", () => {
  assert.equal(
    calculateDigest(new Uint8Array()),
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  assert.equal(
    calculateDigest(enc("{}")),
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  );
});

test("calculateDigest supports sha512", () => {
  const digest = calculateDigest(enc("hello"), "sha512");
  assert.ok(digest.startsWith("sha512:"));
  assert.equal(parseDigest(digest).encoded.length, 128);
});

test("verifyDigest returns true for matching content and false otherwise", () => {
  const data = enc("some content");
  const digest = calculateDigest(data);
  assert.equal(verifyDigest(data, digest), true);
  assert.equal(verifyDigest(enc("tampered"), digest), false);
  assert.equal(verifyDigest(data, "sha256:deadbeef"), false);
});

test("isDigest validates syntax and registered lengths", () => {
  assert.equal(isDigest(`sha256:${"a".repeat(64)}`), true);
  assert.equal(isDigest(`sha256:${"a".repeat(63)}`), false);
  assert.equal(isDigest("sha256:XYZ"), false);
  assert.equal(isDigest("notadigest"), false);
  assert.equal(isDigest(`multihash+base58:QmXyz123`), true);
});

test("parseDigest throws on invalid input", () => {
  assert.throws(() => parseDigest("bad"), TypeError);
  assert.deepEqual(parseDigest(`sha256:${"a".repeat(64)}`), {
    algorithm: "sha256",
    encoded: "a".repeat(64),
  });
});

test("Digester matches calculateDigest", () => {
  const digester = new Digester();
  digester.update(enc("foo")).update(enc("bar"));
  assert.equal(digester.size, 6);
  assert.equal(digester.digest(), calculateDigest(enc("foobar")));
});

test("tryComputeDigest returns undefined for unknown algorithms", () => {
  assert.equal(tryComputeDigest(enc("x"), "not-a-real-hash"), undefined);
  assert.equal(tryComputeDigest(enc("x"), "sha256"), calculateDigest(enc("x")));
});
