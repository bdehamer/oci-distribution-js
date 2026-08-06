import { test } from "node:test";
import assert from "node:assert/strict";
import { parseChallenge } from "../src/auth/challenge.ts";

test("parses a bearer challenge with quoted params", () => {
  const challenge = parseChallenge(
    'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull"',
  );
  assert.equal(challenge.scheme, "bearer");
  assert.equal(challenge.params["realm"], "https://auth.docker.io/token");
  assert.equal(challenge.params["service"], "registry.docker.io");
  assert.equal(challenge.params["scope"], "repository:library/ubuntu:pull");
});

test("scheme matching is case-insensitive and keys are lowercased", () => {
  const challenge = parseChallenge('bearer REALM="x",Service="y"');
  assert.equal(challenge.scheme, "bearer");
  assert.equal(challenge.params["realm"], "x");
  assert.equal(challenge.params["service"], "y");
});

test("basic challenge yields no params", () => {
  const challenge = parseChallenge('Basic realm="registry"');
  assert.equal(challenge.scheme, "basic");
  assert.deepEqual(challenge.params, {});
});

test("handles escaped quotes inside quoted values", () => {
  const challenge = parseChallenge('Bearer realm="a\\"b",error="invalid_token"');
  assert.equal(challenge.params["realm"], 'a"b');
  assert.equal(challenge.params["error"], "invalid_token");
});

test("handles unquoted token values", () => {
  const challenge = parseChallenge("Bearer error=invalid_token,service=svc");
  assert.equal(challenge.params["error"], "invalid_token");
  assert.equal(challenge.params["service"], "svc");
});

test("unknown scheme is reported as unknown", () => {
  assert.equal(parseChallenge("Negotiate abc").scheme, "unknown");
  assert.equal(parseChallenge("").scheme, "unknown");
});

test("stops cleanly at a second scheme in the header", () => {
  const challenge = parseChallenge('Bearer realm="x" Basic realm="y"');
  assert.equal(challenge.scheme, "bearer");
  assert.equal(challenge.params["realm"], "x");
});
