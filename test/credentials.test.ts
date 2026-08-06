import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import {
  EMPTY_CREDENTIAL,
  encodeBasicAuth,
  isEmptyCredential,
  normalizeRegistry,
  staticCredential,
  basicCredential,
  chainCredentials,
} from "../src/auth/credentials.ts";

test("encodeBasicAuth base64-encodes user:pass", () => {
  assert.equal(encodeBasicAuth("user", "pass"), Buffer.from("user:pass").toString("base64"));
});

test("isEmptyCredential", () => {
  assert.equal(isEmptyCredential(EMPTY_CREDENTIAL), true);
  assert.equal(isEmptyCredential(undefined), true);
  assert.equal(isEmptyCredential({ username: "u" }), false);
  assert.equal(isEmptyCredential({ accessToken: "t" }), false);
});

test("normalizeRegistry collapses docker hub aliases", () => {
  assert.equal(normalizeRegistry("docker.io"), "registry-1.docker.io");
  assert.equal(normalizeRegistry("index.docker.io"), "registry-1.docker.io");
  assert.equal(normalizeRegistry("ghcr.io"), "ghcr.io");
});

test("staticCredential matches only its registry", async () => {
  const provider = staticCredential("ghcr.io", { username: "u", password: "p" });
  assert.deepEqual(await provider("ghcr.io"), { username: "u", password: "p" });
  assert.deepEqual(await provider("other.io"), EMPTY_CREDENTIAL);
});

test("staticCredential normalizes docker hub", async () => {
  const provider = staticCredential("docker.io", { username: "u", password: "p" });
  assert.deepEqual(await provider("registry-1.docker.io"), { username: "u", password: "p" });
});

test("basicCredential is username/password sugar", async () => {
  const provider = basicCredential("ghcr.io", "u", "p");
  assert.deepEqual(await provider("ghcr.io"), { username: "u", password: "p" });
});

test("chainCredentials returns the first non-empty", async () => {
  const provider = chainCredentials(
    () => EMPTY_CREDENTIAL,
    staticCredential("ghcr.io", { username: "u", password: "p" }),
  );
  assert.deepEqual(await provider("ghcr.io"), { username: "u", password: "p" });
  assert.deepEqual(await provider("nope.io"), EMPTY_CREDENTIAL);
});
