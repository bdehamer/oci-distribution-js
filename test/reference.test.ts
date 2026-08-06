import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseReference,
  stringifyReference,
  referenceTagOrDigest,
  referrersTag,
  isValidRepository,
  isValidTag,
} from "../src/reference.ts";

const DIGEST = `sha256:${"a".repeat(64)}`;

test("parseReference extracts registry, repository, and tag", () => {
  assert.deepEqual(parseReference("ghcr.io/owner/repo:latest"), {
    registry: "ghcr.io",
    repository: "owner/repo",
    tag: "latest",
  });
});

test("parseReference handles digests", () => {
  assert.deepEqual(parseReference(`ghcr.io/owner/repo@${DIGEST}`), {
    registry: "ghcr.io",
    repository: "owner/repo",
    digest: DIGEST,
  });
  assert.deepEqual(parseReference(`ghcr.io/owner/repo:v1@${DIGEST}`), {
    registry: "ghcr.io",
    repository: "owner/repo",
    tag: "v1",
    digest: DIGEST,
  });
});

test("parseReference treats a dotless first segment as a repository", () => {
  assert.deepEqual(parseReference("ubuntu"), { registry: "", repository: "ubuntu" });
  assert.deepEqual(parseReference("library/ubuntu:latest"), {
    registry: "",
    repository: "library/ubuntu",
    tag: "latest",
  });
});

test("parseReference detects host with port and localhost", () => {
  assert.deepEqual(parseReference("localhost:5000/foo/bar"), {
    registry: "localhost:5000",
    repository: "foo/bar",
  });
  assert.equal(parseReference("registry.io:5000/foo").registry, "registry.io:5000");
});

test("parseReference rejects invalid digests and tags", () => {
  assert.throws(() => parseReference("ghcr.io/foo@sha256:zzz"), TypeError);
  assert.throws(() => parseReference("ghcr.io/foo:-bad!"), TypeError);
  assert.throws(() => parseReference(""), TypeError);
});

test("stringifyReference round-trips", () => {
  const input = `ghcr.io/owner/repo:v1@${DIGEST}`;
  assert.equal(stringifyReference(parseReference(input)), input);
  assert.equal(stringifyReference({ registry: "", repository: "ubuntu" }), "ubuntu");
});

test("referenceTagOrDigest prefers digest", () => {
  assert.equal(referenceTagOrDigest({ registry: "", repository: "x", tag: "t", digest: DIGEST }), DIGEST);
  assert.equal(referenceTagOrDigest({ registry: "", repository: "x", tag: "t" }), "t");
});

test("referrersTag follows the tag schema", () => {
  assert.equal(referrersTag(`sha256:${"a".repeat(64)}`), `sha256-${"a".repeat(64)}`);
  // encoded truncated to 64 chars
  const long = `sha256:${"b".repeat(70)}`;
  assert.throws(() => referrersTag(long)); // 70 chars is not a valid sha256 digest
});

test("validators", () => {
  assert.equal(isValidRepository("library/ubuntu"), true);
  assert.equal(isValidRepository("Bad/Name"), false);
  assert.equal(isValidTag("v1.2.3-alpha_1"), true);
  assert.equal(isValidTag("-bad"), false);
});
