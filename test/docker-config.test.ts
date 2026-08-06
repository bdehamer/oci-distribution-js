import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { dockerConfigCredential, type HelperResult } from "../src/auth/docker-config.ts";

function writeConfig(contents: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "oci-docker-"));
  writeFileSync(join(dir, "config.json"), JSON.stringify(contents));
  return join(dir, "config.json");
}

test("reads inline auths base64 credentials", async () => {
  const auth = Buffer.from("alice:s3cret").toString("base64");
  const configPath = writeConfig({ auths: { "ghcr.io": { auth } } });
  const provider = dockerConfigCredential({ configPath });
  assert.deepEqual(await provider("ghcr.io"), { username: "alice", password: "s3cret" });
  rmSync(join(configPath, ".."), { recursive: true, force: true });
});

test("matches docker hub via URL-form auths key", async () => {
  const auth = Buffer.from("alice:pw").toString("base64");
  const configPath = writeConfig({ auths: { "https://index.docker.io/v1/": { auth } } });
  const provider = dockerConfigCredential({ configPath });
  assert.deepEqual(await provider("registry-1.docker.io"), { username: "alice", password: "pw" });
});

test("reads identity token as refreshToken", async () => {
  const configPath = writeConfig({ auths: { "ghcr.io": { identitytoken: "id-token" } } });
  const provider = dockerConfigCredential({ configPath });
  assert.deepEqual(await provider("ghcr.io"), { refreshToken: "id-token" });
});

test("invokes a credential helper from credHelpers", async () => {
  const configPath = writeConfig({ credHelpers: { "ghcr.io": "test" } });
  const calls: Array<{ helper: string; serverURL: string }> = [];
  const runHelper = async (helper: string, serverURL: string): Promise<HelperResult> => {
    calls.push({ helper, serverURL });
    return { Username: "bob", Secret: "helper-pw" };
  };
  const provider = dockerConfigCredential({ configPath, runHelper });
  assert.deepEqual(await provider("ghcr.io"), { username: "bob", password: "helper-pw" });
  assert.deepEqual(calls, [{ helper: "test", serverURL: "ghcr.io" }]);
});

test("credential helper <token> username yields refreshToken", async () => {
  const configPath = writeConfig({ credsStore: "store" });
  const runHelper = async (): Promise<HelperResult> => ({ Username: "<token>", Secret: "rt" });
  const provider = dockerConfigCredential({ configPath, runHelper });
  assert.deepEqual(await provider("ghcr.io"), { refreshToken: "rt" });
});

test("credsStore uses the docker hub server URL", async () => {
  const configPath = writeConfig({ credsStore: "store" });
  let seen = "";
  const runHelper = async (_h: string, serverURL: string): Promise<HelperResult> => {
    seen = serverURL;
    return { Username: "u", Secret: "p" };
  };
  const provider = dockerConfigCredential({ configPath, runHelper });
  await provider("registry-1.docker.io");
  assert.equal(seen, "https://index.docker.io/v1/");
});

test("resolves config path from DOCKER_CONFIG env", async () => {
  const auth = Buffer.from("x:y").toString("base64");
  const configPath = writeConfig({ auths: { "ghcr.io": { auth } } });
  const dir = join(configPath, "..");
  const provider = dockerConfigCredential({ env: { DOCKER_CONFIG: dir } });
  assert.deepEqual(await provider("ghcr.io"), { username: "x", password: "y" });
});

test("missing config yields anonymous access", async () => {
  const provider = dockerConfigCredential({ configPath: "/nonexistent/config.json" });
  assert.deepEqual(await provider("ghcr.io"), {});
});
