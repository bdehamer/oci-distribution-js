import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Registry } from "../src/registry.ts";
import {
  dockerConfigCredential,
  dockerConfigHeaders,
  type HelperResult,
} from "../src/auth/docker-config.ts";

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

// --- HttpHeaders support ---

test("dockerConfigHeaders reads the top-level HttpHeaders map", () => {
  const dir = mkdtempSync(join(tmpdir(), "oci-docker-"));
  writeFileSync(
    join(dir, "config.json"),
    JSON.stringify({ HttpHeaders: { "X-Meta-Header": "abc", "User-Agent": "custom/1.0" } }),
  );
  try {
    assert.deepEqual(dockerConfigHeaders({ configPath: join(dir, "config.json") }), {
      "X-Meta-Header": "abc",
      "User-Agent": "custom/1.0",
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dockerConfigHeaders returns {} when absent or file is missing", () => {
  const dir = mkdtempSync(join(tmpdir(), "oci-docker-"));
  writeFileSync(join(dir, "config.json"), JSON.stringify({ auths: {} }));
  try {
    assert.deepEqual(dockerConfigHeaders({ configPath: join(dir, "config.json") }), {});
    assert.deepEqual(dockerConfigHeaders({ configPath: "/nonexistent/config.json" }), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dockerConfigHeaders resolves the config via DOCKER_CONFIG env", () => {
  const dir = mkdtempSync(join(tmpdir(), "oci-docker-"));
  writeFileSync(join(dir, "config.json"), JSON.stringify({ HttpHeaders: { "X-Proxy": "1" } }));
  try {
    assert.deepEqual(dockerConfigHeaders({ env: { DOCKER_CONFIG: dir } }), { "X-Proxy": "1" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("HttpHeaders from the docker config are sent to the registry host", async () => {
  const dir = mkdtempSync(join(tmpdir(), "oci-docker-"));
  writeFileSync(join(dir, "config.json"), JSON.stringify({ HttpHeaders: { "X-Custom-Auth": "sekret" } }));
  const received: Array<Record<string, string | string[] | undefined>> = [];
  const server = createServer((req, res) => {
    received.push(req.headers);
    res.statusCode = 200;
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    const registry = new Registry(`127.0.0.1:${port}`, {
      headers: dockerConfigHeaders({ configPath: join(dir, "config.json") }),
    });
    await registry.ping();
    assert.ok(received.length > 0, "registry should have received a request");
    assert.equal(received[0]?.["x-custom-auth"], "sekret");
  } finally {
    await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- M-1: credential-helper name validation (attacker-influenced config) ---

test("rejects a credsStore name containing a path separator without spawning", async () => {
  const configPath = writeConfig({ credsStore: "x/../../../../bin/echo" });
  let called = false;
  const runHelper = async (): Promise<HelperResult> => {
    called = true;
    return { Username: "u", Secret: "p" };
  };
  const provider = dockerConfigCredential({ configPath, runHelper });
  assert.deepEqual(await provider("ghcr.io"), {}, "invalid helper name yields anonymous access");
  assert.equal(called, false, "an invalid helper name must never be executed");
  rmSync(join(configPath, ".."), { recursive: true, force: true });
});

test("rejects a credHelpers name containing a slash without spawning", async () => {
  const configPath = writeConfig({ credHelpers: { "ghcr.io": "sub/evil" } });
  let called = false;
  const runHelper = async (): Promise<HelperResult> => {
    called = true;
    return { Username: "u", Secret: "p" };
  };
  const provider = dockerConfigCredential({ configPath, runHelper });
  assert.deepEqual(await provider("ghcr.io"), {});
  assert.equal(called, false, "an invalid helper name must never be executed");
  rmSync(join(configPath, ".."), { recursive: true, force: true });
});

test("a valid helper name (alnum/._-) is still executed", async () => {
  const configPath = writeConfig({ credHelpers: { "ghcr.io": "ecr-login" } });
  let called = false;
  const runHelper = async (): Promise<HelperResult> => {
    called = true;
    return { Username: "u", Secret: "p" };
  };
  const provider = dockerConfigCredential({ configPath, runHelper });
  assert.deepEqual(await provider("ghcr.io"), { username: "u", password: "p" });
  assert.equal(called, true, "a well-formed helper name must still run");
  rmSync(join(configPath, ".."), { recursive: true, force: true });
});
