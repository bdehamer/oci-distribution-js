import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import { Registry } from "../src/registry.ts";
import { calculateDigest } from "../src/digest.ts";
import { RegistryError } from "../src/errors.ts";
import {
  staticCredential,
  basicCredential,
  EMPTY_CREDENTIAL,
} from "../src/auth/credentials.ts";
import { dockerConfigCredential } from "../src/auth/docker-config.ts";

// --- Advisory GHSA-pf56-329r-95rw: credential confusion via substring match ---

test("staticCredential requires an exact host match (no substring confusion)", async () => {
  const provider = staticCredential("ghcr.io", { username: "u", password: "p" });
  for (const attacker of [
    "cr.io",
    "hcr.io",
    "ghcr.io.evil.com",
    "evilghcr.io",
    "ghcr.io.attacker.example",
  ]) {
    assert.deepEqual(await provider(attacker), EMPTY_CREDENTIAL, `must not match ${attacker}`);
  }
  assert.deepEqual(await provider("ghcr.io"), { username: "u", password: "p" });
});

test("basicCredential requires an exact host match", async () => {
  const provider = basicCredential("ghcr.io", "u", "p");
  assert.deepEqual(await provider("ghcr.io.evil.com"), EMPTY_CREDENTIAL);
  assert.deepEqual(await provider("ghcr.io"), { username: "u", password: "p" });
});

test("dockerConfigCredential requires an exact host match", async () => {
  const dir = mkdtempSync(join(tmpdir(), "oci-sec-"));
  const auth = Buffer.from("alice:s3cret").toString("base64");
  writeFileSync(join(dir, "config.json"), JSON.stringify({ auths: { "ghcr.io": { auth } } }));
  const provider = dockerConfigCredential({ configPath: join(dir, "config.json") });
  try {
    // An attacker-controlled host that is a substring superset of the configured key.
    assert.deepEqual(await provider("ghcr.io.evil.com"), EMPTY_CREDENTIAL);
    assert.deepEqual(await provider("cr.io"), EMPTY_CREDENTIAL);
    assert.deepEqual(await provider("ghcr.io"), { username: "alice", password: "s3cret" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- Advisory GHSA-j63v-mwhm-56jx: credential sent to a response-named host ---

interface TestServer {
  origin: string;
  host: string;
  requests: Array<{ method: string; url: string; headers: NodeJS.Dict<string | string[]> }>;
  close: () => Promise<void>;
}

function startServer(
  onRequest: (req: IncomingMessage, res: ServerResponse, self: TestServer) => void,
): Promise<TestServer> {
  return new Promise((resolve) => {
    const requests: TestServer["requests"] = [];
    const server: Server = createServer((req, res) => {
      requests.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers });
      onRequest(req, res, handle);
    });
    const handle: TestServer = {
      origin: "",
      host: "",
      requests,
      close: () =>
        new Promise<void>((r, j) => server.close((e) => (e ? j(e) : r()))),
    };
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      handle.origin = `http://127.0.0.1:${addr.port}`;
      handle.host = `127.0.0.1:${addr.port}`;
      resolve(handle);
    });
  });
}

const BEARER = "registry-token";

// A registry server that requires bearer auth and issues a token via /token.
function registryHandler(
  routes: (req: IncomingMessage, res: ServerResponse, self: TestServer) => boolean,
) {
  return (req: IncomingMessage, res: ServerResponse, self: TestServer): void => {
    const url = new URL(req.url ?? "/", self.origin);
    if (url.pathname === "/token") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ token: BEARER, access_token: BEARER }));
      return;
    }
    if (url.pathname === "/v2/" || url.pathname === "/v2") {
      res.statusCode = 200;
      res.end();
      return;
    }
    if (req.headers["authorization"] !== `Bearer ${BEARER}`) {
      res.setHeader(
        "www-authenticate",
        `Bearer realm="${self.origin}/token",service="test",scope="repository:lib/app:pull,push"`,
      );
      res.statusCode = 401;
      res.end();
      return;
    }
    if (!routes(req, res, self)) {
      res.statusCode = 404;
      res.end();
    }
  };
}

test("registry token is NOT sent to a cross-host blob-upload Location", async () => {
  const storage = await startServer((req, res) => {
    res.statusCode = 201;
    res.end();
  });
  const registry = await startServer(
    registryHandler((req, res, self) => {
      const url = new URL(req.url ?? "/", self.origin);
      if (req.method === "HEAD" && url.pathname.startsWith("/v2/lib/app/blobs/")) {
        res.statusCode = 404; // blob does not exist yet
        res.end();
        return true;
      }
      if (req.method === "POST" && url.pathname === "/v2/lib/app/blobs/uploads/") {
        // Offload the upload to a DIFFERENT host (attacker-controllable per spec).
        res.setHeader("location", `${storage.origin}/upload/1`);
        res.statusCode = 202;
        res.end();
        return true;
      }
      return false;
    }),
  );

  try {
    const repo = new Registry(registry.host, {
      credentials: staticCredential(registry.host, { username: "u", password: "p" }),
      headers: { "x-secret-header": "leak-me" },
    }).repository("lib/app");

    await repo.blobs.push({ mediaType: "application/octet-stream" }, Buffer.from("payload"));

    const put = storage.requests.find((r) => r.method === "PUT");
    assert.ok(put, "storage should have received the PUT");
    assert.equal(put.headers["authorization"], undefined, "must not leak the registry token");
    assert.equal(put.headers["x-secret-header"], undefined, "must not leak custom headers");
  } finally {
    await Promise.all([registry.close(), storage.close()]);
  }
});

test("credentials are NOT sent across a cross-host redirect", async () => {
  const blob = Buffer.from("redirected blob content");
  const digest = calculateDigest(new Uint8Array(blob));

  const storage = await startServer((req, res) => {
    res.statusCode = 200;
    res.end(blob);
  });
  const registry = await startServer(
    registryHandler((req, res, self) => {
      const url = new URL(req.url ?? "/", self.origin);
      if (req.method === "GET" && url.pathname === `/v2/lib/app/blobs/${digest}`) {
        res.setHeader("location", `${storage.origin}/blob`);
        res.statusCode = 307;
        res.end();
        return true;
      }
      return false;
    }),
  );

  try {
    const repo = new Registry(registry.host, {
      credentials: staticCredential(registry.host, { username: "u", password: "p" }),
      headers: { "x-secret-header": "leak-me" },
    }).repository("lib/app");

    const data = await repo.blobs.get(digest);
    assert.deepEqual(data, new Uint8Array(blob), "blob should be retrieved through the redirect");

    const storageGet = storage.requests.find((r) => r.method === "GET");
    assert.ok(storageGet);
    assert.equal(storageGet.headers["authorization"], undefined, "token must not cross origins");
    assert.equal(storageGet.headers["x-secret-header"], undefined, "custom header must not cross");
  } finally {
    await Promise.all([registry.close(), storage.close()]);
  }
});

test("a cross-origin redirect from the token endpoint is refused (no credential leak)", async () => {
  const attacker = await startServer((req, res) => {
    res.statusCode = 200;
    res.end("caught");
  });
  const registry = await startServer((req, res, self) => {
    const url = new URL(req.url ?? "/", self.origin);
    if (url.pathname === "/token") {
      // Malicious/compromised token endpoint tries to bounce creds elsewhere.
      res.setHeader("location", `${attacker.origin}/steal`);
      res.statusCode = 307;
      res.end();
      return;
    }
    if (url.pathname === "/v2/" || url.pathname === "/v2") {
      res.statusCode = 200;
      res.end();
      return;
    }
    res.setHeader(
      "www-authenticate",
      `Bearer realm="${self.origin}/token",service="test",scope="repository:lib/app:pull"`,
    );
    res.statusCode = 401;
    res.end();
  });

  try {
    const repo = new Registry(registry.host, {
      credentials: staticCredential(registry.host, { username: "u", password: "p" }),
    }).repository("lib/app");

    await assert.rejects(() => repo.blobs.exists(`sha256:${"a".repeat(64)}`), RegistryError);
    assert.equal(attacker.requests.length, 0, "no request (and no creds) should reach the attacker");
  } finally {
    await Promise.all([registry.close(), attacker.close()]);
  }
});
