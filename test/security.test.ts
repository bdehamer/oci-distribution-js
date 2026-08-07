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

// --- M-2: digest verification fails closed for an uncomputable algorithm ---

test("blob get fails closed for a digest whose algorithm cannot be verified", async () => {
  const payload = Buffer.from("unverifiable bytes");
  const server = await startServer((req, res) => {
    res.statusCode = 200;
    res.end(payload);
  });
  try {
    const repo = new Registry(server.host).repository("lib/app");
    // 'blake3' is a syntactically valid digest algorithm that Node's crypto
    // cannot compute, so integrity cannot be verified.
    const digest = `blake3:${"0".repeat(64)}`;
    await assert.rejects(
      () => repo.blobs.get(digest),
      (err: unknown) =>
        err instanceof RegistryError && /unsupported algorithm/.test(String((err as Error).message)),
      "must throw rather than return unverified bytes",
    );
  } finally {
    await server.close();
  }
});

// --- L-1: server-named cross-host Link pagination goes unauthenticated ---

test("credentials are NOT sent to a cross-host Link pagination target (naive global provider)", async () => {
  // A naive/global provider that ignores the host argument. This is the only
  // condition under which an un-hardened pagination follow leaks: exact-host
  // providers already withhold credentials from a foreign host. The attacker
  // host also demands auth and offers a token endpoint, so an un-hardened client
  // would negotiate and hand over the global credentials.
  const globalProvider = () => ({ username: "u", password: "p" });

  const attacker = await startServer(
    registryHandler((req, res, self) => {
      const url = new URL(req.url ?? "/", self.origin);
      if (req.method === "GET" && url.pathname === "/v2/lib/app/tags/list") {
        res.setHeader("content-type", "application/json");
        res.statusCode = 200;
        res.end(JSON.stringify({ name: "lib/app", tags: ["page2"] }));
        return true;
      }
      return false;
    }),
  );
  const registry = await startServer(
    registryHandler((req, res, self) => {
      const url = new URL(req.url ?? "/", self.origin);
      if (req.method === "GET" && url.pathname === "/v2/lib/app/tags/list") {
        // Offload the "next" page to a DIFFERENT host (attacker-controllable).
        res.setHeader("link", `<${attacker.origin}/v2/lib/app/tags/list?page=2>; rel="next"`);
        res.setHeader("content-type", "application/json");
        res.statusCode = 200;
        res.end(JSON.stringify({ name: "lib/app", tags: ["page1"] }));
        return true;
      }
      return false;
    }),
  );

  try {
    const repo = new Registry(registry.host, {
      credentials: globalProvider,
      headers: { "x-secret-header": "leak-me" },
    }).repository("lib/app");

    // With the fix the cross-host page is fetched unauthenticated; because the
    // attacker demands auth, pagination fails — that's fine, we only care that
    // no credentials ever reached the attacker.
    await repo.tags.listAll().catch(() => undefined);

    for (const r of attacker.requests) {
      assert.equal(
        r.headers["authorization"],
        undefined,
        `no credentials should reach the attacker (${r.method} ${r.url})`,
      );
      assert.equal(r.headers["x-secret-header"], undefined, "must not leak custom headers");
    }
    assert.ok(
      attacker.requests.some((r) => r.url.includes("/tags/list")),
      "the attacker should have received the (unauthenticated) page fetch",
    );
    assert.equal(
      attacker.requests.filter((r) => r.url.includes("/token")).length,
      0,
      "the attacker token endpoint must never be hit",
    );
  } finally {
    await Promise.all([registry.close(), attacker.close()]);
  }
});
