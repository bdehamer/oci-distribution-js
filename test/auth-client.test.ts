import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { AuthClient } from "../src/auth/client.ts";

interface RecordedRequest {
  url: string;
  method: string;
  headers: Headers;
  body: string;
}

function recordingFetch(
  handler: (req: RecordedRequest) => Response | Promise<Response>,
): { fetch: (input: string | URL, init?: RequestInit) => Promise<Response>; calls: RecordedRequest[] } {
  const calls: RecordedRequest[] = [];
  const fetchImpl = async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const req: RecordedRequest = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: typeof init?.body === "string" ? init.body : "",
    };
    calls.push(req);
    return handler(req);
  };
  return { fetch: fetchImpl, calls };
}

const RESOURCE = "https://reg.example/v2/foo/manifests/latest";

function bearerChallenge(): Response {
  return new Response("", {
    status: 401,
    headers: {
      "www-authenticate": 'Bearer realm="https://auth.example/token",service="svc",scope="repository:foo:pull"',
    },
  });
}

test("bearer flow: 401 challenge, distribution GET token, retry", async () => {
  const { fetch, calls } = recordingFetch((req) => {
    if (req.url.startsWith("https://auth.example/token")) {
      return new Response(JSON.stringify({ token: "abc" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (req.headers.get("authorization") === "Bearer abc") {
      return new Response("ok", { status: 200 });
    }
    return bearerChallenge();
  });

  const client = new AuthClient({ fetch, credentials: () => ({}) });
  const res = await client.do(RESOURCE, { method: "GET" }, { scopes: ["repository:foo:pull"] });
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "ok");

  const tokenCall = calls.find((c) => c.url.startsWith("https://auth.example/token"));
  assert.ok(tokenCall);
  const url = new URL(tokenCall.url);
  assert.equal(tokenCall.method, "GET");
  assert.equal(url.searchParams.get("service"), "svc");
  assert.deepEqual(url.searchParams.getAll("scope"), ["repository:foo:pull"]);
});

test("bearer flow caches the token for subsequent requests", async () => {
  let challenges = 0;
  const { fetch, calls } = recordingFetch((req) => {
    if (req.url.startsWith("https://auth.example/token")) {
      return new Response(JSON.stringify({ token: "abc" }), { status: 200 });
    }
    if (req.headers.get("authorization") === "Bearer abc") {
      return new Response("ok", { status: 200 });
    }
    challenges++;
    return bearerChallenge();
  });

  const client = new AuthClient({ fetch, credentials: () => ({}) });
  await client.do(RESOURCE, { method: "GET" }, { scopes: ["repository:foo:pull"] });
  await client.do(RESOURCE, { method: "GET" }, { scopes: ["repository:foo:pull"] });

  assert.equal(challenges, 1); // only the first request hit a 401
  const tokenCalls = calls.filter((c) => c.url.startsWith("https://auth.example/token"));
  assert.equal(tokenCalls.length, 1);
});

test("distribution GET token attaches basic auth when credentials exist", async () => {
  const { fetch, calls } = recordingFetch((req) => {
    if (req.url.startsWith("https://auth.example/token")) {
      return new Response(JSON.stringify({ access_token: "tok" }), { status: 200 });
    }
    if (req.headers.get("authorization") === "Bearer tok") {
      return new Response("ok", { status: 200 });
    }
    return bearerChallenge();
  });

  const client = new AuthClient({ fetch, credentials: () => ({ username: "u", password: "p" }) });
  await client.do(RESOURCE, { method: "GET" });

  const tokenCall = calls.find((c) => c.url.startsWith("https://auth.example/token"));
  assert.ok(tokenCall);
  const expected = `Basic ${Buffer.from("u:p").toString("base64")}`;
  assert.equal(tokenCall.headers.get("authorization"), expected);
});

test("basic flow sets the Basic authorization header and retries", async () => {
  const { fetch } = recordingFetch((req) => {
    const expected = `Basic ${Buffer.from("u:p").toString("base64")}`;
    if (req.headers.get("authorization") === expected) {
      return new Response("ok", { status: 200 });
    }
    return new Response("", { status: 401, headers: { "www-authenticate": 'Basic realm="reg"' } });
  });

  const client = new AuthClient({ fetch, credentials: () => ({ username: "u", password: "p" }) });
  const res = await client.do(RESOURCE, { method: "GET" });
  assert.equal(res.status, 200);
});

test("oauth2 flow posts a refresh_token grant", async () => {
  const { fetch, calls } = recordingFetch((req) => {
    if (req.url === "https://auth.example/token") {
      return new Response(JSON.stringify({ access_token: "xyz" }), { status: 200 });
    }
    if (req.headers.get("authorization") === "Bearer xyz") {
      return new Response("ok", { status: 200 });
    }
    return bearerChallenge();
  });

  const client = new AuthClient({ fetch, credentials: () => ({ refreshToken: "RT" }), clientId: "my-client" });
  const res = await client.do(RESOURCE, { method: "GET" }, { scopes: ["repository:foo:pull"] });
  assert.equal(res.status, 200);

  const tokenCall = calls.find((c) => c.url === "https://auth.example/token" && c.method === "POST");
  assert.ok(tokenCall);
  assert.match(tokenCall.headers.get("content-type") ?? "", /application\/x-www-form-urlencoded/);
  const form = new URLSearchParams(tokenCall.body);
  assert.equal(form.get("grant_type"), "refresh_token");
  assert.equal(form.get("refresh_token"), "RT");
  assert.equal(form.get("service"), "svc");
  assert.equal(form.get("client_id"), "my-client");
  assert.equal(form.get("scope"), "repository:foo:pull");
});

test("forceOAuth2 posts a password grant", async () => {
  const { fetch, calls } = recordingFetch((req) => {
    if (req.url === "https://auth.example/token") {
      return new Response(JSON.stringify({ access_token: "pw-tok" }), { status: 200 });
    }
    if (req.headers.get("authorization") === "Bearer pw-tok") {
      return new Response("ok", { status: 200 });
    }
    return bearerChallenge();
  });

  const client = new AuthClient({
    fetch,
    credentials: () => ({ username: "u", password: "p" }),
    forceOAuth2: true,
  });
  await client.do(RESOURCE, { method: "GET" });

  const tokenCall = calls.find((c) => c.method === "POST");
  assert.ok(tokenCall);
  const form = new URLSearchParams(tokenCall.body);
  assert.equal(form.get("grant_type"), "password");
  assert.equal(form.get("username"), "u");
  assert.equal(form.get("password"), "p");
});

test("accessToken credential is used directly without a token request", async () => {
  const { fetch, calls } = recordingFetch((req) => {
    if (req.headers.get("authorization") === "Bearer direct") {
      return new Response("ok", { status: 200 });
    }
    return bearerChallenge();
  });

  const client = new AuthClient({ fetch, credentials: () => ({ accessToken: "direct" }) });
  const res = await client.do(RESOURCE, { method: "GET" });
  assert.equal(res.status, 200);
  assert.equal(calls.filter((c) => c.url.includes("/token")).length, 0);
});

test("a caller-provided Authorization header is left untouched", async () => {
  const { fetch, calls } = recordingFetch(() => new Response("ok", { status: 200 }));
  const client = new AuthClient({ fetch, credentials: () => ({ username: "u", password: "p" }) });
  await client.do(RESOURCE, { method: "GET", headers: { authorization: "Bearer preset" } });
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.headers.get("authorization"), "Bearer preset");
});

// --- L-2: fail-closed 401 origin guard (credentials must not follow a redirect) ---

test("does not offer credentials to a 401 served from a cross-origin redirect host", async () => {
  const { fetch, calls } = recordingFetch((req) => {
    if (req.url === RESOURCE) {
      return new Response("", { status: 307, headers: { location: "https://evil.example/steal" } });
    }
    if (req.url.startsWith("https://evil.example/token")) {
      return new Response(JSON.stringify({ token: "abc" }), { status: 200 });
    }
    // The cross-origin host issues a bearer challenge of its own.
    return new Response("", {
      status: 401,
      headers: {
        "www-authenticate":
          'Bearer realm="https://evil.example/token",service="svc",scope="repository:foo:pull"',
      },
    });
  });

  const client = new AuthClient({ fetch, credentials: () => ({ username: "u", password: "p" }) });
  const res = await client.do(RESOURCE, { method: "GET" }, { scopes: ["repository:foo:pull"] });

  assert.equal(res.status, 401, "the cross-origin 401 should be surfaced, not challenged");
  assert.equal(
    calls.filter((c) => c.url.includes("evil.example/token")).length,
    0,
    "no token request (and no credentials) should reach the cross-origin host",
  );
  const evilReq = calls.find((c) => c.url.startsWith("https://evil.example/steal"));
  assert.ok(evilReq);
  assert.equal(evilReq.headers.get("authorization"), null, "no Authorization across origins");
});

// --- Info-1: require an https (or loopback) token endpoint ---

test("refuses to send credentials to a non-HTTPS (non-loopback) token endpoint", async () => {
  const { fetch, calls } = recordingFetch((req) => {
    if (req.url.startsWith("http://attacker.example/token")) {
      return new Response(JSON.stringify({ token: "abc" }), { status: 200 });
    }
    if (req.headers.get("authorization")) {
      return new Response("ok", { status: 200 });
    }
    return new Response("", {
      status: 401,
      headers: {
        "www-authenticate":
          'Bearer realm="http://attacker.example/token",service="svc",scope="repository:foo:pull"',
      },
    });
  });

  const client = new AuthClient({ fetch, credentials: () => ({ username: "u", password: "p" }) });
  const res = await client.do(RESOURCE, { method: "GET" }, { scopes: ["repository:foo:pull"] });

  assert.equal(res.status, 401, "a challenge to an http realm must be refused");
  assert.equal(
    calls.filter((c) => c.url.includes("attacker.example")).length,
    0,
    "no token request (and no credentials) should reach the http realm",
  );
});

test("still uses an https token endpoint on a different host (Docker Hub pattern)", async () => {
  const { fetch, calls } = recordingFetch((req) => {
    if (req.url.startsWith("https://auth.example/token")) {
      return new Response(JSON.stringify({ token: "abc" }), { status: 200 });
    }
    if (req.headers.get("authorization")) {
      return new Response("ok", { status: 200 });
    }
    return bearerChallenge();
  });

  const client = new AuthClient({ fetch, credentials: () => ({ username: "u", password: "p" }) });
  const res = await client.do(RESOURCE, { method: "GET" }, { scopes: ["repository:foo:pull"] });
  assert.equal(res.status, 200, "a cross-host https realm remains allowed");
  assert.ok(calls.some((c) => c.url.startsWith("https://auth.example/token")));
});
