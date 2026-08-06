import { test } from "node:test";
import assert from "node:assert/strict";
import { withRetry } from "../src/retry.ts";

const fast = { minTimeoutMs: 1, maxTimeoutMs: 4 };

function stub(
  responses: Array<Response | (() => Response | Promise<Response>)>,
): { fetch: (i: string | URL, init?: RequestInit) => Promise<Response>; count: () => number } {
  let i = 0;
  const fetchImpl = async (): Promise<Response> => {
    const entry = responses[Math.min(i, responses.length - 1)]!;
    i++;
    return typeof entry === "function" ? entry() : entry;
  };
  return { fetch: fetchImpl, count: () => i };
}

test("retries a 503 then returns the success response", async () => {
  const s = stub([new Response("", { status: 503 }), new Response("ok", { status: 200 })]);
  const wrapped = withRetry(s.fetch, fast);
  const res = await wrapped("https://x/y");
  assert.equal(res.status, 200);
  assert.equal(s.count(), 2);
});

test("gives up after maxRetries and returns the last response", async () => {
  const s = stub([new Response("", { status: 503 })]);
  const wrapped = withRetry(s.fetch, { ...fast, maxRetries: 2 });
  const res = await wrapped("https://x/y");
  assert.equal(res.status, 503);
  assert.equal(s.count(), 3); // initial + 2 retries
});

test("does not retry a non-retryable status", async () => {
  const s = stub([new Response("", { status: 400 })]);
  const wrapped = withRetry(s.fetch, fast);
  const res = await wrapped("https://x/y");
  assert.equal(res.status, 400);
  assert.equal(s.count(), 1);
});

test("retries a thrown network error", async () => {
  let thrown = false;
  const fetchImpl = async (): Promise<Response> => {
    if (!thrown) {
      thrown = true;
      throw new Error("ECONNRESET");
    }
    return new Response("ok", { status: 200 });
  };
  const res = await withRetry(fetchImpl, fast)("https://x/y");
  assert.equal(res.status, 200);
});

test("honors a numeric Retry-After header", async () => {
  const start = Date.now();
  const s = stub([
    new Response("", { status: 429, headers: { "retry-after": "0" } }),
    new Response("ok", { status: 200 }),
  ]);
  const res = await withRetry(s.fetch, fast)("https://x/y");
  assert.equal(res.status, 200);
  assert.ok(Date.now() - start < 1000);
});

test("does not retry when the body is a stream", async () => {
  const s = stub([new Response("", { status: 503 })]);
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array([1]));
      controller.close();
    },
  });
  const res = await withRetry(s.fetch, fast)("https://x/y", { method: "PUT", body });
  assert.equal(res.status, 503);
  assert.equal(s.count(), 1);
});

test("respects an already-aborted signal by not retrying the throw", async () => {
  const controller = new AbortController();
  controller.abort();
  const fetchImpl = async (): Promise<Response> => {
    const err = new Error("aborted");
    err.name = "AbortError";
    throw err;
  };
  await assert.rejects(() => withRetry(fetchImpl, fast)("https://x/y", { signal: controller.signal }));
});
