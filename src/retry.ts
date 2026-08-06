import { setTimeout as sleep } from "node:timers/promises";
import type { FetchLike } from "./auth/client.ts";

/**
 * Retry/backoff wrapper for a `fetch`-like function. Registries and the
 * networks in front of them (proxies, CDNs, load balancers) return transient
 * failures; this retries them with exponential backoff and full jitter,
 * honoring `Retry-After` when present.
 */
export interface RetryOptions {
  /** Maximum number of retries after the first attempt. Default `3`. */
  maxRetries?: number;
  /** Base delay in milliseconds for the first retry. Default `100`. */
  minTimeoutMs?: number;
  /** Maximum delay in milliseconds between retries. Default `10000`. */
  maxTimeoutMs?: number;
  /** Exponential backoff factor. Default `2`. */
  factor?: number;
  /** HTTP status codes that should be retried. Default `429, 500, 502, 503, 504`. */
  retryStatus?: readonly number[];
}

interface ResolvedRetryOptions {
  maxRetries: number;
  minTimeoutMs: number;
  maxTimeoutMs: number;
  factor: number;
  retryStatus: readonly number[];
}

const DEFAULTS: ResolvedRetryOptions = {
  maxRetries: 3,
  minTimeoutMs: 100,
  maxTimeoutMs: 10_000,
  factor: 2,
  retryStatus: [429, 500, 502, 503, 504],
};

/**
 * Wraps a fetch implementation with retry semantics. Retries are attempted on
 * network errors and on the configured retryable status codes. Requests whose
 * body is a stream are never retried (the body cannot be replayed), and an
 * aborted signal short-circuits any pending backoff.
 */
export function withRetry(fetchImpl: FetchLike, options: RetryOptions = {}): FetchLike {
  const config: ResolvedRetryOptions = { ...DEFAULTS };
  if (options.maxRetries !== undefined) config.maxRetries = options.maxRetries;
  if (options.minTimeoutMs !== undefined) config.minTimeoutMs = options.minTimeoutMs;
  if (options.maxTimeoutMs !== undefined) config.maxTimeoutMs = options.maxTimeoutMs;
  if (options.factor !== undefined) config.factor = options.factor;
  if (options.retryStatus !== undefined) config.retryStatus = options.retryStatus;

  return async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const signal = init?.signal ?? undefined;
    const bodyReplayable = !(init?.body instanceof ReadableStream);
    const maxRetries = bodyReplayable ? config.maxRetries : 0;

    let attempt = 0;
    for (;;) {
      try {
        const response = await fetchImpl(input, init);
        if (attempt >= maxRetries || !config.retryStatus.includes(response.status)) {
          return response;
        }
        const wait = retryAfter(response, config.maxTimeoutMs) ?? backoff(config, attempt);
        await drain(response);
        await sleep(wait, undefined, signal ? { signal } : undefined);
      } catch (err) {
        if (attempt >= maxRetries || isAbortError(err, signal)) {
          throw err;
        }
        await sleep(backoff(config, attempt), undefined, signal ? { signal } : undefined);
      }
      attempt++;
    }
  };
}

function backoff(config: ResolvedRetryOptions, attempt: number): number {
  const ceiling = Math.min(config.maxTimeoutMs, config.minTimeoutMs * config.factor ** attempt);
  return Math.round(Math.random() * ceiling); // full jitter
}

function retryAfter(response: Response, maxMs: number): number | undefined {
  const header = response.headers.get("retry-after");
  if (!header) {
    return undefined;
  }
  let ms: number;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) {
    ms = seconds * 1000;
  } else {
    const date = Date.parse(header);
    if (Number.isNaN(date)) {
      return undefined;
    }
    ms = date - Date.now();
  }
  return Math.min(Math.max(ms, 0), maxMs);
}

function isAbortError(err: unknown, signal: AbortSignal | undefined): boolean {
  if (signal?.aborted) {
    return true;
  }
  return typeof err === "object" && err !== null && (err as { name?: string }).name === "AbortError";
}

async function drain(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // ignore
  }
}
