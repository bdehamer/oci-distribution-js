import type { Descriptor } from "./types.ts";

/**
 * Error types raised by the client, plus OCI error-code constants and helpers
 * for parsing registry error responses.
 *
 * @see https://github.com/opencontainers/distribution-spec — Error Codes
 */

/** The registry error codes defined by the OCI Distribution Spec. */
export const ErrorCode = {
  BLOB_UNKNOWN: "BLOB_UNKNOWN",
  BLOB_UPLOAD_INVALID: "BLOB_UPLOAD_INVALID",
  BLOB_UPLOAD_UNKNOWN: "BLOB_UPLOAD_UNKNOWN",
  DIGEST_INVALID: "DIGEST_INVALID",
  MANIFEST_BLOB_UNKNOWN: "MANIFEST_BLOB_UNKNOWN",
  MANIFEST_INVALID: "MANIFEST_INVALID",
  MANIFEST_UNKNOWN: "MANIFEST_UNKNOWN",
  NAME_INVALID: "NAME_INVALID",
  NAME_UNKNOWN: "NAME_UNKNOWN",
  SIZE_INVALID: "SIZE_INVALID",
  UNAUTHORIZED: "UNAUTHORIZED",
  DENIED: "DENIED",
  UNSUPPORTED: "UNSUPPORTED",
  TOOMANYREQUESTS: "TOOMANYREQUESTS",
} as const;

/** A single structured error returned by a registry. */
export interface OCIErrorInfo {
  code: string;
  message?: string;
  detail?: unknown;
}

/** Base class for all errors raised by this library. */
export class RegistryError extends Error {
  override name = "RegistryError";
}

/** Options used to construct a {@link ResponseError}. */
export interface ResponseErrorInit {
  status: number;
  statusText: string;
  method: string;
  url: string;
  headers: Headers;
  errors: OCIErrorInfo[];
  body?: string;
}

/** An error representing a non-successful HTTP response from a registry. */
export class ResponseError extends RegistryError {
  override name = "ResponseError";
  /** The HTTP status code. */
  readonly status: number;
  /** The HTTP status text. */
  readonly statusText: string;
  /** The HTTP method of the originating request. */
  readonly method: string;
  /** The URL of the originating request. */
  readonly url: string;
  /** The response headers. */
  readonly headers: Headers;
  /** The structured OCI errors parsed from the response body, if any. */
  readonly errors: OCIErrorInfo[];
  /** The raw response body text, if it was read. */
  readonly body: string | undefined;

  constructor(init: ResponseErrorInit) {
    super(buildResponseMessage(init));
    this.status = init.status;
    this.statusText = init.statusText;
    this.method = init.method;
    this.url = init.url;
    this.headers = init.headers;
    this.errors = init.errors;
    this.body = init.body;
  }

  /** True if any parsed OCI error carries the given code. */
  hasErrorCode(code: string): boolean {
    return this.errors.some((e) => e.code === code);
  }

  /**
   * Builds a {@link ResponseError} from a fetch {@link Response}, reading and
   * parsing its body. The body stream is consumed.
   */
  static async fromResponse(response: Response, method: string, url?: string): Promise<ResponseError> {
    const body = await safeReadText(response);
    return new ResponseError({
      status: response.status,
      statusText: response.statusText,
      method,
      url: url ?? response.url,
      headers: response.headers,
      errors: parseOCIErrors(body),
      body,
    });
  }
}

/** Raised when downloaded content does not match its expected digest. */
export class DigestMismatchError extends RegistryError {
  override name = "DigestMismatchError";
  readonly expected: string;
  readonly actual: string;

  constructor(expected: string, actual: string) {
    super(`digest mismatch: expected ${expected}, got ${actual}`);
    this.expected = expected;
    this.actual = actual;
  }
}

/** Raised when downloaded content does not match its expected size. */
export class SizeMismatchError extends RegistryError {
  override name = "SizeMismatchError";
  readonly expected: number;
  readonly actual: number;

  constructor(expected: number, actual: number) {
    super(`size mismatch: expected ${expected} bytes, got ${actual} bytes`);
    this.expected = expected;
    this.actual = actual;
  }
}

/** Raised when a referenced descriptor cannot be found in the registry. */
export class NotFoundError extends RegistryError {
  override name = "NotFoundError";
  readonly reference: string | Descriptor;

  constructor(reference: string | Descriptor) {
    const ref = typeof reference === "string" ? reference : reference.digest;
    super(`not found: ${ref}`);
    this.reference = reference;
  }
}

/** Parses the OCI structured errors from a `4xx` JSON response body. */
export function parseOCIErrors(body: string): OCIErrorInfo[] {
  if (!body) {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return [];
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !Array.isArray((parsed as { errors?: unknown }).errors)
  ) {
    return [];
  }
  const out: OCIErrorInfo[] = [];
  for (const entry of (parsed as { errors: unknown[] }).errors) {
    if (typeof entry === "object" && entry !== null && "code" in entry) {
      const e = entry as Record<string, unknown>;
      const info: OCIErrorInfo = { code: String(e.code) };
      if (typeof e.message === "string") {
        info.message = e.message;
      }
      if ("detail" in e) {
        info.detail = e.detail;
      }
      out.push(info);
    }
  }
  return out;
}

function buildResponseMessage(init: ResponseErrorInit): string {
  const base = `${init.method} ${init.url}: ${init.status} ${init.statusText}`.trimEnd();
  if (init.errors.length > 0) {
    const detail = init.errors
      .map((e) => (e.message ? `${e.code}: ${e.message}` : e.code))
      .join("; ");
    return `${base} (${detail})`;
  }
  return base;
}

async function safeReadText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return "";
  }
}
