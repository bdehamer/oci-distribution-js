import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";

/**
 * A minimal in-memory OCI registry for end-to-end tests. Supports blobs
 * (monolithic upload + cross-repo mount), manifests (with subject handling),
 * tags listing with pagination, and the referrers API (which can be disabled to
 * exercise the tag-schema fallback). Optionally requires bearer-token auth.
 */
export interface MockRegistryOptions {
  /** Enable the referrers API. When false, `/referrers/` returns 404. */
  referrersApi?: boolean;
  /** Require a bearer token obtained from the built-in token endpoint. */
  requireAuth?: boolean;
  /** Page size that forces `Link`-header pagination for tag listing. */
  tagPageSize?: number;
}

interface RepoState {
  blobs: Map<string, Buffer>;
  manifests: Map<string, { body: Buffer; contentType: string }>;
  tags: Map<string, string>;
  referrers: Map<string, Descriptor[]>;
}

interface Descriptor {
  mediaType: string;
  digest: string;
  size: number;
  artifactType?: string;
  annotations?: Record<string, string>;
}

export interface MockRegistry {
  origin: string;
  host: string;
  close(): Promise<void>;
  repo(name: string): RepoState;
}

const TOKEN = "mock-access-token";

export async function createMockRegistry(options: MockRegistryOptions = {}): Promise<MockRegistry> {
  const referrersApi = options.referrersApi ?? true;
  const requireAuth = options.requireAuth ?? false;
  const repos = new Map<string, RepoState>();
  const uploads = new Map<string, string>(); // uploadId -> repo name

  const repo = (name: string): RepoState => {
    let state = repos.get(name);
    if (!state) {
      state = { blobs: new Map(), manifests: new Map(), tags: new Map(), referrers: new Map() };
      repos.set(name, state);
    }
    return state;
  };

  const server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      res.statusCode = 500;
      res.end(String(err));
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    if (path === "/token") {
      json(res, 200, { access_token: TOKEN, token: TOKEN, expires_in: 300 });
      return;
    }

    if (requireAuth) {
      const auth = req.headers["authorization"];
      if (auth !== `Bearer ${TOKEN}`) {
        res.setHeader(
          "www-authenticate",
          `Bearer realm="${origin()}/token",service="mock",scope="repository:_:pull,push"`,
        );
        empty(res, 401);
        return;
      }
    }

    if (path === "/v2/" || path === "/v2") {
      empty(res, 200);
      return;
    }

    const blobUpload = path.match(/^\/v2\/(.+)\/blobs\/uploads\/?$/);
    if (blobUpload && method === "POST") {
      handleUploadStart(decodeURIComponent(blobUpload[1]!), url, res);
      return;
    }

    const uploadPut = path.match(/^\/v2\/(.+)\/blobs\/uploads\/([^/]+)$/);
    if (uploadPut) {
      const name = decodeURIComponent(uploadPut[1]!);
      const id = uploadPut[2]!;
      if (method === "PUT") {
        await handleUploadFinish(name, id, url, req, res);
        return;
      }
      if (method === "DELETE") {
        uploads.delete(id);
        empty(res, 204);
        return;
      }
    }

    const blob = path.match(/^\/v2\/(.+)\/blobs\/(sha256:[a-f0-9]+|sha512:[a-f0-9]+)$/);
    if (blob) {
      handleBlob(decodeURIComponent(blob[1]!), blob[2]!, method, res);
      return;
    }

    const manifest = path.match(/^\/v2\/(.+)\/manifests\/(.+)$/);
    if (manifest) {
      await handleManifest(
        decodeURIComponent(manifest[1]!),
        decodeURIComponent(manifest[2]!),
        method,
        req,
        res,
      );
      return;
    }

    const referrers = path.match(/^\/v2\/(.+)\/referrers\/(.+)$/);
    if (referrers && method === "GET") {
      handleReferrers(decodeURIComponent(referrers[1]!), decodeURIComponent(referrers[2]!), url, res);
      return;
    }

    const tags = path.match(/^\/v2\/(.+)\/tags\/list$/);
    if (tags && method === "GET") {
      handleTags(decodeURIComponent(tags[1]!), url, res);
      return;
    }

    empty(res, 404);
  }

  function handleUploadStart(name: string, url: URL, res: ServerResponse): void {
    const mount = url.searchParams.get("mount");
    const from = url.searchParams.get("from");
    if (mount && from) {
      const source = repos.get(from);
      if (source?.blobs.has(mount)) {
        repo(name).blobs.set(mount, source.blobs.get(mount)!);
        res.setHeader("location", `/v2/${name}/blobs/${mount}`);
        res.setHeader("docker-content-digest", mount);
        empty(res, 201);
        return;
      }
    }
    const id = randomUUID();
    uploads.set(id, name);
    res.setHeader("location", `/v2/${name}/blobs/uploads/${id}`);
    empty(res, 202);
  }

  async function handleUploadFinish(
    name: string,
    id: string,
    url: URL,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    if (uploads.get(id) !== name) {
      empty(res, 404);
      return;
    }
    const body = await readBody(req);
    const digest = url.searchParams.get("digest") ?? sha256(body);
    repo(name).blobs.set(digest, body);
    uploads.delete(id);
    res.setHeader("location", `/v2/${name}/blobs/${digest}`);
    res.setHeader("docker-content-digest", digest);
    empty(res, 201);
  }

  function handleBlob(name: string, digest: string, method: string, res: ServerResponse): void {
    const body = repos.get(name)?.blobs.get(digest);
    if (!body) {
      empty(res, 404);
      return;
    }
    res.setHeader("docker-content-digest", digest);
    res.setHeader("content-length", String(body.byteLength));
    res.setHeader("content-type", "application/octet-stream");
    if (method === "HEAD") {
      empty(res, 200);
      return;
    }
    res.statusCode = 200;
    res.end(body);
  }

  async function handleManifest(
    name: string,
    reference: string,
    method: string,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const state = repo(name);

    if (method === "PUT") {
      const body = await readBody(req);
      const digest = sha256(body);
      const contentType = String(req.headers["content-type"] ?? "application/octet-stream");
      state.manifests.set(digest, { body, contentType });
      if (!reference.startsWith("sha256:")) {
        state.tags.set(reference, digest);
      }
      res.setHeader("docker-content-digest", digest);
      res.setHeader("location", `/v2/${name}/manifests/${digest}`);

      const parsed = safeJSON(body);
      const subject = parsed?.subject?.digest;
      if (subject && referrersApi) {
        const list = state.referrers.get(subject) ?? [];
        const descriptor: Descriptor = { mediaType: contentType, digest, size: body.byteLength };
        const artifactType = parsed?.artifactType ?? parsed?.config?.mediaType;
        if (artifactType) descriptor.artifactType = artifactType;
        if (parsed?.annotations) descriptor.annotations = parsed.annotations;
        if (!list.some((d) => d.digest === digest)) {
          list.push(descriptor);
        }
        state.referrers.set(subject, list);
        res.setHeader("oci-subject", subject);
      }
      empty(res, 201);
      return;
    }

    const digest = reference.startsWith("sha256:") ? reference : state.tags.get(reference);
    const stored = digest ? state.manifests.get(digest) : undefined;
    if (!stored || !digest) {
      empty(res, 404);
      return;
    }
    res.setHeader("docker-content-digest", digest);
    res.setHeader("content-type", stored.contentType);
    res.setHeader("content-length", String(stored.body.byteLength));
    if (method === "HEAD") {
      empty(res, 200);
      return;
    }
    if (method === "DELETE") {
      state.manifests.delete(digest);
      empty(res, 202);
      return;
    }
    res.statusCode = 200;
    res.end(stored.body);
  }

  function handleReferrers(name: string, subject: string, url: URL, res: ServerResponse): void {
    if (!referrersApi) {
      empty(res, 404);
      return;
    }
    const filter = url.searchParams.get("artifactType");
    let manifests = repos.get(name)?.referrers.get(subject) ?? [];
    if (filter) {
      manifests = manifests.filter((d) => d.artifactType === filter);
      res.setHeader("oci-filters-applied", "artifactType");
    }
    res.setHeader("content-type", "application/vnd.oci.image.index.v1+json");
    json(res, 200, {
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.index.v1+json",
      manifests,
    });
  }

  function handleTags(name: string, url: URL, res: ServerResponse): void {
    const state = repos.get(name);
    if (!state) {
      empty(res, 404);
      return;
    }
    const all = [...state.tags.keys()].sort();
    const n = url.searchParams.get("n");
    const last = url.searchParams.get("last");
    let start = 0;
    if (last) {
      start = all.findIndex((t) => t > last);
      if (start < 0) start = all.length;
    }
    const size = n ? Number(n) : options.tagPageSize;
    let page = all.slice(start);
    if (size !== undefined && page.length > size) {
      page = page.slice(0, size);
      const nextLast = page[page.length - 1]!;
      res.setHeader(
        "link",
        `</v2/${name}/tags/list?n=${size}&last=${encodeURIComponent(nextLast)}>; rel="next"`,
      );
    }
    json(res, 200, { name, tags: page });
  }

  function origin(): string {
    const address = server.address() as AddressInfo;
    return `http://127.0.0.1:${address.port}`;
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;

  return {
    origin: `http://127.0.0.1:${address.port}`,
    host: `127.0.0.1:${address.port}`,
    repo,
    close: () => closeServer(server),
  };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sha256(data: Buffer): string {
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  if (!res.hasHeader("content-type")) {
    res.setHeader("content-type", "application/json");
  }
  res.statusCode = status;
  res.end(text);
}

function empty(res: ServerResponse, status: number): void {
  res.statusCode = status;
  res.end();
}

interface ParsedManifest {
  subject?: { digest?: string };
  artifactType?: string;
  config?: { mediaType?: string };
  annotations?: Record<string, string>;
}

function safeJSON(body: Buffer): ParsedManifest | undefined {
  try {
    return JSON.parse(body.toString("utf8")) as ParsedManifest;
  } catch {
    return undefined;
  }
}
