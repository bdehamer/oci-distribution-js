import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import {
  EMPTY_CREDENTIAL,
  normalizeRegistry,
  type Credential,
  type CredentialProvider,
} from "./credentials.ts";

/**
 * A credential provider backed by a Docker configuration file
 * (`~/.docker/config.json` by default, or `$DOCKER_CONFIG/config.json`).
 *
 * Resolution order for a registry, matching the Docker CLI:
 *   1. a matching entry in `credHelpers` → runs `docker-credential-<helper>`
 *   2. a configured `credsStore` → runs `docker-credential-<store>`
 *   3. an inline `auths` entry (base64 `user:pass` and/or `identitytoken`)
 *
 * All errors (missing file, unparneable JSON, failing helper) are swallowed and
 * reported as anonymous access, so this provider composes safely in a chain.
 */
export function dockerConfigCredential(options: DockerConfigOptions = {}): CredentialProvider {
  const configPath = options.configPath ?? defaultConfigPath(options.env ?? process.env);
  const runHelper = options.runHelper ?? defaultRunHelper;

  return async (registry: string): Promise<Credential | undefined> => {
    const config = await loadConfig(configPath);
    if (!config) {
      return EMPTY_CREDENTIAL;
    }

    const wanted = normalizeRegistry(registry);
    const serverURL = serverUrlFor(registry);

    const helper = matchHelper(config.credHelpers, wanted);
    if (helper) {
      const cred = await tryHelper(runHelper, helper, serverURL);
      if (cred) {
        return cred;
      }
    }

    if (config.credsStore) {
      const cred = await tryHelper(runHelper, config.credsStore, serverURL);
      if (cred) {
        return cred;
      }
    }

    const entry = matchAuths(config.auths, wanted);
    if (entry) {
      return decodeAuthEntry(entry);
    }

    return EMPTY_CREDENTIAL;
  };
}

/**
 * Reads the top-level `HttpHeaders` map from the Docker configuration file
 * (`~/.docker/config.json` by default, or `$DOCKER_CONFIG/config.json`).
 *
 * Some registries and proxies require custom HTTP headers to authenticate. Pass
 * the result as the `headers` option to a {@link Registry}, where the headers
 * are scoped to the registry's own host (and never sent to a host named by a
 * server response). Returns an empty object when the file is missing,
 * unparseable, or has no `HttpHeaders`.
 *
 * @example
 * new Registry("ghcr.io", {
 *   credentials: dockerConfigCredential(),
 *   headers: dockerConfigHeaders(),
 * });
 */
export function dockerConfigHeaders(
  options: DockerConfigHeadersOptions = {},
): Record<string, string> {
  const configPath = options.configPath ?? defaultConfigPath(options.env ?? process.env);
  return loadConfigSync(configPath)?.HttpHeaders ?? {};
}

/** Options for {@link dockerConfigHeaders}. */
export interface DockerConfigHeadersOptions {
  /** Explicit path to the config file. Overrides env-based resolution. */
  configPath?: string;
  /** Environment used for `$DOCKER_CONFIG` / `$HOME` resolution. */
  env?: NodeJS.ProcessEnv;
}

/** Options for {@link dockerConfigCredential}. */
export interface DockerConfigOptions {
  /** Explicit path to the config file. Overrides env-based resolution. */
  configPath?: string;
  /** Environment used for `$DOCKER_CONFIG` / `$HOME` resolution. */
  env?: NodeJS.ProcessEnv;
  /** Override for invoking a credential helper (primarily for testing). */
  runHelper?: HelperRunner;
}

/** The JSON returned by a `docker-credential-*` helper's `get` command. */
export interface HelperResult {
  ServerURL?: string;
  Username?: string;
  Secret?: string;
}

/** Invokes `docker-credential-<name> get` for the given server URL. */
export type HelperRunner = (helper: string, serverURL: string) => Promise<HelperResult | undefined>;

interface DockerConfig {
  auths?: Record<string, AuthEntry>;
  credHelpers?: Record<string, string>;
  credsStore?: string;
  HttpHeaders?: Record<string, string>;
}

interface AuthEntry {
  auth?: string;
  identitytoken?: string;
  username?: string;
  password?: string;
}

function defaultConfigPath(env: NodeJS.ProcessEnv): string {
  if (env.DOCKER_CONFIG) {
    return join(env.DOCKER_CONFIG, "config.json");
  }
  const home = env.HOME ?? homedir();
  return join(home, ".docker", "config.json");
}

async function loadConfig(path: string): Promise<DockerConfig | undefined> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return undefined;
  }
  try {
    const parsed = JSON.parse(text) as unknown;
    if (typeof parsed === "object" && parsed !== null) {
      return parsed as DockerConfig;
    }
  } catch {
    // fall through
  }
  return undefined;
}

/** Synchronous variant of {@link loadConfig}, for reading static config values. */
function loadConfigSync(path: string): DockerConfig | undefined {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
  try {
    const parsed = JSON.parse(text) as unknown;
    if (typeof parsed === "object" && parsed !== null) {
      return parsed as DockerConfig;
    }
  } catch {
    // fall through
  }
  return undefined;
}

/** Extracts the host from a Docker auths key that may be a bare host or a URL. */
function hostFromKey(key: string): string {
  let host = key;
  const scheme = host.indexOf("://");
  if (scheme >= 0) {
    host = host.slice(scheme + 3);
  }
  const slash = host.indexOf("/");
  if (slash >= 0) {
    host = host.slice(0, slash);
  }
  return host;
}

function matchAuths(
  auths: Record<string, AuthEntry> | undefined,
  wanted: string,
): AuthEntry | undefined {
  if (!auths) {
    return undefined;
  }
  for (const [key, value] of Object.entries(auths)) {
    if (normalizeRegistry(hostFromKey(key)) === wanted) {
      return value;
    }
  }
  return undefined;
}

function matchHelper(
  helpers: Record<string, string> | undefined,
  wanted: string,
): string | undefined {
  if (!helpers) {
    return undefined;
  }
  for (const [key, value] of Object.entries(helpers)) {
    if (normalizeRegistry(hostFromKey(key)) === wanted) {
      return value;
    }
  }
  return undefined;
}

/** The server URL passed to a credential helper for a given registry. */
function serverUrlFor(registry: string): string {
  if (normalizeRegistry(registry) === "registry-1.docker.io") {
    return "https://index.docker.io/v1/";
  }
  return registry;
}

function decodeAuthEntry(entry: AuthEntry): Credential {
  const cred: Credential = {};
  if (entry.auth) {
    const decoded = Buffer.from(entry.auth, "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx >= 0) {
      cred.username = decoded.slice(0, idx);
      cred.password = decoded.slice(idx + 1);
    }
  }
  if (!cred.username && entry.username) {
    cred.username = entry.username;
  }
  if (!cred.password && entry.password) {
    cred.password = entry.password;
  }
  if (entry.identitytoken) {
    cred.refreshToken = entry.identitytoken;
  }
  return cred;
}

async function tryHelper(
  runHelper: HelperRunner,
  helper: string,
  serverURL: string,
): Promise<Credential | undefined> {
  let result: HelperResult | undefined;
  try {
    result = await runHelper(helper, serverURL);
  } catch {
    return undefined;
  }
  if (!result || !result.Secret) {
    return undefined;
  }
  // A username of "<token>" signals an identity (refresh) token.
  if (result.Username === "<token>") {
    return { refreshToken: result.Secret };
  }
  return { username: result.Username ?? "", password: result.Secret };
}

/** Default helper runner: spawns `docker-credential-<helper> get`. */
const defaultRunHelper: HelperRunner = (helper, serverURL) =>
  new Promise<HelperResult | undefined>((resolve) => {
    const child = spawn(`docker-credential-${helper}`, ["get"], {
      stdio: ["pipe", "pipe", "ignore"],
    });
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.on("error", () => resolve(undefined));
    child.on("close", (code) => {
      if (code !== 0) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(stdout) as HelperResult);
      } catch {
        resolve(undefined);
      }
    });
    child.stdin.end(`${serverURL}\n`);
  });
