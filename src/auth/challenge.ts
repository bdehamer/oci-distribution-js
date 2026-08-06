/**
 * Parsing of the `WWW-Authenticate` challenge header per RFC 7235, restricted to
 * the `Basic` and `Bearer` schemes used by container registries.
 */

/** The authentication scheme named by a challenge. */
export type Scheme = "basic" | "bearer" | "unknown";

/** A parsed authentication challenge. */
export interface Challenge {
  scheme: Scheme;
  /** `auth-param` values, with lowercased keys (e.g. `realm`, `service`, `scope`, `error`). */
  params: Record<string, string>;
}

const TAB = 9;
const SPACE = 32;
const DQUOTE = 34;
const COMMA = 44;
const EQUALS = 61;
const BACKSLASH = 92;

// Additional `tchar` characters beyond ALPHA / DIGIT (RFC 7230 §3.2.6).
const TCHAR_SPECIAL = new Set<number>(
  "!#$%&'*+-.^_`|~".split("").map((c) => c.charCodeAt(0)),
);

function isTokenCode(c: number): boolean {
  return (
    (c >= 65 && c <= 90) || // A-Z
    (c >= 97 && c <= 122) || // a-z
    (c >= 48 && c <= 57) || // 0-9
    TCHAR_SPECIAL.has(c)
  );
}

function isSpace(c: number): boolean {
  return c === SPACE || c === TAB;
}

/**
 * Parses a `WWW-Authenticate` header value. Only the first challenge is
 * considered. Parameters are parsed for the `Bearer` scheme; for other schemes
 * an empty parameter map is returned.
 */
export function parseChallenge(header: string): Challenge {
  let i = 0;
  const n = header.length;

  const skipSpace = (): void => {
    while (i < n && isSpace(header.charCodeAt(i))) {
      i++;
    }
  };

  const readToken = (): string => {
    const start = i;
    while (i < n && isTokenCode(header.charCodeAt(i))) {
      i++;
    }
    return header.slice(start, i);
  };

  skipSpace();
  const schemeToken = readToken();
  const scheme = parseScheme(schemeToken);
  const params: Record<string, string> = {};

  if (scheme !== "bearer") {
    return { scheme, params };
  }

  while (i < n) {
    skipSpace();
    const key = readToken();
    if (key.length === 0) {
      break;
    }
    skipSpace();
    if (i >= n || header.charCodeAt(i) !== EQUALS) {
      // A bare token with no `=` is the start of a new challenge/scheme; stop.
      break;
    }
    i++; // consume '='
    skipSpace();

    let value: string;
    if (i < n && header.charCodeAt(i) === DQUOTE) {
      value = readQuoted();
    } else {
      value = readToken();
    }
    params[key.toLowerCase()] = value;

    skipSpace();
    if (i < n && header.charCodeAt(i) === COMMA) {
      i++; // consume ',' and continue to the next param
    } else {
      break;
    }
  }

  return { scheme, params };

  function readQuoted(): string {
    i++; // consume opening quote
    let out = "";
    while (i < n) {
      const c = header.charCodeAt(i);
      if (c === BACKSLASH && i + 1 < n) {
        out += header.charAt(i + 1);
        i += 2;
        continue;
      }
      if (c === DQUOTE) {
        i++; // consume closing quote
        break;
      }
      out += header.charAt(i);
      i++;
    }
    return out;
  }
}

function parseScheme(token: string): Scheme {
  const lower = token.toLowerCase();
  if (lower === "basic") {
    return "basic";
  }
  if (lower === "bearer") {
    return "bearer";
  }
  return "unknown";
}
