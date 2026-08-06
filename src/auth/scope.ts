/**
 * Registry authorization scopes and their normalization, matching the behavior
 * of oras-go's `CleanScopes`.
 *
 * A scope has the form `resourceType:resourceName:action[,action...]`, e.g.
 * `repository:library/ubuntu:pull,push`.
 */

export const ACTION_PULL = "pull";
export const ACTION_PUSH = "push";
export const ACTION_DELETE = "delete";

/** Normalizes a set of actions: dedup, sort, and collapse to `*` if present. */
function cleanActions(actions: string[]): string[] {
  const set = new Set<string>();
  for (const action of actions) {
    if (action.length > 0) {
      set.add(action);
    }
  }
  if (set.has("*")) {
    return ["*"];
  }
  return [...set].sort();
}

/** Builds a repository scope string for the given actions. */
export function scopeRepository(repository: string, actions: string[]): string {
  return `repository:${repository}:${cleanActions(actions).join(",")}`;
}

/**
 * Cleans and merges a list of scopes:
 *  - actions within the same resource are merged, deduplicated, and sorted;
 *  - a `*` action collapses that resource's actions to `["*"]`;
 *  - scopes with no actions are dropped;
 *  - unrecognized scopes are passed through unchanged;
 *  - the result is sorted and deduplicated.
 */
export function cleanScopes(scopes: string[]): string[] {
  const resources = new Map<string, Map<string, Set<string>>>();
  const result = new Set<string>();

  for (const scope of scopes) {
    const firstColon = scope.indexOf(":");
    if (firstColon < 0) {
      result.add(scope);
      continue;
    }
    const resourceType = scope.slice(0, firstColon);
    const rest = scope.slice(firstColon + 1);
    const lastColon = rest.lastIndexOf(":");
    if (lastColon < 0) {
      result.add(scope);
      continue;
    }
    const resourceName = rest.slice(0, lastColon);
    const actions = rest.slice(lastColon + 1).split(",").filter((a) => a.length > 0);
    if (actions.length === 0) {
      continue;
    }
    let names = resources.get(resourceType);
    if (!names) {
      names = new Map();
      resources.set(resourceType, names);
    }
    let actionSet = names.get(resourceName);
    if (!actionSet) {
      actionSet = new Set();
      names.set(resourceName, actionSet);
    }
    for (const action of actions) {
      actionSet.add(action);
    }
  }

  for (const [resourceType, names] of resources) {
    for (const [resourceName, actionSet] of names) {
      const actions = cleanActions([...actionSet]);
      result.add(`${resourceType}:${resourceName}:${actions.join(",")}`);
    }
  }

  return [...result].sort();
}

/** Merges two scope lists into a single cleaned list. */
export function mergeScopes(a: readonly string[], b: readonly string[]): string[] {
  return cleanScopes([...a, ...b]);
}

/**
 * Derives a stable cache key from a set of scopes (cleaned, space-joined). An
 * empty scope list yields the empty string.
 */
export function scopeKey(scopes: readonly string[]): string {
  return cleanScopes([...scopes]).join(" ");
}

/** Splits the space-separated `scope` parameter of a challenge into scopes. */
export function parseScopeParam(param: string | undefined): string[] {
  if (!param) {
    return [];
  }
  return param.split(" ").filter((s) => s.length > 0);
}
