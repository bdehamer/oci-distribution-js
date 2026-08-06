import { test } from "node:test";
import assert from "node:assert/strict";
import {
  scopeRepository,
  cleanScopes,
  mergeScopes,
  scopeKey,
  parseScopeParam,
} from "../src/auth/scope.ts";

test("scopeRepository builds and sorts actions", () => {
  assert.equal(scopeRepository("library/ubuntu", ["push", "pull"]), "repository:library/ubuntu:pull,push");
});

test("cleanScopes merges actions for the same resource", () => {
  assert.deepEqual(cleanScopes(["repository:a:pull", "repository:a:push"]), ["repository:a:pull,push"]);
});

test("cleanScopes collapses a wildcard action", () => {
  assert.deepEqual(cleanScopes(["repository:a:pull,*"]), ["repository:a:*"]);
});

test("cleanScopes drops empty-action scopes and dedups", () => {
  assert.deepEqual(cleanScopes(["repository:a:", "repository:a:pull", "repository:a:pull"]), [
    "repository:a:pull",
  ]);
});

test("cleanScopes passes through and sorts unrecognized scopes", () => {
  assert.deepEqual(cleanScopes(["registry:catalog:*", "weird"]).sort(), ["registry:catalog:*", "weird"]);
});

test("mergeScopes and scopeKey", () => {
  assert.deepEqual(mergeScopes(["repository:a:pull"], ["repository:a:push"]), ["repository:a:pull,push"]);
  assert.equal(scopeKey(["repository:b:pull", "repository:a:pull"]), "repository:a:pull repository:b:pull");
  assert.equal(scopeKey([]), "");
});

test("parseScopeParam splits on spaces", () => {
  assert.deepEqual(parseScopeParam("repository:a:pull repository:b:push"), [
    "repository:a:pull",
    "repository:b:push",
  ]);
  assert.deepEqual(parseScopeParam(undefined), []);
});
