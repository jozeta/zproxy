import { test } from "node:test";
import assert from "node:assert/strict";
import { hostMatchesPattern, isInScope, addHostToScope, DEFAULT_SCOPE } from "../src/background/scope.js";

test("hostMatchesPattern matches exact hosts case-insensitively", () => {
  assert.equal(hostMatchesPattern("Example.com", "example.com"), true);
  assert.equal(hostMatchesPattern("example.com", "other.com"), false);
});

test("hostMatchesPattern supports *.domain wildcards, including the bare apex", () => {
  assert.equal(hostMatchesPattern("api.example.com", "*.example.com"), true);
  assert.equal(hostMatchesPattern("example.com", "*.example.com"), true);
  assert.equal(hostMatchesPattern("evilexample.com", "*.example.com"), false);
});

test("hostMatchesPattern supports a general * wildcard", () => {
  assert.equal(hostMatchesPattern("dev-api.example.com", "dev-*.example.com"), true);
});

test("hostMatchesPattern rejects an empty pattern", () => {
  assert.equal(hostMatchesPattern("example.com", ""), false);
});

test("DEFAULT_SCOPE is disabled with empty lists (fail closed)", () => {
  assert.equal(DEFAULT_SCOPE.enabled, false);
  assert.deepEqual(DEFAULT_SCOPE.include, []);
  assert.deepEqual(DEFAULT_SCOPE.exclude, []);
});

test("isInScope captures nothing when scope is disabled, even with matching include patterns", () => {
  const scope = { enabled: false, include: ["example.com"], exclude: [] };
  assert.equal(isInScope("https://example.com/", scope), false);
});

test("isInScope captures nothing when include is empty, even when enabled", () => {
  const scope = { enabled: true, include: [], exclude: [] };
  assert.equal(isInScope("https://example.com/", scope), false);
});

test("isInScope captures matching hosts when enabled with a non-empty include list", () => {
  const scope = { enabled: true, include: ["*.example.com"], exclude: [] };
  assert.equal(isInScope("https://api.example.com/x", scope), true);
  assert.equal(isInScope("https://other.com/x", scope), false);
});

test("isInScope lets exclude override include", () => {
  const scope = { enabled: true, include: ["*.example.com"], exclude: ["auth.example.com"] };
  assert.equal(isInScope("https://auth.example.com/login", scope), false);
  assert.equal(isInScope("https://api.example.com/x", scope), true);
});

test("isInScope fails closed on an unparseable URL", () => {
  const scope = { enabled: true, include: ["*"], exclude: [] };
  assert.equal(isInScope("not a url", scope), false);
});

test("isInScope fails closed on a missing/null scope object", () => {
  assert.equal(isInScope("https://example.com/", null), false);
});

test("isInScope ignores a non-default port when matching a plain-hostname pattern", () => {
  // Regression: isInScope used to match against URL.host (hostname:port),
  // so "localhost" would never match "localhost:8787" — silently failing
  // every local dev-server target (including examples/test-lab, on :8787).
  const scope = { enabled: true, include: ["localhost"], exclude: [] };
  assert.equal(isInScope("http://localhost:8787/api/flags", scope), true);
  assert.equal(isInScope("http://localhost/api/flags", scope), true);
});

test("isInScope ignores a non-default port when matching a *.domain pattern", () => {
  const scope = { enabled: true, include: ["*.example.com"], exclude: [] };
  assert.equal(isInScope("https://api.example.com:8443/x", scope), true);
});

test("addHostToScope enables scope and adds the host when starting from nothing", () => {
  const next = addHostToScope(DEFAULT_SCOPE, "localhost");
  assert.equal(next.enabled, true);
  assert.deepEqual(next.include, ["localhost"]);
  assert.deepEqual(next.exclude, []);
});

test("addHostToScope is idempotent when the host is already covered exactly", () => {
  const scope = { enabled: true, include: ["localhost"], exclude: [] };
  const next = addHostToScope(scope, "localhost");
  assert.deepEqual(next.include, ["localhost"]);
});

test("addHostToScope does not add a redundant entry when a wildcard already covers the host", () => {
  const scope = { enabled: false, include: ["*.example.com"], exclude: [] };
  const next = addHostToScope(scope, "api.example.com");
  assert.equal(next.enabled, true);
  assert.deepEqual(next.include, ["*.example.com"]);
});

test("addHostToScope preserves existing Exclude entries (which still take precedence via isInScope)", () => {
  const scope = { enabled: true, include: [], exclude: ["blocked.example.com"] };
  const next = addHostToScope(scope, "blocked.example.com");
  assert.deepEqual(next.exclude, ["blocked.example.com"]);
  assert.equal(isInScope("https://blocked.example.com/", next), false);
});

test("addHostToScope does not mutate the scope object it was given", () => {
  const scope = { enabled: false, include: ["a.com"], exclude: ["b.com"] };
  addHostToScope(scope, "c.com");
  assert.deepEqual(scope, { enabled: false, include: ["a.com"], exclude: ["b.com"] });
});
