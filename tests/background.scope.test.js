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

test("parseScopePattern splits scheme, host, port, and path — all but host optional", async () => {
  const { parseScopePattern } = await import("../src/background/scope.js");
  assert.deepEqual(parseScopePattern("example.com"), { scheme: null, host: "example.com", port: null, path: null });
  assert.deepEqual(parseScopePattern("HTTPS://*.Example.com:8443/API/*"), { scheme: "https", host: "*.example.com", port: "8443", path: "/api/*" });
  assert.deepEqual(parseScopePattern("[::1]:8080/x"), { scheme: null, host: "[::1]", port: "8080", path: "/x" });
});

test("a path pattern matches only URLs whose path starts with it", () => {
  const scope = { enabled: true, include: ["example.com/api/"], exclude: [] };
  assert.equal(isInScope("https://example.com/api/users?id=1", scope), true);
  assert.equal(isInScope("https://example.com/apifoo", scope), false);
  assert.equal(isInScope("https://example.com/", scope), false);
});

test("a path pattern's * is a wildcard within the path", () => {
  const scope = { enabled: true, include: ["example.com/v*/admin"], exclude: [] };
  assert.equal(isInScope("https://example.com/v2/admin/panel", scope), true);
  assert.equal(isInScope("https://example.com/v2/public", scope), false);
});

test("scheme and port in a pattern are enforced, with default ports filled in", () => {
  const scope = { enabled: true, include: ["https://example.com:443", "http://localhost:8787"], exclude: [] };
  assert.equal(isInScope("https://example.com/", scope), true);
  assert.equal(isInScope("http://example.com/", scope), false);
  assert.equal(isInScope("https://example.com:8443/", scope), false);
  assert.equal(isInScope("http://localhost:8787/x", scope), true);
  assert.equal(isInScope("http://localhost:9999/x", scope), false);
});

test("a path-restricted Exclude carves a path out of an otherwise in-scope host", () => {
  const scope = { enabled: true, include: ["example.com"], exclude: ["example.com/logout"] };
  assert.equal(isInScope("https://example.com/account", scope), true);
  assert.equal(isInScope("https://example.com/logout?next=/", scope), false);
});

test("addHostToScope still adds the plain host when only a path-restricted pattern mentions it", () => {
  const scope = { enabled: true, include: ["example.com/api/"], exclude: [] };
  assert.deepEqual(addHostToScope(scope, "example.com").include, ["example.com/api/", "example.com"]);
});
