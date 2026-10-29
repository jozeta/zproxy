import { test } from "node:test";
import assert from "node:assert/strict";
import { scopePatternToDnrDomain, scopeToDnrDomains, toDnrRule } from "../src/background/dnr-rules.js";

const headerRule = {
  enabled: true,
  engine: "static",
  scope: "request",
  location: "header",
  headerName: "Authorization",
  urlFilter: "",
  staticAction: "set",
  staticValue: "Bearer test-token",
};

test("scope patterns map to DNR domains; mid-pattern wildcards can't be expressed", () => {
  assert.equal(scopePatternToDnrDomain("*.Example.com"), "example.com");
  assert.equal(scopePatternToDnrDomain("localhost"), "localhost");
  assert.equal(scopePatternToDnrDomain("api-*.example.com"), null);
  assert.equal(scopePatternToDnrDomain("*"), null);
  assert.equal(scopePatternToDnrDomain(""), null);
});

test("a disabled, empty, or wholly-unexpressible scope yields no domains (fails closed)", () => {
  assert.equal(scopeToDnrDomains(null), null);
  assert.equal(scopeToDnrDomains({ enabled: false, include: ["example.com"], exclude: [] }), null);
  assert.equal(scopeToDnrDomains({ enabled: true, include: [], exclude: [] }), null);
  assert.equal(scopeToDnrDomains({ enabled: true, include: ["a*.example.com"], exclude: [] }), null);
});

test("includes and excludes become requestDomains / excludedRequestDomains, deduplicated", () => {
  const domains = scopeToDnrDomains({ enabled: true, include: ["*.example.com", "example.com", "lab.test"], exclude: ["admin.example.com"] });
  assert.deepEqual(domains, { requestDomains: ["example.com", "lab.test"], excludedRequestDomains: ["admin.example.com"] });
});

test("a static rule is never compiled without a scope — it would apply to every site in the browser", () => {
  assert.equal(toDnrRule(headerRule, 0, null), null);
});

test("a static rule's condition is restricted to the in-scope domains", () => {
  const domains = scopeToDnrDomains({ enabled: true, include: ["lab.test"], exclude: [] });
  const rule = toDnrRule(headerRule, 3, domains);
  assert.equal(rule.id, 10003);
  assert.deepEqual(rule.condition.requestDomains, ["lab.test"]);
  assert.deepEqual(rule.action.requestHeaders, [{ header: "Authorization", operation: "set", value: "Bearer test-token" }]);
});

test("a URL filter is kept alongside the scope restriction", () => {
  const domains = scopeToDnrDomains({ enabled: true, include: ["lab.test"], exclude: [] });
  const rule = toDnrRule({ ...headerRule, urlFilter: "api/users" }, 0, domains);
  assert.equal(rule.condition.urlFilter, "*api/users*");
  assert.deepEqual(rule.condition.requestDomains, ["lab.test"]);
});

test("scheme/port/path-restricted patterns are never widened to a whole domain for static rules", () => {
  assert.equal(scopePatternToDnrDomain("example.com/api/"), null);
  assert.equal(scopePatternToDnrDomain("https://example.com"), null);
  assert.equal(scopePatternToDnrDomain("example.com:8443"), null);
  // Only a path-restricted include -> no static rules at all (fails closed).
  assert.equal(scopeToDnrDomains({ enabled: true, include: ["example.com/api/"], exclude: [] }), null);
  // A path-restricted exclude is ignored rather than excluding the whole target host.
  assert.deepEqual(scopeToDnrDomains({ enabled: true, include: ["example.com"], exclude: ["example.com/logout"] }), {
    requestDomains: ["example.com"],
  });
});
