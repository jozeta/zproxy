import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultInterceptRule, shouldPauseForRules } from "../src/interception/intercept-rules.js";

function rule(overrides) {
  return { ...defaultInterceptRule(), ...overrides };
}

test("defaultInterceptRule starts enabled, matching URL-contains-empty", () => {
  const r = defaultInterceptRule();
  assert.equal(r.enabled, true);
  assert.equal(r.field, "url");
  assert.equal(r.operator, "contains");
});

test("no rules at all (or empty array) pauses everything — the pre-existing default", () => {
  const request = { url: "https://example.com/anything", method: "GET", body: "" };
  assert.equal(shouldPauseForRules(request, []), true);
  assert.equal(shouldPauseForRules(request, undefined), true);
});

test("all-disabled rules also pause everything, same as no rules", () => {
  const request = { url: "https://example.com/x", method: "GET", body: "" };
  const rules = [rule({ enabled: false, field: "url", operator: "contains", value: "nope" })];
  assert.equal(shouldPauseForRules(request, rules), true);
});

test("url contains — matches only requests whose URL contains the substring, case-insensitively", () => {
  const rules = [rule({ field: "url", operator: "contains", value: "ADMIN" })];
  assert.equal(shouldPauseForRules({ url: "https://x.com/admin/panel" }, rules), true);
  assert.equal(shouldPauseForRules({ url: "https://x.com/public" }, rules), false);
});

test("method equals — matches only the exact method, case-insensitively", () => {
  const rules = [rule({ field: "method", operator: "equals", value: "post" })];
  assert.equal(shouldPauseForRules({ method: "POST" }, rules), true);
  assert.equal(shouldPauseForRules({ method: "GET" }, rules), false);
});

test("body regex — matches via a real regex against the body", () => {
  const rules = [rule({ field: "body", operator: "regex", value: "pass(word)?=" })];
  assert.equal(shouldPauseForRules({ body: "user=bob&password=hunter2" }, rules), true);
  assert.equal(shouldPauseForRules({ body: "user=bob" }, rules), false);
});

test("an invalid regex never matches, rather than throwing", () => {
  const rules = [rule({ field: "url", operator: "regex", value: "(unclosed" })];
  assert.doesNotThrow(() => shouldPauseForRules({ url: "https://x.com/" }, rules));
  assert.equal(shouldPauseForRules({ url: "https://x.com/" }, rules), false);
});

test("multiple enabled rules use OR semantics — matching any one is enough", () => {
  const rules = [
    rule({ field: "method", operator: "equals", value: "DELETE" }),
    rule({ field: "url", operator: "contains", value: "/api/" }),
  ];
  assert.equal(shouldPauseForRules({ method: "GET", url: "https://x.com/api/users" }, rules), true);
  assert.equal(shouldPauseForRules({ method: "DELETE", url: "https://x.com/home" }, rules), true);
  assert.equal(shouldPauseForRules({ method: "GET", url: "https://x.com/home" }, rules), false);
});

test("a disabled rule is never consulted even if it would otherwise match", () => {
  const rules = [rule({ enabled: false, field: "url", operator: "contains", value: "admin" })];
  assert.equal(shouldPauseForRules({ url: "https://x.com/admin" }, rules), false);
});
