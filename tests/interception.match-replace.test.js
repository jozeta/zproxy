import { test } from "node:test";
import assert from "node:assert/strict";
import {
  compileRule,
  applyStringRule,
  applyRulesToUrl,
  applyRulesToHeaders,
  applyRulesToBody,
  urlMatchesFilter,
} from "../src/interception/match-replace.js";

test("compileRule leaves substring rules untouched", () => {
  const rule = { matchType: "contains", match: "a" };
  assert.equal(compileRule(rule).regex, null);
});

test("compileRule compiles a valid regex", () => {
  const compiled = compileRule({ matchType: "regex", match: "a+" });
  assert.ok(compiled.regex instanceof RegExp);
  assert.equal(compiled.regexError, null);
});

test("compileRule reports an error for an invalid regex instead of throwing", () => {
  const compiled = compileRule({ matchType: "regex", match: "(" });
  assert.equal(compiled.regex, null);
  assert.ok(compiled.regexError);
});

test("applyStringRule does substring replace-all", () => {
  const rule = { enabled: true, matchType: "contains", match: "foo", replace: "bar" };
  assert.equal(applyStringRule(rule, "foo foo baz"), "bar bar baz");
});

test("applyStringRule does global regex replace", () => {
  const rule = compileRule({ enabled: true, matchType: "regex", match: "\\d+", replace: "#" });
  assert.equal(applyStringRule(rule, "a1 b22 c333"), "a# b# c#");
});

test("applyStringRule is a no-op when disabled, non-string input, or no match text", () => {
  const rule = { enabled: false, matchType: "contains", match: "foo", replace: "bar" };
  assert.equal(applyStringRule(rule, "foo"), "foo");
  assert.equal(applyStringRule({ enabled: true, matchType: "contains", match: "foo" }, null), null);
  assert.equal(applyStringRule({ enabled: true, matchType: "contains", match: "" }, "foo"), "foo");
});

test("applyStringRule with an invalid regex returns input unchanged rather than throwing", () => {
  const rule = compileRule({ enabled: true, matchType: "regex", match: "(", replace: "x" });
  assert.equal(applyStringRule(rule, "abc"), "abc");
});

test("applyRulesToUrl only applies enabled url-scoped rules matching scope", () => {
  const rules = [
    { enabled: true, scope: "request", location: "url", matchType: "contains", match: "http://", replace: "https://" },
    { enabled: false, scope: "request", location: "url", matchType: "contains", match: "example", replace: "nope" },
    { enabled: true, scope: "response", location: "url", matchType: "contains", match: "https://", replace: "nope" },
  ];
  assert.equal(applyRulesToUrl(rules, "http://example.com", "request"), "https://example.com");
});

test("applyRulesToHeaders rewrites only the named header, leaving others alone, without mutating the input array", () => {
  const original = [
    { name: "Authorization", value: "Bearer old" },
    { name: "Accept", value: "*/*" },
  ];
  const rules = [
    { enabled: true, scope: "request", location: "header", headerName: "Authorization", matchType: "contains", match: "old", replace: "new" },
  ];
  const result = applyRulesToHeaders(rules, original, "request");
  assert.deepEqual(result, [
    { name: "Authorization", value: "Bearer new" },
    { name: "Accept", value: "*/*" },
  ]);
  assert.equal(original[0].value, "Bearer old");
});

test("applyRulesToHeaders with no headerName applies to every header's value", () => {
  const rules = [{ enabled: true, scope: "request", location: "header", headerName: "", matchType: "contains", match: "a", replace: "X" }];
  const result = applyRulesToHeaders(rules, [{ name: "H1", value: "abc" }, { name: "H2", value: "zzz" }], "request");
  assert.deepEqual(result, [{ name: "H1", value: "Xbc" }, { name: "H2", value: "zzz" }]);
});

test("applyRulesToBody applies body-scoped rules and passes through non-strings", () => {
  const rules = [{ enabled: true, scope: "response", location: "body", matchType: "contains", match: "secret", replace: "REDACTED" }];
  assert.equal(applyRulesToBody(rules, "token=secret", "response"), "token=REDACTED");
  assert.equal(applyRulesToBody(rules, null, "response"), null);
});

test("urlMatchesFilter supports plain substrings, /regex/ syntax, and an empty filter matching everything", () => {
  assert.equal(urlMatchesFilter("https://example.com/api", ""), true);
  assert.equal(urlMatchesFilter("https://example.com/api", "example.com"), true);
  assert.equal(urlMatchesFilter("https://example.com/api", "other.com"), false);
  assert.equal(urlMatchesFilter("https://example.com/api/v2", "/\\/v\\d+/"), true);
  assert.equal(urlMatchesFilter("https://example.com/api", "/[/"), false);
});
