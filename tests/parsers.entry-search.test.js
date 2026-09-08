import { test } from "node:test";
import assert from "node:assert/strict";
import { compileEntryQuery, searchableTexts, matchesEntryQuery } from "../src/parsers/entry-search.js";

function entry(overrides = {}) {
  return {
    request: { url: "https://example.com/login", method: "POST", headers: [{ name: "X-Foo", value: "bar" }], body: "user=bob" },
    response: { statusCode: 200, headers: [{ name: "Set-Cookie", value: "session=abc123" }], body: null },
    ...overrides,
  };
}

test("compileEntryQuery returns null for an empty query", () => {
  assert.equal(compileEntryQuery("", false), null);
  assert.equal(compileEntryQuery(undefined, false), null);
});

test("compileEntryQuery returns null (not a throw) for an invalid regex", () => {
  assert.equal(compileEntryQuery("(unclosed", true), null);
});

test("plain mode matches case-insensitively as a substring", () => {
  const matcher = compileEntryQuery("LOGIN", false);
  assert.equal(matcher.test("https://example.com/login"), true);
  assert.equal(matcher.test("https://example.com/logout"), false);
});

test("regex mode compiles and matches", () => {
  const matcher = compileEntryQuery("^https://.*/login$", true);
  assert.equal(matcher.test("https://example.com/login"), true);
  assert.equal(matcher.test("https://example.com/login/x"), false);
});

test("searchableTexts includes url/method/status, both header blocks, and both bodies", () => {
  const texts = searchableTexts(entry());
  assert.ok(texts.includes("https://example.com/login"));
  assert.ok(texts.includes("POST"));
  assert.ok(texts.includes("200"));
  assert.ok(texts.includes("X-Foo: bar"));
  assert.ok(texts.includes("Set-Cookie: session=abc123"));
  assert.ok(texts.includes("user=bob"));
});

test("searchableTexts pulls editDiff bodies for edited entries (response.body itself is always null otherwise)", () => {
  const texts = searchableTexts(
    entry({ editDiff: { kind: "response", original: { body: "old body" }, edited: { body: "new body" } } })
  );
  assert.ok(texts.includes("old body"));
  assert.ok(texts.includes("new body"));
});

test("matchesEntryQuery: no query matches everything", () => {
  assert.equal(matchesEntryQuery(entry(), "", false), true);
});

test("matchesEntryQuery finds a hit in a response header (not just url/method/status)", () => {
  assert.equal(matchesEntryQuery(entry(), "session=abc123", false), true);
});

test("matchesEntryQuery finds a hit in a request body", () => {
  assert.equal(matchesEntryQuery(entry(), "user=bob", false), true);
});

test("matchesEntryQuery returns false when nothing matches", () => {
  assert.equal(matchesEntryQuery(entry(), "nope-not-here", false), false);
});

test("searchableTexts and matchesEntryQuery include a user-added comment", () => {
  const e = entry({ comment: "revisit this — looks like an IDOR" });
  assert.ok(searchableTexts(e).includes("revisit this — looks like an IDOR"));
  assert.equal(matchesEntryQuery(e, "IDOR", false), true);
});

test("matchesEntryQuery in regex mode", () => {
  assert.equal(matchesEntryQuery(entry(), "user=\\w+", true), true);
  assert.equal(matchesEntryQuery(entry(), "user=\\d+", true), false);
});
