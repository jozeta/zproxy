import { test } from "node:test";
import assert from "node:assert/strict";
import { compileSearchQuery, extractMatches, headersAsText, searchResponse } from "../src/intruder/search.js";

test("compileSearchQuery returns null for empty/whitespace queries", () => {
  assert.equal(compileSearchQuery(""), null);
  assert.equal(compileSearchQuery("   "), null);
  assert.equal(compileSearchQuery(undefined), null);
});

test("a plain literal query (no wildcards) extracts the matched substring itself", () => {
  const compiled = compileSearchQuery("Invalid password");
  assert.equal(compiled.hasWildcard, false);
  assert.deepEqual(extractMatches("Error: Invalid password given", compiled), ["Invalid password"]);
  assert.deepEqual(extractMatches("Error: nothing wrong here", compiled), []);
});

test("string-wildcard-string extracts just the wildcard span, using both sides as anchors", () => {
  const compiled = compileSearchQuery("<h1>*</h1>");
  assert.equal(compiled.hasWildcard, true);
  assert.deepEqual(extractMatches("<h1>some text</h1>", compiled), ["some text"]);
});

test("* is non-greedy — stops at the nearest following anchor", () => {
  const compiled = compileSearchQuery("<b>*</b>");
  assert.deepEqual(extractMatches("<b>one</b> middle <b>two</b>", compiled), ["one", "two"]);
});

test("? matches exactly one character, and a run of ?? matches exactly that many", () => {
  const compiled = compileSearchQuery("id=??");
  // The one-digit id sits at the very end so there's no second character
  // after it — `?` matches any character, whitespace included.
  assert.deepEqual(extractMatches("id=42 id=99 id=7", compiled), ["42", "99"]);
});

test("a query with more than one wildcard run extracts each span, joined with a separator", () => {
  const compiled = compileSearchQuery("name=*&age=*&");
  assert.deepEqual(extractMatches("name=bob&age=30&done", compiled), ["bob | 30"]);
});

test("special regex characters in the literal portions are treated literally, not as regex syntax", () => {
  const compiled = compileSearchQuery("total: $*.00");
  assert.deepEqual(extractMatches("total: $19.00", compiled), ["19"]);
});

test("a bare wildcard (which can match zero-length text at every position) does not loop forever", () => {
  const compiled = compileSearchQuery("*");
  assert.deepEqual(extractMatches("ab", compiled), ["", "", ""]);
});

test("headersAsText renders one 'Name: value' line per header", () => {
  assert.equal(
    headersAsText([
      { name: "Set-Cookie", value: "session=abc123; Path=/" },
      { name: "Content-Type", value: "text/html" },
    ]),
    "Set-Cookie: session=abc123; Path=/\nContent-Type: text/html"
  );
});

test("searchResponse('first') scans body before headers and stops at the first hit", () => {
  const response = { body: "<h1>Body Title</h1>", headers: [{ name: "X-Title", value: "Header Title" }] };
  const compiled = compileSearchQuery("<h1>*</h1>");
  assert.deepEqual(searchResponse(response, compiled, "first"), ["Body Title"]);
});

test("searchResponse('first') falls through to headers when the body has no match", () => {
  const response = { body: "no match here", headers: [{ name: "Set-Cookie", value: "session=abc123; Path=/" }] };
  const compiled = compileSearchQuery("session=*;");
  assert.deepEqual(searchResponse(response, compiled, "first"), ["abc123"]);
});

test("searchResponse('all') collects every match across body and headers", () => {
  const response = {
    body: "<li>one</li><li>two</li>",
    headers: [{ name: "X-Extra", value: "<li>three</li>" }],
  };
  const compiled = compileSearchQuery("<li>*</li>");
  assert.deepEqual(searchResponse(response, compiled, "all"), ["one", "two", "three"]);
});

test("searchResponse returns [] for a missing response or an empty query", () => {
  assert.deepEqual(searchResponse(null, compileSearchQuery("x")), []);
  assert.deepEqual(searchResponse({ body: "x" }, compileSearchQuery("")), []);
});
