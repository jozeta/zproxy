import { test } from "node:test";
import assert from "node:assert/strict";
import { tryParseJson, prettyPrintJson, minifyJson, looksLikeJson } from "../src/parsers/json.js";

test("tryParseJson reports success and the parsed value", () => {
  const result = tryParseJson('{"a":1}');
  assert.equal(result.ok, true);
  assert.deepEqual(result.value, { a: 1 });
});

test("tryParseJson reports failure with a message, never throws", () => {
  const result = tryParseJson("{not json");
  assert.equal(result.ok, false);
  assert.equal(typeof result.error, "string");
});

test("prettyPrintJson reformats valid JSON with indentation", () => {
  assert.equal(prettyPrintJson('{"a":1}'), '{\n  "a": 1\n}');
});

test("prettyPrintJson returns the original text unchanged when invalid", () => {
  assert.equal(prettyPrintJson("not json"), "not json");
});

test("minifyJson collapses whitespace", () => {
  assert.equal(minifyJson('{\n  "a": 1\n}'), '{"a":1}');
});

test("minifyJson returns the original text unchanged when invalid", () => {
  assert.equal(minifyJson("not json"), "not json");
});

test("looksLikeJson trusts an explicit JSON content-type", () => {
  assert.equal(looksLikeJson("anything", "application/json; charset=utf-8"), true);
});

test("looksLikeJson falls back to sniffing braces/brackets", () => {
  assert.equal(looksLikeJson('  {"a":1}'), true);
  assert.equal(looksLikeJson("[1,2,3]"), true);
  assert.equal(looksLikeJson("plain text"), false);
  assert.equal(looksLikeJson(42), false);
});
