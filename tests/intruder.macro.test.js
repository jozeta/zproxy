import { test } from "node:test";
import assert from "node:assert/strict";
import { containsMacroToken, usesMacroToken, applyMacroValue, extractMacroValue, defaultMacro, MACRO_TOKEN } from "../src/intruder/macro.js";

test("MACRO_TOKEN is the literal placeholder", () => {
  assert.equal(MACRO_TOKEN, "{{macro}}");
});

test("containsMacroToken / usesMacroToken detect the placeholder across fields", () => {
  assert.equal(containsMacroToken("no token here"), false);
  assert.equal(containsMacroToken("X-CSRF: {{macro}}"), true);
  assert.equal(usesMacroToken({ url: "https://x/?t={{macro}}", headersText: "", body: "" }), true);
  assert.equal(usesMacroToken({ url: "https://x/", headersText: "X-CSRF: {{macro}}", body: "" }), true);
  assert.equal(usesMacroToken({ url: "https://x/", headersText: "", body: "" }), false);
});

test("applyMacroValue substitutes every occurrence across url/headersText/body", () => {
  const fields = { url: "https://x/?t={{macro}}", headersText: "X-CSRF: {{macro}}", body: "csrf={{macro}}&x=1" };
  const result = applyMacroValue(fields, "TOKEN123");
  assert.equal(result.url, "https://x/?t=TOKEN123");
  assert.equal(result.headersText, "X-CSRF: TOKEN123");
  assert.equal(result.body, "csrf=TOKEN123&x=1");
});

test("applyMacroValue substitutes multiple occurrences in the same field", () => {
  const result = applyMacroValue({ url: "", headersText: "", body: "a={{macro}}&b={{macro}}" }, "V");
  assert.equal(result.body, "a=V&b=V");
});

test("applyMacroValue treats a missing/null value as empty substitution rather than the string 'null'", () => {
  const result = applyMacroValue({ url: "t={{macro}}", headersText: "", body: "" }, null);
  assert.equal(result.url, "t=");
});

test("extractMacroValue uses the wildcard query against the response and returns the first match", () => {
  const response = { body: '<input name="csrf" value="abc123">', headers: [] };
  assert.equal(extractMacroValue(response, 'name="csrf" value="*">'), "abc123");
});

test("extractMacroValue returns null for an empty query or no match", () => {
  const response = { body: "nothing useful here", headers: [] };
  assert.equal(extractMacroValue(response, ""), null);
  assert.equal(extractMacroValue(response, "won't-match-*-anything-weird"), null);
});

test("defaultMacro starts disabled with empty fields", () => {
  const macro = defaultMacro();
  assert.equal(macro.enabled, false);
  assert.equal(macro.method, "GET");
  assert.equal(macro.extractQuery, "");
});
