import { test } from "node:test";
import assert from "node:assert/strict";
import { textToBase64, base64ToText, formatBytes, truncate } from "../src/utils/bytes.js";

test("textToBase64/base64ToText round-trip ASCII", () => {
  const text = "GET / HTTP/1.1";
  assert.equal(base64ToText(textToBase64(text)), text);
});

test("textToBase64/base64ToText round-trip multi-byte UTF-8 (the case naive btoa(text) corrupts)", () => {
  const text = '{"name":"héllo 世界 🚀"}';
  assert.equal(base64ToText(textToBase64(text)), text);
});

test("textToBase64/base64ToText round-trip an empty string", () => {
  assert.equal(base64ToText(textToBase64("")), "");
});

test("formatBytes scales through B/KB/MB/GB", () => {
  assert.equal(formatBytes(500), "500 B");
  assert.equal(formatBytes(2048), "2.0 KB");
  assert.equal(formatBytes(5 * 1024 * 1024), "5 MB");
});

test("formatBytes handles null/NaN without throwing", () => {
  assert.equal(formatBytes(null), "—");
  assert.equal(formatBytes(NaN), "—");
});

test("truncate leaves short strings untouched and adds an ellipsis to long ones", () => {
  assert.equal(truncate("short", 10), "short");
  assert.equal(truncate("this is long", 4), "this…");
});

test("truncate passes through non-strings unchanged", () => {
  assert.equal(truncate(null, 4), null);
});
