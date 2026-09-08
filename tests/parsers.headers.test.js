import { test } from "node:test";
import assert from "node:assert/strict";
import {
  toHeaderList,
  toHeaderMap,
  findHeader,
  getHeaderValue,
  setHeader,
  removeHeader,
  dedupeHeaders,
  withCorrectedFramingHeaders,
  parseHeaderLines,
} from "../src/parsers/headers.js";

test("parseHeaderLines parses 'Name: value' lines, trims whitespace, and skips blank/colon-less lines", () => {
  assert.deepEqual(parseHeaderLines("Content-Type: application/json\n\nX-Foo:  bar  \nnotaheader"), [
    { name: "Content-Type", value: "application/json" },
    { name: "X-Foo", value: "bar" },
  ]);
  assert.deepEqual(parseHeaderLines(""), []);
  assert.deepEqual(parseHeaderLines(undefined), []);
});

test("toHeaderList normalizes an array of {name,value}", () => {
  const list = toHeaderList([{ name: "Content-Type", value: "text/plain" }]);
  assert.deepEqual(list, [{ name: "Content-Type", value: "text/plain" }]);
});

test("toHeaderList normalizes a plain object", () => {
  const list = toHeaderList({ "X-Foo": "bar" });
  assert.deepEqual(list, [{ name: "X-Foo", value: "bar" }]);
});

test("toHeaderList returns [] for null/undefined", () => {
  assert.deepEqual(toHeaderList(null), []);
  assert.deepEqual(toHeaderList(undefined), []);
});

test("toHeaderMap collapses to name->value", () => {
  const map = toHeaderMap([
    { name: "A", value: "1" },
    { name: "B", value: "2" },
  ]);
  assert.deepEqual(map, { A: "1", B: "2" });
});

test("findHeader/getHeaderValue are case-insensitive", () => {
  const list = [{ name: "Content-Type", value: "application/json" }];
  assert.equal(findHeader(list, "content-type").value, "application/json");
  assert.equal(getHeaderValue(list, "CONTENT-TYPE"), "application/json");
  assert.equal(getHeaderValue(list, "missing"), undefined);
});

test("setHeader replaces an existing header case-insensitively without mutating input", () => {
  const original = [{ name: "X-Foo", value: "old" }];
  const updated = setHeader(original, "x-foo", "new");
  assert.deepEqual(original, [{ name: "X-Foo", value: "old" }]);
  assert.deepEqual(updated, [{ name: "x-foo", value: "new" }]);
});

test("setHeader appends when the header doesn't exist", () => {
  const updated = setHeader([], "X-New", "v");
  assert.deepEqual(updated, [{ name: "X-New", value: "v" }]);
});

test("removeHeader is case-insensitive and leaves other headers alone", () => {
  const list = [
    { name: "Authorization", value: "secret" },
    { name: "Accept", value: "*/*" },
  ];
  assert.deepEqual(removeHeader(list, "AUTHORIZATION"), [{ name: "Accept", value: "*/*" }]);
});

test("dedupeHeaders keeps the last value for a repeated name", () => {
  const list = [
    { name: "X-A", value: "first" },
    { name: "x-a", value: "second" },
  ];
  assert.deepEqual(dedupeHeaders(list), [{ name: "x-a", value: "second" }]);
});

test("withCorrectedFramingHeaders strips Content-Length outright — CDP's Fetch.fulfillRequest/continueRequest reject it if set explicitly", () => {
  // Regression, confirmed at runtime: chrome.debugger.sendCommand rejects
  // with {"code":-32602,"message":"Unsafe header: Content-Length"} if this
  // is present in the headers list at all. There's no "correct value" to
  // set — Chrome computes it itself from the actual body being sent — so
  // this must be removed unconditionally, never recomputed and re-added.
  const headers = [
    { name: "Content-Type", value: "application/json" },
    { name: "Content-Length", value: "999" },
  ];
  assert.deepEqual(withCorrectedFramingHeaders(headers), [{ name: "Content-Type", value: "application/json" }]);
});

test("withCorrectedFramingHeaders strips Content-Encoding — a captured body is already decoded by Chrome, so a stale gzip/br header would tell the receiver to re-decode plain text", () => {
  const headers = [
    { name: "Content-Type", value: "text/html" },
    { name: "Content-Encoding", value: "gzip" },
  ];
  assert.deepEqual(withCorrectedFramingHeaders(headers), [{ name: "Content-Type", value: "text/html" }]);
});

test("withCorrectedFramingHeaders strips Transfer-Encoding and the standard hop-by-hop headers", () => {
  const headers = [
    { name: "Content-Type", value: "text/plain" },
    { name: "Transfer-Encoding", value: "chunked" },
    { name: "Connection", value: "keep-alive" },
    { name: "Keep-Alive", value: "timeout=5" },
    { name: "Proxy-Authenticate", value: "Basic" },
    { name: "Proxy-Authorization", value: "Basic xyz" },
    { name: "TE", value: "trailers" },
    { name: "Trailer", value: "X-Checksum" },
    { name: "Upgrade", value: "websocket" },
  ];
  assert.deepEqual(withCorrectedFramingHeaders(headers), [{ name: "Content-Type", value: "text/plain" }]);
});

test("withCorrectedFramingHeaders is case-insensitive and leaves content headers untouched", () => {
  const headers = [
    { name: "content-length", value: "5" },
    { name: "X-Custom", value: "keep-me" },
  ];
  assert.deepEqual(withCorrectedFramingHeaders(headers), [{ name: "X-Custom", value: "keep-me" }]);
});

test("withCorrectedFramingHeaders does not mutate the input header list", () => {
  const headers = [{ name: "Content-Length", value: "999" }];
  withCorrectedFramingHeaders(headers);
  assert.deepEqual(headers, [{ name: "Content-Length", value: "999" }]);
});
