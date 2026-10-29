import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseQueryParams,
  hostAndPath,
  requestToRawHttp,
  responseToRawHttp,
  requestToCurl,
  requestResponseToHarEntry,
  buildHar,
  requestToPostmanItem,
  buildPostmanCollection,
  withBodyUnavailable,
} from "../src/parsers/http.js";

test("parseQueryParams extracts name/value pairs from a URL", () => {
  assert.deepEqual(parseQueryParams("https://example.com/x?a=1&b=two"), [
    { name: "a", value: "1" },
    { name: "b", value: "two" },
  ]);
});

test("parseQueryParams returns [] for a URL with no query or an invalid URL", () => {
  assert.deepEqual(parseQueryParams("https://example.com/x"), []);
  assert.deepEqual(parseQueryParams("not a url"), []);
});

test("hostAndPath splits a URL into host and path+query", () => {
  assert.deepEqual(hostAndPath("https://example.com:8080/a/b?x=1"), { host: "example.com:8080", path: "/a/b?x=1" });
});

test("hostAndPath falls back to {host:'', path: url} for an unparseable URL", () => {
  assert.deepEqual(hostAndPath("not a url"), { host: "", path: "not a url" });
  assert.deepEqual(hostAndPath(""), { host: "", path: "" });
});

test("requestToRawHttp builds a request line, injects Host when missing, and appends the body", () => {
  const raw = requestToRawHttp({
    method: "POST",
    url: "https://api.example.com/login?x=1",
    headers: [{ name: "Content-Type", value: "application/json" }],
    body: '{"u":"a"}',
  });
  const lines = raw.split("\r\n");
  assert.equal(lines[0], "POST /login?x=1 HTTP/1.1");
  assert.ok(lines.includes("Host: api.example.com"));
  assert.ok(lines.includes("Content-Type: application/json"));
  assert.equal(lines.at(-1), '{"u":"a"}');
});

test("requestToRawHttp does not duplicate an explicit Host header", () => {
  const raw = requestToRawHttp({
    method: "GET",
    url: "https://api.example.com/",
    headers: [{ name: "Host", value: "override.example.com" }],
  });
  const hostLines = raw.split("\r\n").filter((l) => l.toLowerCase().startsWith("host:"));
  assert.equal(hostLines.length, 1);
  assert.equal(hostLines[0], "Host: override.example.com");
});

test("responseToRawHttp builds a status line and appends the body", () => {
  const raw = responseToRawHttp({ statusCode: 200, statusText: "OK", headers: [{ name: "Content-Type", value: "text/plain" }], body: "hi" });
  const lines = raw.split("\r\n");
  assert.equal(lines[0], "HTTP/1.1 200 OK");
  assert.equal(lines.at(-1), "hi");
});

test("requestToCurl quotes arguments and skips Content-Length", () => {
  const curl = requestToCurl({
    method: "POST",
    url: "https://example.com/it's",
    headers: [
      { name: "Content-Type", value: "application/json" },
      { name: "Content-Length", value: "9" },
    ],
    body: '{"a":1}',
  });
  assert.match(curl, /^curl /);
  assert.doesNotMatch(curl, /Content-Length/);
  assert.match(curl, /--data-raw/);
});

test("requestResponseToHarEntry produces a HAR-shaped entry with sizes and postData", () => {
  const entry = requestResponseToHarEntry({
    startedAt: 1700000000000,
    durationMs: 42,
    request: { method: "POST", url: "https://example.com/?a=1", headers: [{ name: "Content-Type", value: "application/json" }], body: '{"a":1}' },
    response: { statusCode: 200, statusText: "OK", headers: [{ name: "Content-Type", value: "application/json" }], body: '{"ok":true}', mimeType: "application/json" },
  });
  assert.equal(entry.request.method, "POST");
  assert.equal(entry.request.postData.text, '{"a":1}');
  assert.equal(entry.response.status, 200);
  assert.equal(entry.response.content.text, '{"ok":true}');
  assert.equal(entry.time, 42);
});

test("requestResponseToHarEntry handles a missing response (still in flight / errored)", () => {
  const entry = requestResponseToHarEntry({ request: { method: "GET", url: "https://example.com/", headers: [] }, response: null });
  assert.equal(entry.response.status, 0);
});

test("buildHar wraps entries in a HAR 1.2 log", () => {
  const har = buildHar([{ request: { method: "GET", url: "https://example.com/", headers: [] }, response: null }]);
  assert.equal(har.log.version, "1.2");
  assert.equal(har.log.entries.length, 1);
});

test("withBodyUnavailable marks an entry's response as bodyAvailable: false without mutating the original", () => {
  const entry = { request: { url: "https://x.com/" }, response: { statusCode: 200, body: null } };
  const result = withBodyUnavailable(entry);
  assert.equal(result.response.bodyAvailable, false);
  assert.equal(entry.response.bodyAvailable, undefined);
});

test("withBodyUnavailable is a no-op for an entry with no response", () => {
  const entry = { request: { url: "https://x.com/" }, response: null };
  assert.equal(withBodyUnavailable(entry), entry);
});

test("requestToPostmanItem maps method/headers/url/body, omitting body when there isn't one", () => {
  const item = requestToPostmanItem({
    method: "POST",
    url: "https://example.com/login",
    headers: [{ name: "Content-Type", value: "application/json" }],
    body: '{"a":1}',
  });
  assert.equal(item.request.method, "POST");
  assert.deepEqual(item.request.header, [{ key: "Content-Type", value: "application/json" }]);
  assert.equal(item.request.url, "https://example.com/login");
  assert.deepEqual(item.request.body, { mode: "raw", raw: '{"a":1}' });

  const getItem = requestToPostmanItem({ method: "GET", url: "https://example.com/", headers: [] });
  assert.equal("body" in getItem.request, false);
});

test("buildPostmanCollection wraps entries under a v2.1 schema info block", () => {
  const collection = buildPostmanCollection([{ request: { method: "GET", url: "https://example.com/", headers: [] } }], "My export");
  assert.equal(collection.info.name, "My export");
  assert.match(collection.info.schema, /schema\.getpostman\.com\/json\/collection\/v2\.1\.0/);
  assert.equal(collection.item.length, 1);
});

test("withBodyUnavailable leaves an entry alone once its body was captured (Intercept's Network capture)", () => {
  const entry = { response: { statusCode: 200, headers: [], body: "<html></html>" } };
  assert.equal(withBodyUnavailable(entry), entry);
  assert.equal(withBodyUnavailable({ response: { statusCode: 200, headers: [], body: "" } }).response.bodyAvailable, undefined);
});
