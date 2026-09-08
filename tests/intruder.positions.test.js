import { test } from "node:test";
import assert from "node:assert/strict";
import {
  findPositions,
  countPositions,
  clearMarkers,
  clearAllMarkers,
  applyPayloads,
  buildPreviewSegments,
  autoMarkUrl,
  autoMarkHeaders,
  autoMarkBody,
} from "../src/intruder/positions.js";

test("findPositions finds markers across url, headers, then body, in order", () => {
  const fields = {
    url: "https://example.com/?id=§1§",
    headersText: "X-A: §a§\nX-B: plain",
    body: "field=§b§",
  };
  const positions = findPositions(fields);
  assert.deepEqual(
    positions.map((p) => [p.field, p.originalValue]),
    [
      ["url", "1"],
      ["headersText", "a"],
      ["body", "b"],
    ]
  );
});

test("countPositions matches findPositions length, including zero", () => {
  assert.equal(countPositions({ url: "x", headersText: "", body: "" }), 0);
  assert.equal(countPositions({ url: "§a§§b§", headersText: "", body: "" }), 2);
});

test("clearMarkers strips all § characters", () => {
  assert.equal(clearMarkers("a§b§c"), "abc");
  assert.equal(clearMarkers(""), "");
  assert.equal(clearMarkers(undefined), "");
});

test("clearAllMarkers applies to all three fields", () => {
  const result = clearAllMarkers({ url: "§u§", headersText: "§h§", body: "§b§" });
  assert.deepEqual(result, { url: "u", headersText: "h", body: "b" });
});

test("applyPayloads substitutes a payload per position, falling back to the original value for null", () => {
  const fields = { url: "https://example.com/?id=§1§&name=§bob§", headersText: "X: §a§", body: "" };
  // 3 positions: url id, url name, header X
  const result = applyPayloads(fields, ["PAYLOAD", null, "HDR"]);
  assert.equal(result.url, "https://example.com/?id=PAYLOAD&name=bob");
  assert.equal(result.headersText, "X: HDR");
});

test("applyPayloads with all-null tuple reconstructs the original unmarked request", () => {
  const fields = { url: "https://example.com/?id=§1§", headersText: "X: §a§", body: "body §c§ text" };
  const result = applyPayloads(fields, [null, null, null]);
  assert.equal(result.url, "https://example.com/?id=1");
  assert.equal(result.headersText, "X: a");
  assert.equal(result.body, "body c text");
});

test("applyPayloads handles multiple markers within the same field independently", () => {
  const fields = { url: "", headersText: "", body: "§a§-§b§-§c§" };
  const result = applyPayloads(fields, ["1", "2", "3"]);
  assert.equal(result.body, "1-2-3");
});

test("buildPreviewSegments numbers markers 1-based in canonical order and preserves surrounding text", () => {
  const fields = { url: "u§1§u", headersText: "", body: "" };
  const segments = buildPreviewSegments(fields).filter((s) => !s.isFieldBreak);
  const marker = segments.find((s) => s.isMarker);
  assert.equal(marker.index, 1);
  assert.equal(marker.text, "1");
  assert.ok(segments.some((s) => !s.isMarker && s.text === "u"));
});

test("autoMarkUrl marks every query parameter value and leaves the path/keys untouched", () => {
  assert.equal(autoMarkUrl("https://example.com/path?a=1&b=two"), "https://example.com/path?a=§1§&b=§two§");
});

test("autoMarkUrl is a no-op for a URL with no query string", () => {
  assert.equal(autoMarkUrl("https://example.com/path"), "https://example.com/path");
});

test("autoMarkHeaders marks header values but skips the default skip-list", () => {
  const headersText = "Host: example.com\nAuthorization: secret\nContent-Length: 10";
  const result = autoMarkHeaders(headersText);
  assert.equal(result, "Host: example.com\nAuthorization: §secret§\nContent-Length: 10");
});

test("autoMarkBody marks form-urlencoded parameter values", () => {
  assert.equal(autoMarkBody("user=admin&pass=hunter2"), "user=§admin§&pass=§hunter2§");
});

test("autoMarkBody marks JSON string values but not keys", () => {
  const body = '{"user":"admin","nested":{"role":"guest"}}';
  const result = autoMarkBody(body, "application/json");
  assert.equal(result, '{"user":"§admin§","nested":{"role":"§guest§"}}');
});

test("autoMarkBody leaves an unrecognized body format untouched", () => {
  const body = "<xml><a>1</a></xml>";
  assert.equal(autoMarkBody(body, "application/xml"), body);
});
