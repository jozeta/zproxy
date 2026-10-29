import { test } from "node:test";
import assert from "node:assert/strict";
import { findEntryForBody, consumeResponseBody, attachResponseBody } from "../src/background/body-tracker.js";
import { shouldCaptureBody } from "../src/interception/network-body-capture.js";

function entry(id, method, url, completedAt, body = null) {
  return { id, startedAt: completedAt - 100, durationMs: 100, request: { method, url }, response: { statusCode: 200, headers: [], body } };
}

test("findEntryForBody picks the newest matching entry without a body, ignoring the URL fragment", () => {
  const history = [entry("a", "GET", "https://x.test/p", 1000), entry("b", "GET", "https://x.test/p#frag", 2000)];
  assert.equal(findEntryForBody(history, "GET", "https://x.test/p", 2050), 1);
});

test("findEntryForBody skips entries that already have a body, other methods, and other URLs", () => {
  const history = [
    entry("a", "GET", "https://x.test/p", 1000),
    entry("b", "GET", "https://x.test/p", 1100, "already"),
    entry("c", "POST", "https://x.test/p", 1150),
    entry("d", "GET", "https://x.test/other", 1200),
  ];
  assert.equal(findEntryForBody(history, "GET", "https://x.test/p", 1300), 0);
});

test("findEntryForBody rejects an entry that completed outside the match window", () => {
  assert.equal(findEntryForBody([entry("a", "GET", "https://x.test/p", 1000)], "GET", "https://x.test/p", 60_000), -1);
  assert.equal(findEntryForBody([entry("a", "GET", "https://x.test/p", 60_000)], "GET", "https://x.test/p", 1000), -1);
});

test("findEntryForBody ignores entries with no response at all (still pending / errored)", () => {
  const e = entry("a", "GET", "https://x.test/p", 1000);
  e.response = null;
  assert.equal(findEntryForBody([e], "GET", "https://x.test/p", 1000), -1);
});

test("a body that arrives before its History entry is parked and consumed exactly once", async () => {
  // Stub just enough chrome.storage for attachResponseBody's getHistory() — History is empty.
  const area = { get: async () => ({}), set: async () => {}, remove: async () => {} };
  globalThis.chrome = { storage: { local: area, session: area } };
  assert.equal(await attachResponseBody("GET", "https://x.test/early", 5000, "early body"), false);
  assert.equal(consumeResponseBody("GET", "https://x.test/early", 5200), "early body");
  assert.equal(consumeResponseBody("GET", "https://x.test/early", 5200), null);
});

test("a parked body too far from the entry's completion time is not used", async () => {
  await attachResponseBody("GET", "https://x.test/late", 1000, "stale");
  assert.equal(consumeResponseBody("GET", "https://x.test/late", 90_000), null);
});

test("shouldCaptureBody keeps text-like responses and skips binary ones", () => {
  assert.equal(shouldCaptureBody("Document", "text/html"), true);
  assert.equal(shouldCaptureBody("XHR", "application/json"), true);
  assert.equal(shouldCaptureBody("Fetch", "application/vnd.api+json"), true);
  assert.equal(shouldCaptureBody("Script", "application/javascript"), true);
  assert.equal(shouldCaptureBody("Image", "image/svg+xml"), false);
  assert.equal(shouldCaptureBody("Fetch", "application/octet-stream"), false);
  assert.equal(shouldCaptureBody("Font", "font/woff2"), false);
  assert.equal(shouldCaptureBody("Other", null), false);
});
