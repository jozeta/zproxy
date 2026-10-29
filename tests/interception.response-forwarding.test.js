// Drives response-interceptor.js against a stubbed chrome.debugger, checking
// what actually gets sent back to the page — the display copy of a body is
// capped and lossy, and must never be what's forwarded.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

let calls = [];
let responseBody = { body: "", base64Encoded: false };
const storageArea = { get: async () => ({}), set: async () => {}, remove: async () => {} };
globalThis.chrome = {
  debugger: {
    sendCommand: async (_target, method, params) => {
      calls.push({ method, params });
      if (method === "Fetch.getResponseBody") return responseBody;
      return {};
    },
  },
  storage: { local: storageArea, session: storageArea },
};

const RI = await import("../src/interception/response-interceptor.js");
const { base64ToText } = await import("../src/utils/bytes.js");

let nextId = 0;
function pausedParams() {
  return {
    requestId: `fetch-${++nextId}`,
    request: { method: "GET", url: "https://lab.test/big.js", headers: {} },
    responseStatusCode: 200,
    responseHeaders: [{ name: "Content-Type", value: "application/javascript" }],
  };
}

async function pause(params, { applyRules } = {}) {
  const emitted = [];
  await RI.handlePaused(1, params, { applyRules, manualPauseEnabled: true, interceptRules: [], emit: (e) => emitted.push(e) });
  return emitted[0].item;
}

const fulfilled = () => calls.find((c) => c.method === "Fetch.fulfillRequest")?.params;

beforeEach(() => {
  calls = [];
});

test("the UI gets a truncated display copy of a huge body", async () => {
  responseBody = { body: "x".repeat(600_000), base64Encoded: false };
  const item = await pause(pausedParams());
  assert.equal(item.response.body.length, 500_000);
  assert.equal(item.response.bodyTruncated, true);
});

test("editing only a header of a truncated response forwards the FULL body", async () => {
  const full = "x".repeat(600_000);
  responseBody = { body: full, base64Encoded: false };
  const params = pausedParams();
  const item = await pause(params);
  const edited = { ...item.response, headers: [...item.response.headers, { name: "X-Edited", value: "1" }] };
  await RI.forwardEdited(1, params.requestId, edited);
  assert.equal(base64ToText(fulfilled().body).length, full.length);
});

test("editing the body of a truncated response is refused, and the response stays paused", async () => {
  responseBody = { body: "x".repeat(600_000), base64Encoded: false };
  const params = pausedParams();
  const item = await pause(params);
  await assert.rejects(RI.forwardEdited(1, params.requestId, { ...item.response, body: "short" }), /truncated/);
  assert.equal(fulfilled(), undefined);
  assert.equal(RI.getPendingItems(1).some((p) => p.fetchRequestId === params.requestId), true);
  await RI.forwardUnmodified(1, params.requestId);
});

test("a binary body forwarded after a header-only edit keeps its original bytes", async () => {
  // 0xFF 0xD8 0xFF 0xE0: a JPEG header — not valid UTF-8, so a text round-trip would mangle it.
  const raw = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]).toString("base64");
  responseBody = { body: raw, base64Encoded: true };
  const params = pausedParams();
  const item = await pause(params);
  await RI.forwardEdited(1, params.requestId, { ...item.response, statusText: "Edited" });
  assert.equal(fulfilled().body, raw);
});

test("plain Forward keeps a content rule's change instead of passing the original through", async () => {
  responseBody = { body: "flag=false", base64Encoded: false };
  const params = pausedParams();
  const applyRules = (it) => ({ ...it, response: { ...it.response, body: it.response.body.replace("false", "true") } });
  await pause(params, { applyRules });
  await RI.forward(1, params.requestId);
  assert.equal(base64ToText(fulfilled().body), "flag=true");
  assert.equal(calls.some((c) => c.method === "Fetch.continueResponse"), false);
});

test("plain Forward with no rule change uses the native pass-through", async () => {
  responseBody = { body: "unchanged", base64Encoded: false };
  const params = pausedParams();
  await pause(params);
  await RI.forward(1, params.requestId);
  assert.equal(fulfilled(), undefined);
  assert.equal(calls.some((c) => c.method === "Fetch.continueResponse"), true);
});
