import { test } from "node:test";
import assert from "node:assert/strict";
import { recordSend, stepHistory, previousResponse, groupOutliers, MAX_HISTORY_PER_TAB } from "../src/utils/repeater-history.js";

const res = (statusCode, body) => ({ statusCode, statusText: "", headers: [], body, durationMs: 1 });
const ok = (statusCode, body) => ({ ok: true, response: res(statusCode, body) });

test("recordSend appends and makes the new send current", () => {
  const tab = {};
  recordSend(tab, { request: { url: "a" }, response: res(200, "x"), error: null });
  recordSend(tab, { request: { url: "b" }, response: res(403, "y"), error: null });
  assert.equal(tab.history.length, 2);
  assert.equal(tab.historyIndex, 1);
  assert.equal(tab.request.url, "b");
});

test("stepHistory restores request/response/error and refuses to go past either end", () => {
  const tab = {};
  recordSend(tab, { request: { url: "a" }, response: res(200, "x"), error: null });
  recordSend(tab, { request: { url: "b" }, response: null, error: "boom" });
  assert.equal(stepHistory(tab, 1), false);
  assert.equal(stepHistory(tab, -1), true);
  assert.deepEqual([tab.request.url, tab.response.statusCode, tab.error], ["a", 200, null]);
  assert.equal(stepHistory(tab, -1), false);
  assert.equal(stepHistory(tab, 1), true);
  assert.equal(tab.error, "boom");
});

test("sending from an older entry appends instead of discarding later entries", () => {
  const tab = {};
  for (const url of ["a", "b", "c"]) recordSend(tab, { request: { url }, response: res(200, url), error: null });
  stepHistory(tab, -1);
  stepHistory(tab, -1);
  recordSend(tab, { request: { url: "d" }, response: res(200, "d"), error: null });
  assert.deepEqual(tab.history.map((h) => h.request.url), ["a", "b", "c", "d"]);
  assert.equal(tab.historyIndex, 3);
});

test("history is capped, dropping the oldest", () => {
  const tab = {};
  for (let i = 0; i < MAX_HISTORY_PER_TAB + 5; i++) recordSend(tab, { request: { url: String(i) }, response: null, error: "e" });
  assert.equal(tab.history.length, MAX_HISTORY_PER_TAB);
  assert.equal(tab.history[0].request.url, "5");
});

test("previousResponse skips earlier sends that errored", () => {
  const tab = {};
  recordSend(tab, { request: {}, response: res(200, "first"), error: null });
  recordSend(tab, { request: {}, response: null, error: "network" });
  recordSend(tab, { request: {}, response: res(200, "third"), error: null });
  assert.equal(previousResponse(tab).body, "first");
  stepHistory(tab, -2);
  assert.equal(previousResponse(tab), null);
});

test("groupOutliers flags results differing from the majority status+length, and every error", () => {
  const results = [ok(200, "aa"), ok(200, "aa"), ok(200, "aa"), ok(409, "conflict"), ok(200, "aaa"), { ok: false, error: "x" }];
  assert.deepEqual(groupOutliers(results), [false, false, false, true, true, true]);
});
