import { test } from "node:test";
import assert from "node:assert/strict";
import { findEntryToPatch, consumeEdited } from "../src/background/edited-tracker.js";

// markEdited() itself isn't unit-tested here — it calls into
// storage/history.js (chrome.storage), and this project's tests
// deliberately never mock chrome.*. findEntryToPatch() is the pure matching
// logic extracted specifically so it CAN be tested without that dependency;
// markEdited() just wires it to getHistory()/updateHistoryEntry().

function entry(overrides = {}) {
  return {
    id: "e1",
    startedAt: 900,
    durationMs: 100, // completes at 1000
    edited: false,
    request: { method: "GET", url: "https://example.com/api" },
    ...overrides,
  };
}

test("findEntryToPatch finds an entry that completed right around pausedAt", () => {
  const history = [entry()]; // completes at 1000
  assert.equal(findEntryToPatch(history, "GET", "https://example.com/api", 1000), 0);
});

test("findEntryToPatch returns -1 when nothing matches method+url", () => {
  const history = [entry()];
  assert.equal(findEntryToPatch(history, "POST", "https://example.com/api", 1000), -1);
  assert.equal(findEntryToPatch(history, "GET", "https://example.com/other", 1000), -1);
});

test("findEntryToPatch skips an entry already marked edited", () => {
  const history = [entry({ edited: true })];
  assert.equal(findEntryToPatch(history, "GET", "https://example.com/api", 1000), -1);
});

test("findEntryToPatch rejects an entry that finished well BEFORE the pause — an earlier, unrelated request to the same URL (e.g. a normal page load) must never be mistaken for the one just edited", () => {
  const history = [entry({ startedAt: 0, durationMs: 50 })]; // completes at 50
  assert.equal(findEntryToPatch(history, "GET", "https://example.com/api", 30_000), -1);
});

test("findEntryToPatch accepts a match no matter how long editing took — there is no upper bound tied to pausedAt, since human edit time is unbounded (this was the actual bug: a previous version rejected exactly this case)", () => {
  // Paused at t=0, but the request didn't actually complete until t=5 minutes
  // later (a slow, careful manual edit) — still a valid match.
  const fiveMinutesLater = 5 * 60 * 1000;
  const history = [entry({ startedAt: fiveMinutesLater, durationMs: 200 })];
  assert.equal(findEntryToPatch(history, "GET", "https://example.com/api", 0), 0);
});

test("findEntryToPatch accepts an entry that completed slightly BEFORE pausedAt within the small fire-order jitter allowance", () => {
  const history = [entry({ startedAt: 900, durationMs: 50 })]; // completes at 950
  assert.equal(findEntryToPatch(history, "GET", "https://example.com/api", 1000), 0);
});

test("findEntryToPatch picks the correct (later) match over an earlier unrelated one to the same URL", () => {
  const history = [
    entry({ id: "unrelated-page-load", startedAt: 0, durationMs: 50 }), // completes at 50 — long before pausedAt
    entry({ id: "the-edited-one", startedAt: 990, durationMs: 10 }), // completes at 1000 — right at pausedAt
  ];
  assert.equal(findEntryToPatch(history, "GET", "https://example.com/api", 1000), 1);
});

test("consumeEdited returns null when nothing was marked for that method+url", () => {
  assert.equal(consumeEdited("GET", "https://example.com/never-marked", 1000), null);
});

test("findEntryToPatch ignores a URL fragment on either side — CDP's Fetch.requestPaused never includes one (fragments aren't sent to the server) while chrome.webRequest's details.url does, for the exact same transaction", () => {
  const withFragment = [entry({ request: { method: "GET", url: "https://example.com/api?name=h#" } })];
  const withoutFragment = [entry({ request: { method: "GET", url: "https://example.com/api?name=h" } })];
  // Marker registered with the fragment-less (CDP) form, entry saved with
  // the fragment (webRequest) form, and vice versa — both must match.
  assert.equal(findEntryToPatch(withFragment, "GET", "https://example.com/api?name=h", 1000), 0);
  assert.equal(findEntryToPatch(withoutFragment, "GET", "https://example.com/api?name=h#", 1000), 0);
});
