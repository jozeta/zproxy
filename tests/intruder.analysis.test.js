import { test } from "node:test";
import assert from "node:assert/strict";
import { findAnomalies, sortResults, SORTABLE_RESULT_KEYS } from "../src/intruder/analysis.js";

function row(index, overrides = {}) {
  return { index, response: { statusCode: 200, body: "" }, status: 200, length: 1000, timeMs: 50, ...overrides };
}

test("findAnomalies returns [] for fewer than 2 successful results", () => {
  assert.deepEqual(findAnomalies([]), new Set());
  assert.deepEqual(findAnomalies([row(1)]), new Set());
});

test("findAnomalies flags nothing when every response shares the same status and length", () => {
  const results = [row(1), row(2), row(3)];
  assert.deepEqual(findAnomalies(results), new Set());
});

test("findAnomalies flags the response whose length differs from the majority", () => {
  const results = [row(1), row(2), row(3, { length: 42 })];
  assert.deepEqual(findAnomalies(results), new Set([3]));
});

test("findAnomalies flags the response whose status differs from the majority", () => {
  const results = [row(1), row(2), row(3, { status: 500 })];
  assert.deepEqual(findAnomalies(results), new Set([3]));
});

test("findAnomalies never flags a row with no response, and excludes it from the majority computation", () => {
  const results = [row(1), row(2), { index: 3, response: null, status: null, length: null, timeMs: null, error: "Aborted" }];
  assert.deepEqual(findAnomalies(results), new Set());
});

test("findAnomalies with a genuine 3-way split flags whichever isn't the (first-seen) majority", () => {
  // two 200/1000s, one 200/500 -> the odd one out is flagged
  const results = [row(1), row(2, { length: 500 }), row(3)];
  assert.deepEqual(findAnomalies(results), new Set([2]));
});

test("SORTABLE_RESULT_KEYS covers the numeric columns", () => {
  assert.deepEqual(SORTABLE_RESULT_KEYS, ["index", "status", "length", "timeMs"]);
});

test("sortResults sorts ascending/descending by the given key without mutating the input", () => {
  const results = [row(1, { length: 300 }), row(2, { length: 100 }), row(3, { length: 200 })];
  const asc = sortResults(results, "length", "asc");
  assert.deepEqual(asc.map((r) => r.index), [2, 3, 1]);
  const desc = sortResults(results, "length", "desc");
  assert.deepEqual(desc.map((r) => r.index), [1, 3, 2]);
  assert.deepEqual(results.map((r) => r.index), [1, 2, 3]); // original order untouched
});

test("sortResults pushes null/missing values to the end regardless of direction", () => {
  const results = [row(1, { status: 200 }), row(2, { status: null }), row(3, { status: 404 })];
  assert.deepEqual(sortResults(results, "status", "asc").map((r) => r.index), [1, 3, 2]);
  assert.deepEqual(sortResults(results, "status", "desc").map((r) => r.index), [3, 1, 2]);
});

test("sortResults falls back to index order for an unrecognized key", () => {
  const results = [row(3), row(1), row(2)];
  assert.deepEqual(sortResults(results, "nonsense", "asc").map((r) => r.index), [1, 2, 3]);
});
