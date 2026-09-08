import { test } from "node:test";
import assert from "node:assert/strict";
import { responseActuallyChanged } from "../src/interception/response-interceptor.js";

function res(overrides = {}) {
  return {
    statusCode: 200,
    statusText: "OK",
    headers: [{ name: "Content-Type", value: "application/json" }],
    body: '{"ok":true}',
    ...overrides,
  };
}

test("responseActuallyChanged is false for identical responses", () => {
  assert.equal(responseActuallyChanged(res(), res()), false);
});

test("responseActuallyChanged is false when there's nothing to compare against yet", () => {
  assert.equal(responseActuallyChanged(res(), null), false);
});

test("responseActuallyChanged detects a status code change (compared as strings, so 200 vs '200' isn't a false positive)", () => {
  assert.equal(responseActuallyChanged(res({ statusCode: 200 }), res({ statusCode: "200" })), false);
  assert.equal(responseActuallyChanged(res({ statusCode: 200 }), res({ statusCode: 404 })), true);
});

test("responseActuallyChanged detects a body change — this is the exact case a content-engine rule (e.g. flipping a feature flag) needs to flag as edited", () => {
  assert.equal(responseActuallyChanged(res({ body: '{"featureXEnabled":false}' }), res({ body: '{"featureXEnabled":true}' })), true);
});

test("responseActuallyChanged ignores header order but catches a value change", () => {
  const a = res({
    headers: [
      { name: "Content-Type", value: "application/json" },
      { name: "X-Custom", value: "1" },
    ],
  });
  const reordered = res({
    headers: [
      { name: "X-Custom", value: "1" },
      { name: "Content-Type", value: "application/json" },
    ],
  });
  const changed = res({ headers: [{ name: "Content-Type", value: "text/html" }] });
  assert.equal(responseActuallyChanged(a, reordered), false);
  assert.equal(responseActuallyChanged(a, changed), true);
});
