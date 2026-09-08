import { test } from "node:test";
import assert from "node:assert/strict";
import { requestActuallyChanged } from "../src/interception/request-interceptor.js";

function req(overrides = {}) {
  return {
    method: "GET",
    url: "https://example.com/api",
    headers: [{ name: "Accept", value: "*/*" }],
    body: null,
    ...overrides,
  };
}

test("requestActuallyChanged is false for identical requests", () => {
  assert.equal(requestActuallyChanged(req(), req()), false);
});

test("requestActuallyChanged is false when there's nothing to compare against yet", () => {
  assert.equal(requestActuallyChanged(req(), null), false);
  assert.equal(requestActuallyChanged(req(), undefined), false);
});

test("requestActuallyChanged detects a method change", () => {
  assert.equal(requestActuallyChanged(req(), req({ method: "POST" })), true);
});

test("requestActuallyChanged detects a URL change", () => {
  assert.equal(requestActuallyChanged(req(), req({ url: "https://example.com/other" })), true);
});

test("requestActuallyChanged detects a body change, treating null and empty string as equal", () => {
  assert.equal(requestActuallyChanged(req({ body: null }), req({ body: "" })), false);
  assert.equal(requestActuallyChanged(req({ body: "a" }), req({ body: "b" })), true);
});

test("requestActuallyChanged detects a header value change but ignores header order", () => {
  const a = req({
    headers: [
      { name: "A", value: "1" },
      { name: "B", value: "2" },
    ],
  });
  const reordered = req({
    headers: [
      { name: "B", value: "2" },
      { name: "A", value: "1" },
    ],
  });
  const changed = req({
    headers: [
      { name: "A", value: "1" },
      { name: "B", value: "different" },
    ],
  });
  assert.equal(requestActuallyChanged(a, reordered), false);
  assert.equal(requestActuallyChanged(a, changed), true);
});
