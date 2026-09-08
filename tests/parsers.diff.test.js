import { test } from "node:test";
import assert from "node:assert/strict";
import { tokenize, diffText, MAX_DIFF_TOKENS } from "../src/parsers/diff.js";

test("tokenize splits into whitespace-run and non-whitespace tokens, preserving everything", () => {
  const tokens = tokenize("foo  bar\nbaz");
  assert.equal(tokens.join(""), "foo  bar\nbaz");
  assert.deepEqual(tokens, ["foo", "  ", "bar", "\n", "baz"]);
});

test("diffText on identical text produces a single equal segment", () => {
  const { segments, truncated } = diffText("same text here", "same text here");
  assert.equal(truncated, false);
  assert.equal(segments.length, 1);
  assert.equal(segments[0].type, "equal");
  assert.equal(segments[0].text, "same text here");
});

test("diffText reconstructs both original strings from the segments", () => {
  const a = "GET /login?user=alice HTTP/1.1";
  const b = "GET /login?user=bob HTTP/1.1";
  const { segments } = diffText(a, b);
  const reconstructedA = segments.filter((s) => s.type !== "added").map((s) => s.text).join("");
  const reconstructedB = segments.filter((s) => s.type !== "removed").map((s) => s.text).join("");
  assert.equal(reconstructedA, a);
  assert.equal(reconstructedB, b);
});

test("diffText marks a single changed word as removed+added around shared equal context", () => {
  const { segments } = diffText("status: 200 ok", "status: 403 ok");
  const types = segments.map((s) => s.type);
  assert.deepEqual(types, ["equal", "removed", "equal", "added", "equal"]);
  assert.equal(segments.find((s) => s.type === "removed").text, "200");
  assert.equal(segments.find((s) => s.type === "added").text, "403");
});

test("diffText handles a completely different pair as one big removed and one big added block", () => {
  const { segments } = diffText("aaa", "zzz");
  assert.deepEqual(
    segments.map((s) => s.type),
    ["removed", "added"]
  );
});

test("diffText handles empty strings on either or both sides", () => {
  assert.deepEqual(diffText("", "").segments, []);
  assert.deepEqual(diffText("x", "").segments, [{ type: "removed", text: "x" }]);
  assert.deepEqual(diffText("", "x").segments, [{ type: "added", text: "x" }]);
});

test("diffText falls back to a two-block diff instead of a full LCS when either side is too large", () => {
  const huge = Array.from({ length: MAX_DIFF_TOKENS + 1 }, (_, i) => `w${i}`).join(" ");
  const { segments, truncated } = diffText(huge, "short text");
  assert.equal(truncated, true);
  assert.equal(segments[0].type, "removed");
  assert.equal(segments[1].type, "added");
  assert.equal(segments[1].text, "short text");
});
