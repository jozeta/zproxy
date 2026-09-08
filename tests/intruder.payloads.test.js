import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultConfig, estimateCount, generatePayloads, countNumbers, countBruteForce, DEFAULT_GENERATION_CAP } from "../src/intruder/payloads.js";

test("simple list: blank lines are dropped, order preserved", () => {
  const config = { type: "simpleList", text: "admin\n\nroot\r\nguest" };
  const { payloads, truncated } = generatePayloads(config);
  assert.deepEqual(payloads, ["admin", "root", "guest"]);
  assert.equal(truncated, false);
  assert.equal(estimateCount(config), 3);
});

test("numbers: ascending range with step", () => {
  const config = { type: "numbers", from: 1, to: 5, step: 2 };
  const { payloads } = generatePayloads(config);
  assert.deepEqual(payloads, ["1", "3", "5"]);
  assert.equal(countNumbers(config), 3);
});

test("numbers: descending range with negative step", () => {
  const config = { type: "numbers", from: 5, to: 1, step: -1 };
  const { payloads } = generatePayloads(config);
  assert.deepEqual(payloads, ["5", "4", "3", "2", "1"]);
});

test("numbers: zero-padded decimal output", () => {
  const config = { type: "numbers", from: 1, to: 3, step: 1, padLength: 3 };
  const { payloads } = generatePayloads(config);
  assert.deepEqual(payloads, ["001", "002", "003"]);
});

test("numbers: hex format", () => {
  const config = { type: "numbers", from: 14, to: 16, step: 1, format: "hex" };
  const { payloads } = generatePayloads(config);
  assert.deepEqual(payloads, ["e", "f", "10"]);
});

test("numbers: invalid/zero step yields nothing rather than looping forever", () => {
  const config = { type: "numbers", from: 1, to: 10, step: 0 };
  const { payloads } = generatePayloads(config);
  assert.deepEqual(payloads, []);
  assert.equal(countNumbers(config), 0);
});

test("brute forcer: exhaustively enumerates every length in range", () => {
  const config = { type: "bruteForce", charset: "ab", minLength: 1, maxLength: 2 };
  const { payloads } = generatePayloads(config);
  // length 1: a, b ; length 2: aa, ab, ba, bb
  assert.deepEqual(payloads, ["a", "b", "aa", "ab", "ba", "bb"]);
  assert.equal(countBruteForce(config), 6);
});

test("brute forcer: duplicate characters in the charset are deduplicated", () => {
  const config = { type: "bruteForce", charset: "aab", minLength: 1, maxLength: 1 };
  const { payloads } = generatePayloads(config);
  assert.deepEqual(payloads, ["a", "b"]);
});

test("generatePayloads caps output at `limit` and reports truncation", () => {
  const config = { type: "bruteForce", charset: "abcdefghij", minLength: 4, maxLength: 4 }; // 10,000 combos
  const { payloads, truncated } = generatePayloads(config, { limit: 50 });
  assert.equal(payloads.length, 50);
  assert.equal(truncated, true);
});

test("generatePayloads never materializes more than DEFAULT_GENERATION_CAP without an explicit limit", () => {
  const config = { type: "bruteForce", charset: "abcdefghijklmnopqrstuvwxyz", minLength: 5, maxLength: 6 };
  const { payloads, truncated } = generatePayloads(config);
  assert.ok(payloads.length <= DEFAULT_GENERATION_CAP);
  assert.equal(truncated, true);
});

test("estimateCount for brute forcer matches countBruteForce and can exceed the generation cap", () => {
  const config = defaultConfig("bruteForce");
  assert.equal(estimateCount(config), countBruteForce(config));
});

test("unknown payload type generates nothing instead of throwing", () => {
  const { payloads, truncated } = generatePayloads({ type: "nonsense" });
  assert.deepEqual(payloads, []);
  assert.equal(truncated, false);
  assert.equal(estimateCount({ type: "nonsense" }), 0);
});
