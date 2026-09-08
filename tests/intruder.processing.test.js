import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import { applyProcessingRules, applyProcessingRulesToAll, defaultProcessingRule, ruleTakesValue, PROCESSING_RULE_TYPES } from "../src/intruder/processing.js";

test("PROCESSING_RULE_TYPES lists options with value/label pairs", () => {
  assert.ok(PROCESSING_RULE_TYPES.length > 0);
  for (const opt of PROCESSING_RULE_TYPES) {
    assert.equal(typeof opt.value, "string");
    assert.equal(typeof opt.label, "string");
  }
});

test("ruleTakesValue/defaultProcessingRule: prefix/suffix carry a value field, others don't", () => {
  assert.equal(ruleTakesValue("prefix"), true);
  assert.equal(ruleTakesValue("upper"), false);
  assert.deepEqual(defaultProcessingRule("prefix"), { type: "prefix", value: "" });
  assert.deepEqual(defaultProcessingRule("upper"), { type: "upper" });
});

test("applyProcessingRules with no rules returns the payload unchanged", async () => {
  assert.equal(await applyProcessingRules("hello", []), "hello");
  assert.equal(await applyProcessingRules("hello", undefined), "hello");
});

test("prefix/suffix", async () => {
  assert.equal(await applyProcessingRules("x", [{ type: "prefix", value: "admin_" }]), "admin_x");
  assert.equal(await applyProcessingRules("x", [{ type: "suffix", value: "_test" }]), "x_test");
});

test("urlEncode/urlDecode round-trip, and urlDecode passes through malformed input rather than throwing", async () => {
  assert.equal(await applyProcessingRules("a b&c", [{ type: "urlEncode" }]), "a%20b%26c");
  assert.equal(await applyProcessingRules("a%20b", [{ type: "urlDecode" }]), "a b");
  assert.equal(await applyProcessingRules("%E0%A4%A", [{ type: "urlDecode" }]), "%E0%A4%A");
});

test("base64Encode/base64Decode round-trip, and base64Decode passes through invalid input rather than throwing", async () => {
  assert.equal(await applyProcessingRules("hello", [{ type: "base64Encode" }]), "aGVsbG8=");
  assert.equal(await applyProcessingRules("aGVsbG8=", [{ type: "base64Decode" }]), "hello");
  assert.equal(await applyProcessingRules("not base64!!!", [{ type: "base64Decode" }]), "not base64!!!");
});

test("upper/lower", async () => {
  assert.equal(await applyProcessingRules("MiXeD", [{ type: "upper" }]), "MIXED");
  assert.equal(await applyProcessingRules("MiXeD", [{ type: "lower" }]), "mixed");
});

test("sha1/sha256 hash rules produce the expected hex digest", async () => {
  assert.equal(await applyProcessingRules("hello", [{ type: "sha1" }]), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
  assert.equal(await applyProcessingRules("hello", [{ type: "sha256" }]), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
});

test("rules chain in order, each rule's output feeding the next", async () => {
  const result = await applyProcessingRules("x", [{ type: "prefix", value: "a" }, { type: "suffix", value: "z" }, { type: "upper" }]);
  assert.equal(result, "AXZ");
});

test("applyProcessingRulesToAll maps every payload through the chain, preserving order", async () => {
  const result = await applyProcessingRulesToAll(["a", "b", "c"], [{ type: "upper" }]);
  assert.deepEqual(result, ["A", "B", "C"]);
});

test("applyProcessingRulesToAll with no rules returns the same array contents unchanged", async () => {
  const input = ["a", "b"];
  assert.deepEqual(await applyProcessingRulesToAll(input, []), input);
});
