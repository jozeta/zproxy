import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  defaultConfig, generatePayloads, estimateCount, DEFAULT_GENERATION_CAP, formatDate, caseVariants, parseSubstitutions, substitutionVariants, usernameVariants, PAYLOAD_TYPES,
} from "../src/intruder/payloads.js";
import { WORDLISTS, WORDLIST_IDS } from "../src/intruder/wordlists.js";
import { applyProcessingRules, applyProcessingRulesToAll, PROCESSING_RULE_TYPES, defaultProcessingRule } from "../src/intruder/processing.js";
import { resultsToCsv } from "../src/intruder/export.js";

const gen = (cfg, limit) => generatePayloads(cfg, limit ? { limit } : undefined).payloads;

test("every payload type has a default config that generates and estimates consistently", () => {
  for (const { value } of PAYLOAD_TYPES) {
    const cfg = { ...defaultConfig(value), text: "Ada Lovelace\nadmin" };
    // Generation stops at the cap; the estimate is the true (uncapped) count.
    assert.equal(Math.min(estimateCount(cfg), DEFAULT_GENERATION_CAP), gen(cfg).length, value);
  }
});

test("Fuzz lists are non-empty, de-duplicated, and generate their items", () => {
  for (const id of WORDLIST_IDS) {
    const { items } = WORDLISTS[id];
    assert.ok(items.length >= 5, id);
    assert.equal(new Set(items).size, items.length, `${id} has duplicates`);
  }
  assert.deepEqual(gen({ type: "wordlist", list: "httpMethods" }).slice(0, 2), ["GET", "POST"]);
  assert.equal(estimateCount({ type: "wordlist", list: "nope" }), 0);
});

test("Dates walk the range in UTC (no DST skips) in the chosen format", () => {
  assert.deepEqual(gen({ type: "dates", from: "2024-03-30", to: "2024-04-01", stepDays: 1, format: "DD/MM/YYYY" }), ["30/03/2024", "31/03/2024", "01/04/2024"]);
  assert.deepEqual(gen({ type: "dates", from: "2024-01-10", to: "2024-01-01", stepDays: -5, format: "YYYYMMDD" }), ["20240110", "20240105"]);
  assert.equal(formatDate(Date.UTC(2024, 0, 31), "unix"), "1706659200");
  assert.equal(estimateCount({ type: "dates", from: "2024-01-01", to: "2023-01-01", stepDays: 1 }), 0);
  assert.equal(estimateCount({ type: "dates", from: "bad", to: "2023-01-01", stepDays: 1 }), 0);
});

test("caseVariants de-duplicates (a word that's already lowercase yields fewer variants)", () => {
  assert.deepEqual(caseVariants("Admin"), ["Admin", "admin", "ADMIN", "aDMIN", "AdMiN"]);
  assert.deepEqual(caseVariants("123"), ["123"]);
});

test("character substitution yields every combination, with multiple replacements per char", () => {
  const map = parseSubstitutions("a=4,@ s=5 bogus x=");
  assert.deepEqual([...map.keys()], ["a", "s"]);
  assert.deepEqual([...substitutionVariants("as", map)], ["as", "a5", "4s", "45", "@s", "@5"]);
  assert.deepEqual(gen({ type: "charSubstitution", text: "zz", substitutions: "a=4" }), ["zz"]);
});

test("username generator covers common formats and handles single names", () => {
  const u = usernameVariants("Ada  Byron Lovelace");
  for (const expected of ["ada.lovelace", "adalovelace", "alovelace", "a.lovelace", "ada_lovelace", "lovelace.ada", "adal"]) assert.ok(u.includes(expected), expected);
  assert.deepEqual(usernameVariants("Cher"), ["cher"]);
});

test("character blocks and null payloads produce the requested sizes", () => {
  assert.deepEqual(gen({ type: "charBlocks", base: "ab", minLength: 1, maxLength: 5, step: 2 }), ["a", "aba", "ababa"]);
  assert.deepEqual(gen({ type: "nullPayloads", count: 3 }), ["", "", ""]);
  assert.equal(estimateCount({ type: "nullPayloads", count: -4 }), 0);
});

test("generation is capped for exploding configs", () => {
  const { payloads, truncated } = generatePayloads({ type: "charSubstitution", text: "aaaaaaaaaaaaaaaaaaaa", substitutions: "a=4,@" }, { limit: 50 });
  assert.equal(payloads.length, 50);
  assert.equal(truncated, true);
});

test("new processing rules transform as documented", async () => {
  const run = (type, extra = {}) => applyProcessingRules("<a b>", [{ ...defaultProcessingRule(type), ...extra }]);
  assert.equal(await run("urlEncodeAll"), "%3C%61%20%62%3E");
  assert.equal(await run("doubleUrlEncode"), "%253Ca%2520b%253E");
  assert.equal(await run("htmlEncode"), "&lt;a b&gt;");
  assert.equal(await run("hexEncode"), "3c6120623e");
  assert.equal(await run("reverse"), ">b a<");
  assert.equal(await run("replace", { match: " ", value: "/**/" }), "<a/**/b>");
  assert.equal(await run("md5"), createHash("md5").update("<a b>").digest("hex"));
  assert.equal(await applyProcessingRules("é", [{ type: "unicodeEscape" }]), "\\u00e9");
  assert.equal(await applyProcessingRules("?a", [{ type: "base64UrlEncode" }]), "P2E");
});

test("Skip if matches drops payloads from the set; an invalid regex never skips", async () => {
  assert.deepEqual(await applyProcessingRulesToAll(["keep", "drop-me", "also"], [{ type: "skipIfMatches", value: "^drop" }]), ["keep", "also"]);
  assert.deepEqual(await applyProcessingRulesToAll(["a"], [{ type: "skipIfMatches", value: "(" }]), ["a"]);
});

test("every processing rule type is selectable and has a working default", async () => {
  for (const { value } of PROCESSING_RULE_TYPES) {
    const out = await applyProcessingRules("abc", [defaultProcessingRule(value)]);
    assert.equal(typeof out, "string", value);
  }
});

test("resultsToCsv quotes, orders by index, adds grep columns, and neutralizes formula payloads", () => {
  const rows = [
    { index: 2, payloads: ['=cmd|"/C calc"!A0'], status: 200, length: 5, timeMs: 3, response: { body: "Welcome, admin" }, error: null },
    { index: 1, payloads: ["a", "b,c"], status: null, length: null, timeMs: null, response: null, error: "Request failed" },
  ];
  const csv = resultsToCsv(rows, ["Welcome"]).split("\r\n");
  assert.equal(csv[0], "#,Payload(s),Status,Length,Time (ms),Grep: Welcome,Error");
  assert.equal(csv[1], '1,"a | b,c",,,,,Request failed');
  assert.equal(csv[2], `2,"'=cmd|""/C calc""!A0",200,5,3,yes,`);
});
