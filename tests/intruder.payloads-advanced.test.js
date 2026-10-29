import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePayloads, estimateCount } from "../src/intruder/payloads.js";
import { illegalUnicodeForms, parseIpRange, encodingVariants, parseRegexTemplate } from "../src/intruder/payloads-advanced.js";

const gen = (cfg, limit = 1000) => generatePayloads(cfg, { limit }).payloads;

test("Custom iterator combines one item per position with separators", () => {
  const cfg = { type: "customIterator", slots: [{ text: "admin\nroot", separator: "@" }, { text: "a.test\nb.test", separator: "" }] };
  assert.deepEqual(gen(cfg), ["admin@a.test", "admin@b.test", "root@a.test", "root@b.test"]);
  assert.equal(estimateCount(cfg), 4);
  assert.deepEqual(gen({ type: "customIterator", slots: [{ text: "", separator: "" }] }), []);
});

test("Regex generator enumerates classes, groups, and bounded quantifiers", () => {
  assert.deepEqual(gen({ type: "regexGenerator", pattern: "ORD-[0-2]{2}" }), ["ORD-00", "ORD-01", "ORD-02", "ORD-10", "ORD-11", "ORD-12", "ORD-20", "ORD-21", "ORD-22"]);
  assert.deepEqual(gen({ type: "regexGenerator", pattern: "(admin|root)[0-1]?" }), ["admin", "admin0", "admin1", "root", "root0", "root1"]);
  assert.deepEqual(gen({ type: "regexGenerator", pattern: "^a\\d$" }).length, 10);
  assert.deepEqual(gen({ type: "regexGenerator", pattern: "x+", maxRepeat: 3 }), ["x", "xx", "xxx"]);
  assert.deepEqual(gen({ type: "regexGenerator", pattern: "[^a-z0-9]" }).includes("a"), false);
});

test("Regex generator rejects what it can't generate, with a readable message", () => {
  assert.throws(() => parseRegexTemplate("(abc"), /Missing \)/);
  assert.throws(() => parseRegexTemplate("[z-a]"), /backwards/);
  assert.throws(() => parseRegexTemplate("*x"), /Nothing to repeat/);
  assert.throws(() => parseRegexTemplate("\\bword"), /isn't supported/);
  assert.deepEqual(gen({ type: "regexGenerator", pattern: "(abc" }), []); // invalid → nothing, never a crash
});

test("Illegal Unicode produces overlong UTF-8, %u, double-encoded, and full-width forms", () => {
  assert.deepEqual(illegalUnicodeForms("/"), ["%C0%AF", "%E0%80%AF", "%F0%80%80%AF", "%u002F", "%252F", "／"]);
  const out = gen({ type: "illegalUnicode", text: "../", targets: "/" });
  assert.equal(out[0], "..%C0%AF");
  assert.equal(out.length, 6);
});

test("Character frobber and bit flipper change exactly one position per payload", () => {
  assert.deepEqual(gen({ type: "characterFrobber", text: "ab" }), ["bb", "ac"]);
  const flips = gen({ type: "bitFlipper", text: "A" });
  assert.equal(flips.length, 8);
  assert.equal(flips[0], "@"); // 0x41 ^ 0x01
  assert.deepEqual(gen({ type: "bitFlipper", text: "00ff", format: "hex" }).slice(0, 2), ["01ff", "02ff"]);
});

test("ECB block shuffler swaps whole blocks and keeps the input format", () => {
  const hex = "aa".repeat(8) + "bb".repeat(8) + "cc".repeat(8);
  const out = gen({ type: "ecbShuffler", text: hex, format: "hex", blockSize: 8 });
  assert.equal(out.length, 6); // 3 blocks × 2 replacements each
  assert.ok(out.includes("bb".repeat(8) + "bb".repeat(8) + "cc".repeat(8)));
  assert.deepEqual(gen({ type: "ecbShuffler", text: "aabb", format: "hex", blockSize: 8 }), []); // shorter than two blocks
});

test("IP ranges parse CIDR, start-end, and single addresses", () => {
  assert.deepEqual(parseIpRange("10.0.0.5/30"), { start: 167772164, end: 167772167 });
  assert.deepEqual(gen({ type: "ipRange", text: "10.0.0.0/30\n192.168.1.9-192.168.1.10\n127.0.0.1" }), ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "192.168.1.9", "192.168.1.10", "127.0.0.1"]);
  assert.equal(estimateCount({ type: "ipRange", text: "10.0.0.0/24\nnot an ip" }), 256);
  assert.equal(parseIpRange("300.1.1.1"), null);
});

test("Random strings and UUIDs have the requested shape and count", () => {
  const r = gen({ type: "randomStrings", count: 5, length: 12, charset: "hex" });
  assert.equal(r.length, 5);
  assert.ok(r.every((s) => /^[0-9a-f]{12}$/.test(s)));
  assert.ok(gen({ type: "randomStrings", count: 3, length: 4, charset: "custom", custom: "xy" }).every((s) => /^[xy]{4}$/.test(s)));
  const u = gen({ type: "uuids", count: 3 });
  assert.ok(u.every((s) => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s)));
  assert.equal(new Set(u).size, 3);
});

test("Encoding variants cover the common filter-bypass encodings without duplicates", () => {
  const v = encodingVariants("<a>");
  for (const expected of ["<a>", "%3Ca%3E", "%253Ca%253E", "%3C%61%3E", "&lt;a&gt;", "&#x3c;&#x61;&#x3e;", "&#60;&#97;&#62;", "\\u003c\\u0061\\u003e", "\\x3c\\x61\\x3e", "PGE+"]) {
    assert.ok(v.includes(expected), expected);
  }
  assert.equal(new Set(v).size, v.length);
  assert.deepEqual(encodingVariants("abc").slice(0, 1), ["abc"]);
});
