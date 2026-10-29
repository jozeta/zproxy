import { test } from "node:test";
import assert from "node:assert/strict";
import {
  encodeBase64,
  decodeBase64,
  encodeUrl,
  decodeUrl,
  encodeHtmlEntities,
  decodeHtmlEntities,
  encodeHex,
  decodeHex,
  DECODER_MODES,
} from "../src/parsers/decoder.js";

test("base64 round-trips, including unicode", () => {
  const encoded = encodeBase64("héllo 👋");
  assert.equal(decodeBase64(encoded).value, "héllo 👋");
});

test("decodeBase64 reports failure instead of throwing on invalid input", () => {
  const result = decodeBase64("not valid base64!!! ***");
  assert.equal(result.ok, false);
  assert.match(result.error, /invalid/i);
});

test("URL encode/decode round-trips and reports failure on malformed percent-encoding", () => {
  assert.equal(encodeUrl("a b&c"), "a%20b%26c");
  assert.equal(decodeUrl("a%20b%26c").value, "a b&c");
  const bad = decodeUrl("%E0%A4%A");
  assert.equal(bad.ok, false);
});

test("HTML entity encode escapes the five dangerous characters", () => {
  assert.equal(encodeHtmlEntities(`<script>alert('x')&"y"</script>`), "&lt;script&gt;alert(&#39;x&#39;)&amp;&quot;y&quot;&lt;/script&gt;");
});

test("HTML entity decode handles named and numeric (decimal/hex) entities", () => {
  assert.equal(decodeHtmlEntities("&lt;b&gt;&amp;&#65;&#x42;").value, "<b>&AB");
});

test("HTML entity decode leaves an unknown named entity untouched rather than dropping it", () => {
  assert.equal(decodeHtmlEntities("&notreal;").value, "&notreal;");
});

test("hex encode/decode round-trips, including unicode", () => {
  const encoded = encodeHex("hi é");
  assert.equal(encoded, "686920c3a9"); // h=68 i=69 space=20 é(UTF-8)=c3a9
  assert.equal(decodeHex(encoded).value, "hi é");
});

test("decodeHex accepts whitespace-separated hex and rejects malformed input", () => {
  assert.equal(decodeHex("68 69").value, "hi");
  assert.equal(decodeHex("xyz").ok, false);
  assert.equal(decodeHex("abc").ok, false); // odd length
});

test("DECODER_MODES exposes matching encode/decode pairs for every mode (either side may be async)", async () => {
  for (const mode of DECODER_MODES) {
    const encoded = await mode.encode("round trip me");
    const result = await mode.decode(encoded);
    assert.equal(result.ok, true);
    assert.equal(result.value, "round trip me");
  }
});

test("new decoder modes encode and decode their own formats", async () => {
  const { encodeUrlAll, encodeBase64Url, decodeBase64Url, encodeUnicodeEscape, decodeUnicodeEscape, encodeBinary, decodeCharCodes, rot13, decodeGzip } = await import("../src/parsers/decoder.js");
  assert.equal(encodeUrlAll("a b"), "%61%20%62");
  assert.equal(encodeBase64Url("??>"), "Pz8-");
  assert.equal(decodeBase64Url("Pz8-").value, "??>");
  assert.equal(encodeUnicodeEscape("é<"), "\\u00e9<");
  assert.equal(decodeUnicodeEscape("\\u00e9\\x41\\u{1F600}").value, "éA😀");
  assert.equal(encodeBinary("A"), "01000001");
  assert.equal(decodeCharCodes("72, 105").value, "Hi");
  assert.equal(decodeCharCodes("1,x").ok, false);
  assert.equal(rot13(rot13("Hello")), "Hello");
  assert.equal((await decodeGzip("not base64!")).ok, false);
  // zlib (deflate) data is accepted too, not just gzip.
  const zlib = await import("node:zlib");
  assert.equal((await decodeGzip(zlib.deflateSync("hej").toString("base64"))).value, "hej");
});

test("smartDecode peels layered encodings and stops on plain text", async () => {
  const { smartDecode } = await import("../src/parsers/decoder.js");
  const layered = encodeURIComponent(Buffer.from('{"user":"admin","role":"staff"}').toString("base64"));
  const steps = smartDecode(layered);
  assert.deepEqual(steps.map((s) => s.label), ["URL", "Base64"]);
  assert.equal(steps.at(-1).value, '{"user":"admin","role":"staff"}');
  assert.deepEqual(smartDecode("just some words"), []);
  assert.deepEqual(smartDecode("&lt;b&gt;").map((s) => s.value), ["<b>"]);
});

test("describeTimestamp recognizes Unix seconds, milliseconds, and ISO dates — and nothing else", async () => {
  const { describeTimestamp } = await import("../src/parsers/decoder.js");
  assert.equal(describeTimestamp("1706659200").iso, "2024-01-31T00:00:00.000Z");
  assert.equal(describeTimestamp("1706659200000").unixSeconds, 1706659200);
  assert.equal(describeTimestamp("2024-01-31T00:00:00Z").unixSeconds, 1706659200);
  assert.equal(describeTimestamp("12345"), null);
  assert.equal(describeTimestamp("hello"), null);
});
