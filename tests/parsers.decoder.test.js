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

test("DECODER_MODES exposes matching encode/decode pairs for every mode", () => {
  for (const mode of DECODER_MODES) {
    const encoded = mode.encode("round trip me");
    const result = mode.decode(encoded);
    assert.equal(result.ok, true);
    assert.equal(result.value, "round trip me");
  }
});
