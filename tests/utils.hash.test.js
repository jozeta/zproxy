import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
// Node exposes WebCrypto as a global without a flag starting in v19; on some
// v18 builds it's not global yet, so shim it here for the test run —
// src/utils/hash.js itself relies on the always-present browser global.
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import { sha1Hex, sha256Hex, sha384Hex, sha512Hex } from "../src/utils/hash.js";

test("sha256Hex matches a known digest", async () => {
  // echo -n "hello" | sha256sum
  assert.equal(await sha256Hex("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
});

test("sha1Hex matches a known digest", async () => {
  assert.equal(await sha1Hex("hello"), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
});

test("sha384Hex and sha512Hex produce hex strings of the expected length", async () => {
  assert.equal((await sha384Hex("hello")).length, 96);
  assert.equal((await sha512Hex("hello")).length, 128);
});

test("hashing the empty string doesn't throw and is stable", async () => {
  const a = await sha256Hex("");
  const b = await sha256Hex(undefined);
  assert.equal(a, b);
  assert.equal(a.length, 64);
});
