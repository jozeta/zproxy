import { test } from "node:test";
import assert from "node:assert/strict";
import { isJwtLike, decodeJwt, extractBearerToken, findJwtInHeaders } from "../src/parsers/jwt.js";

function makeJwt(header, payload, signature = "sig") {
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  return `${b64url(header)}.${b64url(payload)}.${signature}`;
}

test("isJwtLike accepts a well-formed 3-part token", () => {
  assert.equal(isJwtLike(makeJwt({ alg: "HS256" }, { sub: "1" })), true);
});

test("isJwtLike rejects non-strings and malformed tokens", () => {
  assert.equal(isJwtLike(null), false);
  assert.equal(isJwtLike("only.two"), false);
  assert.equal(isJwtLike("has spaces.in.it"), false);
});

test("decodeJwt decodes header and payload, and never claims a verified signature", () => {
  const token = makeJwt({ alg: "HS256", typ: "JWT" }, { sub: "user-1", admin: true });
  const result = decodeJwt(token);
  assert.equal(result.ok, true);
  assert.deepEqual(result.header, { alg: "HS256", typ: "JWT" });
  assert.deepEqual(result.payload, { sub: "user-1", admin: true });
  assert.equal(result.signatureVerified, false);
  assert.match(result.warning, /not.*verified/i);
});

test("decodeJwt fails cleanly on a non-3-part token", () => {
  const result = decodeJwt("not-a-jwt");
  assert.equal(result.ok, false);
  assert.match(result.error, /3-part/);
});

test("decodeJwt fails cleanly on garbage base64 segments", () => {
  const result = decodeJwt("!!!.???.sig");
  assert.equal(result.ok, false);
});

test("extractBearerToken pulls the token out of an Authorization value", () => {
  assert.equal(extractBearerToken("Bearer abc.def.ghi"), "abc.def.ghi");
  assert.equal(extractBearerToken("bearer abc.def.ghi"), "abc.def.ghi");
  assert.equal(extractBearerToken("Basic dXNlcjpwYXNz"), null);
  assert.equal(extractBearerToken(""), null);
});

test("findJwtInHeaders locates and decodes a bearer JWT among headers", () => {
  const token = makeJwt({ alg: "none" }, { sub: "x" });
  const headers = [
    { name: "Accept", value: "*/*" },
    { name: "Authorization", value: `Bearer ${token}` },
  ];
  const result = findJwtInHeaders(headers);
  assert.ok(result?.ok);
  assert.equal(result.payload.sub, "x");
});

test("findJwtInHeaders returns null when there is no bearer JWT", () => {
  assert.equal(findJwtInHeaders([{ name: "Accept", value: "*/*" }]), null);
  assert.equal(findJwtInHeaders([{ name: "Authorization", value: "Bearer not-a-jwt" }]), null);
});
