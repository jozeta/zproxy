import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCookieHeader, serializeCookieHeader, parseSetCookie, parseAllSetCookies } from "../src/parsers/cookies.js";

test("parseCookieHeader splits name=value pairs", () => {
  assert.deepEqual(parseCookieHeader("a=1; b=2; c=3"), [
    { name: "a", value: "1" },
    { name: "b", value: "2" },
    { name: "c", value: "3" },
  ]);
});

test("parseCookieHeader handles empty input and values containing '='", () => {
  assert.deepEqual(parseCookieHeader(""), []);
  assert.deepEqual(parseCookieHeader("token=a=b=c"), [{ name: "token", value: "a=b=c" }]);
});

test("serializeCookieHeader round-trips with parseCookieHeader", () => {
  const cookies = [{ name: "a", value: "1" }, { name: "b", value: "2" }];
  assert.equal(serializeCookieHeader(cookies), "a=1; b=2");
  assert.deepEqual(parseCookieHeader(serializeCookieHeader(cookies)), cookies);
});

test("parseSetCookie extracts name/value and known attributes", () => {
  const cookie = parseSetCookie("session=abc123; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict");
  assert.equal(cookie.name, "session");
  assert.equal(cookie.value, "abc123");
  assert.equal(cookie.domain, "example.com");
  assert.equal(cookie.path, "/");
  assert.equal(cookie.secure, true);
  assert.equal(cookie.httpOnly, true);
  assert.equal(cookie.sameSite, "Strict");
});

test("parseSetCookie handles Max-Age and Expires", () => {
  const cookie = parseSetCookie("id=1; Max-Age=3600; Expires=Wed, 09 Jun 2027 10:18:14 GMT");
  assert.equal(cookie.maxAge, 3600);
  assert.equal(cookie.expires, "Wed, 09 Jun 2027 10:18:14 GMT");
});

test("parseSetCookie returns null for malformed input", () => {
  assert.equal(parseSetCookie(""), null);
  assert.equal(parseSetCookie("no-equals-sign"), null);
});

test("parseAllSetCookies collects every Set-Cookie header, case-insensitively", () => {
  const headers = [
    { name: "Set-Cookie", value: "a=1" },
    { name: "set-cookie", value: "b=2" },
    { name: "Content-Type", value: "text/html" },
  ];
  const cookies = parseAllSetCookies(headers);
  assert.equal(cookies.length, 2);
  assert.deepEqual(cookies.map((c) => c.name), ["a", "b"]);
});
