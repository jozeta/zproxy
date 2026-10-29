import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAdvanced, cspScriptWeaknesses, parseCsp } from "../src/parsers/passive-checks-advanced.js";

const NOW = Date.parse("2026-10-29T12:00:00Z");
const https = { isHttps: true, html: false, now: NOW };
const ids = (fs) => fs.map((f) => f.id);
const res = (headers, extra = {}) => ({ statusCode: 200, headers: headers.map(([name, value]) => ({ name, value })), body: "", ...extra });
const req = (url = "https://app.test/", headers = [], body = "") => ({ method: "GET", url, headers: headers.map(([name, value]) => ({ name, value })), body });

test("parseCsp keeps the first occurrence of each directive", () => {
  assert.deepEqual(parseCsp("script-src 'self'; script-src *").get("script-src"), ["'self'"]);
});

test("cspScriptWeaknesses flags unsafe-inline (unless a nonce/hash is present), unsafe-eval, and wildcards", () => {
  assert.equal(cspScriptWeaknesses("default-src 'self'").length, 0);
  assert.equal(cspScriptWeaknesses("script-src 'self' 'unsafe-inline'").length, 1);
  assert.equal(cspScriptWeaknesses("script-src 'self' 'unsafe-inline' 'nonce-abc'").length, 0);
  assert.equal(cspScriptWeaknesses("script-src 'unsafe-eval' https:").length, 2);
  assert.equal(cspScriptWeaknesses("img-src *").length, 1); // no script policy at all
});

test("a short HSTS max-age is flagged; a year is not", () => {
  assert.ok(ids(checkAdvanced(req(), res([["Strict-Transport-Security", "max-age=3600"]]), https)).includes("weak-hsts"));
  assert.ok(!ids(checkAdvanced(req(), res([["Strict-Transport-Security", "max-age=31536000"]]), https)).includes("weak-hsts"));
});

test("CORS echoing a cross-site Origin with credentials is flagged, but a same-origin echo is not", () => {
  const cors = (origin) => res([["Access-Control-Allow-Origin", origin], ["Access-Control-Allow-Credentials", "true"]]);
  assert.ok(ids(checkAdvanced(req("https://app.test/api", [["Origin", "https://evil.test"]]), cors("https://evil.test"), https)).includes("cors-reflected-origin"));
  assert.ok(!ids(checkAdvanced(req("https://app.test/api", [["Origin", "https://app.test"]]), cors("https://app.test"), https)).includes("cors-reflected-origin"));
  assert.ok(ids(checkAdvanced(req(), cors("null"), https)).includes("cors-null-origin"));
});

test("an authenticated 200 without no-store/private is flagged as cacheable", () => {
  const authed = req("https://app.test/me", [["Authorization", "Bearer x"]]);
  assert.ok(ids(checkAdvanced(authed, res([["Cache-Control", "max-age=600"]]), https)).includes("cacheable-sensitive-response"));
  assert.ok(!ids(checkAdvanced(authed, res([["Cache-Control", "private, max-age=600"]]), https)).includes("cacheable-sensitive-response"));
  assert.ok(!ids(checkAdvanced(req(), res([["Cache-Control", "max-age=600"]]), https)).includes("cacheable-sensitive-response"));
});

test("JSON labelled text/html and a body with no Content-Type are flagged", () => {
  assert.ok(ids(checkAdvanced(req(), res([["Content-Type", "text/html"]], { body: '{"name":"<b>x</b>"}' }), https)).includes("json-served-as-html"));
  assert.ok(!ids(checkAdvanced(req(), res([["Content-Type", "text/html"]], { body: "{not json}" }), https)).includes("json-served-as-html"));
  assert.ok(ids(checkAdvanced(req(), res([], { body: "hello" }), https)).includes("missing-content-type"));
});

test("a long-lived session-like cookie is flagged; a short one or a non-session name is not", () => {
  const long = res([["Set-Cookie", "session=1; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax"]]);
  const short = res([["Set-Cookie", "session=1; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"]]);
  const prefs = res([["Set-Cookie", "theme=dark; Expires=Wed, 01 Jan 2031 00:00:00 GMT"]]);
  assert.ok(ids(checkAdvanced(req(), long, https)).includes("long-lived-session-cookie"));
  assert.ok(!ids(checkAdvanced(req(), short, https)).includes("long-lived-session-cookie"));
  assert.ok(!ids(checkAdvanced(req(), prefs, https)).includes("long-lived-session-cookie"));
});

test("SameSite=None without Secure is flagged", () => {
  assert.ok(ids(checkAdvanced(req(), res([["Set-Cookie", "a=1; SameSite=None"]]), https)).includes("cookie-samesite-none-insecure"));
});

test("secrets in the query string are flagged; ordinary parameters are not", () => {
  assert.ok(ids(checkAdvanced(req("https://app.test/cb?access_token=abc&page=2"), res([]), https)).includes("sensitive-data-in-url"));
  assert.ok(!ids(checkAdvanced(req("https://app.test/list?page=2&sort=name"), res([]), https)).includes("sensitive-data-in-url"));
});

test("Basic auth and passwords over plain HTTP are high severity; over HTTPS they're not flagged", () => {
  const basic = req("http://app.test/", [["Authorization", "Basic dTpw"]]);
  const login = req("http://app.test/login", [], "user=bob&password=hunter2");
  const http = { isHttps: false, html: false, now: NOW };
  assert.ok(ids(checkAdvanced(basic, res([]), http)).includes("basic-auth-over-http"));
  assert.equal(checkAdvanced(login, res([]), http).find((f) => f.id === "password-over-http").severity, "high");
  assert.ok(!ids(checkAdvanced({ ...login, url: "https://app.test/login" }, res([]), https)).includes("password-over-http"));
});

test("a JWT declaring alg none is flagged wherever it appears", () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const none = `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: "1" })}.`;
  const hs = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "1" })}.sig`;
  assert.ok(ids(checkAdvanced(req("https://app.test/", [["Authorization", `Bearer ${none}`]]), res([]), https)).includes("jwt-alg-none"));
  assert.ok(ids(checkAdvanced(req(), res([], { body: `{"token":"${none}"}` }), https)).includes("jwt-alg-none"));
  assert.ok(!ids(checkAdvanced(req("https://app.test/", [["Authorization", `Bearer ${hs}`]]), res([]), https)).includes("jwt-alg-none"));
});

test("SQL errors and stack traces in the body are flagged by kind", () => {
  const sql = checkAdvanced(req(), res([], { body: "You have an error in your SQL syntax; check the manual" }), https);
  assert.equal(sql.find((f) => f.id === "error-disclosure-sql-error").severity, "medium");
  assert.ok(ids(checkAdvanced(req(), res([], { body: "Traceback (most recent call last):\n  File x" }), https)).includes("error-disclosure-python-traceback"));
  assert.ok(ids(checkAdvanced(req(), res([], { body: "\tat com.acme.Foo.bar(Foo.java:42)" }), https)).includes("error-disclosure-java-stack-trace"));
  assert.equal(checkAdvanced(req(), res([["Content-Type", "text/plain"]], { body: "All good." }), https).length, 0);
});

test("directory listings and internal IPs are flagged — internal IPs only when the target itself is public", () => {
  assert.ok(ids(checkAdvanced(req(), res([], { body: "<title>Index of /backup</title>" }), https)).includes("directory-listing"));
  assert.ok(ids(checkAdvanced(req(), res([], { body: "upstream 10.0.3.17 timed out" }), https)).includes("private-ip-disclosure"));
  assert.ok(!ids(checkAdvanced(req("http://192.168.1.5/"), res([], { body: "host 192.168.1.5" }), { isHttps: false, now: NOW })).includes("private-ip-disclosure"));
});

test("HTTPS HTML pages loading http:// scripts or posting forms to http:// are flagged", () => {
  const html = { isHttps: true, html: true, now: NOW };
  const hdrs = [["Content-Type", "text/html"], ["Referrer-Policy", "no-referrer"]];
  assert.ok(ids(checkAdvanced(req(), res(hdrs, { body: '<script src="http://cdn.test/a.js"></script>' }), html)).includes("mixed-content"));
  assert.ok(ids(checkAdvanced(req(), res(hdrs, { body: '<form method="post" action="http://app.test/login">' }), html)).includes("insecure-form-action"));
  assert.ok(!ids(checkAdvanced(req(), res(hdrs, { body: '<script src="https://cdn.test/a.js"></script>' }), html)).includes("mixed-content"));
});

test("a redirect to another host taken from a query parameter is an open-redirect candidate", () => {
  const redirect = (location) => res([["Location", location]], { statusCode: 302 });
  assert.ok(ids(checkAdvanced(req("https://app.test/go?next=https://evil.test/x"), redirect("https://evil.test/x"), https)).includes("open-redirect-candidate"));
  assert.ok(!ids(checkAdvanced(req("https://app.test/go?next=/home"), redirect("https://app.test/home"), https)).includes("open-redirect-candidate"));
  assert.ok(!ids(checkAdvanced(req("https://app.test/login"), redirect("https://sso.test/auth"), https)).includes("open-redirect-candidate"));
});
