import { test } from "node:test";
import assert from "node:assert/strict";
import { checkResponse } from "../src/parsers/passive-checks.js";

const H = (pairs) => pairs.map(([name, value]) => ({ name, value }));
const req = (url = "https://app.example.com/", headers = [], body = "") => ({ method: "GET", url, headers: H(headers), body });
const res = (headers = [], body = "", statusCode = 200) => ({ statusCode, headers: H(headers), body });
const ids = (r, s) => checkResponse(r, s).map((f) => f.id);
const has = (r, s, id) => ids(r, s).includes(id);
const sev = (r, s, id) => checkResponse(r, s).find((f) => f.id === id)?.severity;

// --- cookies ---

test("cookies: parent-domain scoping, broken prefixes, invalid SameSite, framework fingerprints", () => {
  assert.ok(has(req(), res([["Set-Cookie", "sid=1; Domain=.example.com; Secure; HttpOnly; SameSite=Lax"]]), "cookie-loosely-scoped"));
  assert.ok(!has(req(), res([["Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"]]), "cookie-loosely-scoped"));
  assert.ok(has(req(), res([["Set-Cookie", "__Host-sid=1; Secure; Path=/; Domain=example.com"]]), "cookie-prefix-violation"));
  assert.ok(!has(req(), res([["Set-Cookie", "__Host-sid=1; Secure; Path=/; HttpOnly; SameSite=Strict"]]), "cookie-prefix-violation"));
  assert.ok(has(req(), res([["Set-Cookie", "a=1; Secure; SameSite=Sometimes"]]), "cookie-samesite-invalid"));
  assert.match(checkResponse(req(), res([["Set-Cookie", "PHPSESSID=x; Secure; HttpOnly"]])).find((f) => f.id === "framework-cookie-fingerprint").detail, /PHP/);
});

test("cookies: readable role data and stored passwords", () => {
  const roleCookie = Buffer.from('{"user_id":7,"role":"customer"}').toString("base64");
  assert.ok(has(req(), res([["Set-Cookie", `profile=${roleCookie}; Secure; HttpOnly; SameSite=Lax`]]), "client-side-state-cookie"));
  assert.ok(has(req(), res([["Set-Cookie", "user_password=hunter2; Secure; HttpOnly"]]), "password-in-cookie"));
});

// --- headers ---

test("headers: legacy XSS filter, deprecated headers, invalid X-Frame-Options and nosniff values", () => {
  assert.ok(has(req(), res([["X-XSS-Protection", "1; mode=block"]]), "x-xss-protection-enabled"));
  assert.ok(!has(req(), res([["X-XSS-Protection", "0"]]), "x-xss-protection-enabled"));
  assert.ok(has(req(), res([["Public-Key-Pins", "pin-sha256=\"x\"; max-age=10"]]), "deprecated-security-headers"));
  assert.ok(has(req(), res([["X-Frame-Options", "ALLOW-FROM https://a.test"]]), "xfo-invalid"));
  assert.ok(has(req(), res([["X-Frame-Options", "DENY"], ["X-Frame-Options", "SAMEORIGIN"]]), "xfo-duplicate"));
  assert.ok(has(req(), res([["X-Content-Type-Options", "nosniff, nosniff"]]), "xcto-invalid"));
});

test("headers: CSP hosts with known bypasses, debug headers, and disclosure headers", () => {
  const csp = res([["Content-Security-Policy", "script-src 'self' https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'self'"]]);
  assert.ok(has(req(), csp, "csp-bypass-host"));
  assert.ok(!has(req(), res([["Content-Security-Policy", "script-src 'self'; object-src 'none'"]]), "csp-bypass-host"));
  assert.equal(sev(req(), res([["X-Debug-Token-Link", "https://app.example.com/_profiler/abc123"]]), "debug-headers-exposed"), "medium");
  assert.equal(sev(req(), res([["X-AspNet-Version", "4.0.30319"]]), "tech-disclosure-header"), "low"); // versioned
  assert.equal(sev(req(), res([["X-Backend-Server", "web-07"]]), "tech-disclosure-header"), "info");
  assert.ok(has(req(), res([["X-Powered-By", "Express"]]), "x-powered-by-disclosure"));
});

test("headers: authenticated responses from a shared cache, and logout without Clear-Site-Data", () => {
  const authed = req("https://app.example.com/account", [["Cookie", "sid=1"]]);
  assert.ok(has(authed, res([["Age", "42"]]), "served-from-shared-cache"));
  assert.ok(has(authed, res([["X-Cache", "HIT from edge-03"]]), "served-from-shared-cache"));
  assert.ok(!has(req("https://app.example.com/account"), res([["Age", "42"]]), "served-from-shared-cache"));
  assert.ok(has(req("https://app.example.com/auth/logout"), res(), "logout-no-clear-site-data"));
  assert.ok(!has(req("https://app.example.com/auth/logout"), res([["Clear-Site-Data", '"cookies"']]), "logout-no-clear-site-data"));
});

// --- request ---

test("request: secrets leaked via Referer to another site, session IDs in the path", () => {
  const leak = req("https://cdn.other.test/img.png", [["Referer", "https://app.example.com/reset?token=abc123"]]);
  assert.ok(has(leak, res(), "sensitive-data-in-referer"));
  assert.ok(!has(req("https://app.example.com/x", [["Referer", "https://app.example.com/reset?token=abc123"]]), res(), "sensitive-data-in-referer"));
  assert.ok(has(req("https://app.example.com/cart;jsessionid=0123456789ABCDEF"), res(), "session-id-in-url-path"));
});

test("request: JWTs without expiry or with sensitive claims", () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const token = (payload) => `${b64({ alg: "HS256" })}.${b64(payload)}.sig`;
  assert.ok(has(req("https://app.example.com/", [["Authorization", `Bearer ${token({ sub: "ada" })}`]]), res(), "jwt-no-expiry"));
  assert.ok(!has(req("https://app.example.com/", [["Authorization", `Bearer ${token({ sub: "ada", exp: 2e9 })}`]]), res(), "jwt-no-expiry"));
  assert.equal(sev(req("https://app.example.com/", [["Authorization", `Bearer ${token({ sub: "ada", exp: 2e9, password: "x" })}`]]), res(), "jwt-sensitive-claims"), "medium");
});

// --- HTML ---

const page = (body, url = "https://app.example.com/") => [req(url), res([["Content-Type", "text/html; charset=utf-8"]], body)];

test("HTML: POST forms without CSRF tokens, password forms over HTTP", () => {
  assert.ok(has(...page('<form method="post" action="/transfer"><input name="amount"></form>'), "form-without-csrf-token"));
  assert.ok(!has(...page('<form method="post"><input type="hidden" name="csrf_token" value="x"><input name="amount"></form>'), "form-without-csrf-token"));
  assert.ok(!has(...page('<form method="get"><input name="q"></form>'), "form-without-csrf-token"));
  assert.equal(sev(...page('<form method="post"><input type="password" name="pw"><input type="hidden" name="_token"></form>', "http://app.example.com/login"), "password-form-over-http"), "high");
});

test("HTML: third-party scripts without SRI, and known-compromised script domains", () => {
  assert.ok(has(...page('<script src="https://cdn.thirdparty.test/lib.js"></script>'), "third-party-script-no-sri"));
  assert.ok(!has(...page('<script src="https://cdn.thirdparty.test/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>'), "third-party-script-no-sri"));
  assert.ok(!has(...page('<script src="https://static.example.com/app.js"></script>'), "third-party-script-no-sri")); // same site
  assert.equal(sev(...page('<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>'), "compromised-script-domain"), "high");
});

test("HTML: generator meta tags, suspicious comments, rel=opener, unencrypted JSF ViewState", () => {
  assert.equal(sev(...page('<meta name="generator" content="WordPress 6.1.1">'), "generator-meta-disclosure"), "low");
  assert.ok(has(...page("<!-- TODO: remove debug login admin/admin -->"), "suspicious-html-comments"));
  assert.ok(!has(...page("<!-- main navigation -->"), "suspicious-html-comments"));
  assert.ok(has(...page('<a href="https://x.test" target="_blank" rel="opener">x</a>'), "reverse-tabnabbing"));
  assert.ok(has(...page('<input type="hidden" name="javax.faces.ViewState" value="rO0ABXNyAAAA">'), "jsf-viewstate-unprotected"));
});

// --- scripts ---

const script = (body, url = "https://app.example.com/static/app.js") => [req(url), res([["Content-Type", "application/javascript"]], body)];

test("scripts: DOM XSS source+sink, postMessage without an origin check, source maps", () => {
  const sink = ["el", "inner" + "HTML"].join("."); // assembled so this file has no literal sink name either
  assert.ok(has(...script(`var q = location.hash.slice(1); ${sink} = q;`), "dom-xss-source-sink"));
  assert.ok(!has(...script(`var q = location.hash.slice(1); el.textContent = q;`), "dom-xss-source-sink"));
  assert.ok(has(...script(`window.addEventListener("message", function (e) { run(e.data); });`), "postmessage-no-origin-check"));
  assert.ok(!has(...script(`window.addEventListener("message", function (e) { if (e.origin !== "https://a.test") return; run(e.data); });`), "postmessage-no-origin-check"));
  assert.ok(has(...script("var a=1;\n//# sourceMappingURL=app.js.map"), "source-map-exposed"));
});

test("scripts: vulnerable libraries are reported by version with their CVEs", () => {
  const f = checkResponse(...script("/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */"));
  const jq = f.find((x) => x.id === "vulnerable-js-jquery");
  assert.equal(jq.title, "Vulnerable JavaScript library: jQuery 1.12.4");
  assert.match(jq.detail, /CVE-2015-9251/);
  assert.match(jq.detail, /Fixed in 3\.5\.0/);
  assert.ok(!has(...script("/*! jQuery v3.7.1 | (c) OpenJS Foundation */"), "vulnerable-js-jquery"));
});

// --- detailed error messages ---

test("detailed errors: dangerous debug pages are high severity", () => {
  assert.equal(sev(req(), res([], "<h1>Werkzeug Debugger</h1> The debugger caught an exception in your WSGI application.", 500), "error-disclosure-werkzeug-debugger"), "high");
  assert.equal(sev(req(), res([], "You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.", 500), "error-disclosure-django-debug-page"), "high");
  assert.equal(sev(req(), res([], "Illuminate\\Database\\QueryException ... vendor/laravel/framework/src/Illuminate/Database", 500), "error-disclosure-laravel-debug-page"), "high");
});

test("detailed errors: ASP.NET yellow screen, template engines, NoSQL, Go panics, path disclosure", () => {
  assert.ok(has(req(), res([], "<h1>Server Error in '/' Application.</h1><b> Exception Details: </b>System.NullReferenceException", 500), "error-disclosure-asp-net-detailed-error"));
  assert.ok(has(req(), res([], "jinja2.exceptions.UndefinedError: 'user' is undefined", 500), "error-disclosure-template-engine-error"));
  assert.ok(has(req(), res([], "MongoServerError: E11000 duplicate key error collection: app.users", 500), "error-disclosure-nosql-error"));
  assert.ok(has(req(), res([], "panic: runtime error: index out of range\n\ngoroutine 1 [running]:", 500), "error-disclosure-go-panic"));
  assert.ok(has(req(), res([], "Warning: include(): Failed opening '/var/www/html/includes/config.php'", 500), "error-disclosure-full-path-disclosure"));
  assert.equal(checkResponse(req(), res([["Content-Type", "text/plain"], ["Strict-Transport-Security", "max-age=63072000; includeSubDomains"]], "Everything is fine.")).length, 0);
});

// --- information leakage ---

test("information leakage: phpinfo, server-status, Spring Actuator, exposed .git and .env", () => {
  assert.ok(has(req("https://app.example.com/info.php"), res([], "<title>phpinfo()</title><tr><td>PHP Version </td>"), "phpinfo-exposed"));
  assert.ok(has(req("https://app.example.com/server-status"), res([], "<h1>Apache Server Status for app.example.com</h1>"), "server-status-exposed"));
  assert.equal(sev(req("https://app.example.com/actuator/env"), res([], '{"activeProfiles":["prod"],"propertySources":[]}'), "spring-actuator-exposed"), "high");
  assert.equal(sev(req("https://app.example.com/.git/HEAD"), res([], "ref: refs/heads/main\n"), "exposed-git"), "high");
  assert.equal(sev(req("https://app.example.com/.env"), res([], "APP_KEY=base64:abc\nDB_PASSWORD=secret\n"), "exposed-env-file"), "high");
  assert.ok(!has(req("https://app.example.com/.git/HEAD"), res([], "Not found", 404), "exposed-git"));
});

test("information leakage: internal hostnames, in-page server banners, hashes, cards, serialized objects", () => {
  assert.ok(has(req(), res([], "upstream db-primary.corp timed out"), "internal-hostname-disclosure"));
  assert.ok(has(req(), res([], "connect to ip-10-0-3-17.ec2.internal failed"), "internal-hostname-disclosure"));
  assert.ok(!has(...script("this.config.internal = true;"), "internal-hostname-disclosure"));
  assert.ok(has(req(), res([], "<address>Apache/2.4.41 (Ubuntu) Server at app.example.com Port 443</address>", 404), "in-page-server-banner"));
  assert.ok(has(req(), res([], '{"hash":"$2y$10$abcdefghijklmnopqrstuuJ8Rl5mZbE3V9n1cX6eQm2zW0yRk4Kq."}'), "password-hash-disclosed"));
  assert.ok(has(req(), res([], "card on file: 4111 1111 1111 1111"), "credit-card-disclosed"));
  assert.ok(!has(req(), res([], "order 4111 1111 1111 1112"), "credit-card-disclosed")); // fails Luhn
  assert.ok(has(req(), res([], '{"state":"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"}'), "java-serialized-object"));
  assert.ok(has(req(), res([], '{"__schema":{"queryType":{"name":"Query"},"types":[]}}'), "graphql-introspection"));
});

test("information leakage: emails are reported but placeholder domains are ignored", () => {
  assert.ok(has(req(), res([], "Contact jane.doe@acme-corp.test"), "email-disclosed"));
  assert.ok(!has(req(), res([], "e.g. you@example.com"), "email-disclosed"));
});
