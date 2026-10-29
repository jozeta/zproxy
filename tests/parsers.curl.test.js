import { test } from "node:test";
import assert from "node:assert/strict";
import { shellSplit, parseCurl } from "../src/parsers/curl.js";
import { requestToCurl } from "../src/parsers/http.js";

test("shellSplit handles single, double, ANSI-C quotes, escapes, and line continuations", () => {
  assert.deepEqual(shellSplit(`curl 'a b' "c \\"d\\"" $'e\\nf' g\\ h \\\n -k`), ["curl", "a b", 'c "d"', "e\nf", "g h", "-k"]);
  assert.throws(() => shellSplit("curl 'oops"), /Unterminated/);
});

test("parseCurl reads a Chrome 'Copy as cURL (bash)' command", () => {
  const cmd = `curl 'https://app.test/api/items?x=1' \\
  -H 'accept: application/json' \\
  -H 'content-type: application/json' \\
  -b 'session=abc; theme=dark' \\
  --data-raw $'{"name":"it\\'s"}' \\
  --compressed`;
  const r = parseCurl(cmd);
  assert.equal(r.method, "POST");
  assert.equal(r.url, "https://app.test/api/items?x=1");
  assert.deepEqual(r.headers, [
    { name: "accept", value: "application/json" },
    { name: "content-type", value: "application/json" },
    { name: "Cookie", value: "session=abc; theme=dark" },
  ]);
  assert.equal(r.body, `{"name":"it's"}`);
});

test("parseCurl infers the method, honours -X, and adds a form Content-Type for -d", () => {
  assert.equal(parseCurl("curl https://a.test/").method, "GET");
  assert.equal(parseCurl("curl -I https://a.test/").method, "HEAD");
  assert.equal(parseCurl("curl -X delete https://a.test/x").method, "DELETE");
  const form = parseCurl("curl -d a=1 -d b=2 a.test/login");
  assert.equal(form.url, "http://a.test/login");
  assert.equal(form.body, "a=1&b=2");
  assert.deepEqual(form.headers, [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }]);
});

test("parseCurl maps -u to Basic auth and skips flags that take a value it doesn't need", () => {
  const r = parseCurl("curl -u bob:pw -o out.html --max-time 5 https://a.test/");
  assert.equal(r.url, "https://a.test/");
  assert.deepEqual(r.headers, [{ name: "Authorization", value: `Basic ${btoa("bob:pw")}` }]);
});

test("parseCurl rejects things that aren't a curl command", () => {
  assert.throws(() => parseCurl("wget https://a.test"), /curl/);
  assert.throws(() => parseCurl("curl -k"), /No URL/);
});

test("requestToCurl output parses back to the same request", () => {
  const original = { method: "PUT", url: "https://a.test/p?q='x'", headers: [{ name: "X-Test", value: "it's" }], body: '{"a":"b c"}' };
  const back = parseCurl(requestToCurl(original));
  assert.equal(back.method, "PUT");
  assert.equal(back.url, original.url);
  assert.equal(back.body, original.body);
  assert.deepEqual(back.headers.find((h) => h.name === "X-Test"), { name: "X-Test", value: "it's" });
});
