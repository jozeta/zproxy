import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const dnrCalls = [];
let activeRules = new Map();
globalThis.chrome = {
  declarativeNetRequest: {
    updateSessionRules: async ({ addRules = [], removeRuleIds = [] }) => {
      dnrCalls.push({ addRules, removeRuleIds });
      for (const id of removeRuleIds) activeRules.delete(id);
      for (const r of addRules) activeRules.set(r.id, r);
    },
  },
};
let fetchLog = [];
let fetchImpl = async () => new Response("ok", { status: 200 });
globalThis.fetch = async (url, init) => {
  fetchLog.push({ url, init, rulesDuringFetch: [...activeRules.values()] });
  return fetchImpl(url, init);
};

const { headerOverrides, buildOverrideRule, sendRequest, sendRequestGroup } = await import("../src/ui/components/http-send.js");

beforeEach(() => {
  dnrCalls.length = 0;
  activeRules = new Map();
  fetchLog = [];
  fetchImpl = async () => new Response("ok", { status: 200 });
});

const req = (headers, overrides = {}) => ({ method: "GET", url: "https://lab.test/api/me?x=1#frag", headers, body: "", ...overrides });

test("headerOverrides picks only Cookie/Origin/Referer, case-insensitively, last value winning", () => {
  const o = headerOverrides([
    { name: "Cookie", value: "a=1" },
    { name: "Accept", value: "*/*" },
    { name: "ORIGIN", value: "https://evil.test" },
    { name: "cookie", value: "b=2" },
    { name: "Host", value: "x" },
  ]);
  assert.deepEqual(o, [
    { name: "cookie", value: "b=2" },
    { name: "origin", value: "https://evil.test" },
  ]);
});

test("buildOverrideRule pins the rule to the exact URL (no fragment), method, and non-tab requests", () => {
  const rule = buildOverrideRule(900001, req([]), [{ name: "origin", value: "https://evil.test" }]);
  assert.equal(rule.condition.urlFilter, "|https://lab.test/api/me?x=1|");
  assert.deepEqual(rule.condition.requestMethods, ["get"]);
  assert.deepEqual(rule.condition.tabIds, [-1]);
  assert.deepEqual(rule.action.requestHeaders, [{ header: "origin", operation: "set", value: "https://evil.test" }]);
  assert.equal(rule.action.responseHeaders, undefined);
});

test("an empty Cookie value removes the header, and any Cookie override strips Set-Cookie from the response", () => {
  const rule = buildOverrideRule(1, req([]), [{ name: "cookie", value: "" }]);
  assert.deepEqual(rule.action.requestHeaders, [{ header: "cookie", operation: "remove" }]);
  assert.deepEqual(rule.action.responseHeaders, [{ header: "set-cookie", operation: "remove" }]);
});

test("a URL containing urlFilter syntax characters gets an escaped, anchored regex instead", () => {
  const rule = buildOverrideRule(1, req([], { url: "https://lab.test/a*b|c" }), [{ name: "referer", value: "x" }]);
  assert.equal(rule.condition.urlFilter, undefined);
  // WHATWG URL parsing (also what fetch() uses) leaves * and | in a path as-is.
  assert.equal(new RegExp(rule.condition.regexFilter).test("https://lab.test/a*b|c"), true);
  assert.equal(new RegExp(rule.condition.regexFilter).test("https://lab.test/aXXb|c"), false);
});

test("non-standard methods map to DNR's 'other'", () => {
  assert.deepEqual(buildOverrideRule(1, req([], { method: "PROPFIND" }), [{ name: "cookie", value: "a" }]).condition.requestMethods, ["other"]);
});

test("sendRequest with no overridable headers never touches DNR", async () => {
  const result = await sendRequest(req([{ name: "Accept", value: "*/*" }]));
  assert.equal(result.ok, true);
  assert.equal(dnrCalls.length, 0);
});

test("sendRequest installs the override rule for the fetch only, then removes it", async () => {
  const result = await sendRequest(req([{ name: "Cookie", value: "session=user-b" }]));
  assert.equal(result.ok, true);
  assert.deepEqual(result.overriddenHeaders, ["cookie"]);
  assert.equal(fetchLog[0].rulesDuringFetch.length, 1);
  assert.equal(fetchLog[0].init.headers.has("cookie"), false); // never handed to fetch() itself
  assert.equal(activeRules.size, 0);
});

test("the override rule is removed even when the fetch fails", async () => {
  fetchImpl = async () => {
    throw new TypeError("Failed to fetch");
  };
  const result = await sendRequest(req([{ name: "Cookie", value: "a=1" }]));
  assert.equal(result.ok, false);
  assert.equal(activeRules.size, 0);
});

test("concurrent overridden sends to the same target never overlap their rules", async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  fetchImpl = async () => {
    await gate;
    return new Response("ok");
  };
  const a = sendRequest(req([{ name: "Cookie", value: "user=a" }]));
  const b = sendRequest(req([{ name: "Cookie", value: "user=b" }]));
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(fetchLog.length, 1); // b waits for a's rule to be gone
  release();
  await Promise.all([a, b]);
  assert.equal(fetchLog.length, 2);
  assert.equal(fetchLog[1].rulesDuringFetch.length, 1);
  assert.equal(fetchLog[1].rulesDuringFetch[0].action.requestHeaders[0].value, "user=b");
});

test("sendRequestGroup sends identical overridden requests concurrently under one shared rule", async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  fetchImpl = async () => {
    await gate;
    return new Response("ok");
  };
  const group = sendRequestGroup([1, 2, 3].map(() => req([{ name: "Cookie", value: "a=1" }], { method: "POST" })));
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(fetchLog.length, 3); // all in flight at once
  assert.equal(dnrCalls.filter((c) => c.addRules.length).length, 1);
  release();
  const results = await group;
  assert.equal(results.every((r) => r.ok), true);
  assert.equal(activeRules.size, 0);
});

test("sendRequest gives up after timeoutMs and says it timed out", async () => {
  fetchImpl = (_url, init) =>
    new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason)));
  const result = await sendRequest(req([]), { timeoutMs: 20 });
  assert.equal(result.ok, false);
  assert.equal(result.timedOut, true);
  assert.match(result.error, /Timed out/);
});

test("a successful response records whether redirects were followed and the final URL", async () => {
  fetchImpl = async () => {
    const r = new Response("ok");
    Object.defineProperty(r, "redirected", { value: true });
    Object.defineProperty(r, "url", { value: "https://lab.test/landing" });
    return r;
  };
  const result = await sendRequest(req([]));
  assert.equal(result.response.redirected, true);
  assert.equal(result.response.finalUrl, "https://lab.test/landing");
});
