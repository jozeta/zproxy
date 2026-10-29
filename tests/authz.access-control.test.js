import { test } from "node:test";
import assert from "node:assert/strict";
import { applyIdentity, selectCandidates, isSafeMethod, UNAUTHENTICATED_IDENTITY } from "../src/authz/access-control.js";

const request = {
  method: "GET",
  url: "https://app.test/api/orders/7",
  headers: [
    { name: "Accept", value: "application/json" },
    { name: "Cookie", value: "session=admin" },
    { name: "Authorization", value: "Bearer admin-token" },
  ],
  body: "",
};

test("applyIdentity replaces exactly the headers the identity names, keeping the rest", () => {
  const out = applyIdentity(request, { headersText: "cookie: session=user\nX-Tenant: 2" });
  assert.deepEqual(out.headers, [
    { name: "Accept", value: "application/json" },
    { name: "Authorization", value: "Bearer admin-token" },
    { name: "cookie", value: "session=user" },
    { name: "X-Tenant", value: "2" },
  ]);
  assert.equal(request.headers.length, 3); // input not mutated
});

test("Unauthenticated keeps an empty Cookie line (so the browser's cookies are removed) and drops Authorization", () => {
  const out = applyIdentity(request, UNAUTHENTICATED_IDENTITY);
  assert.deepEqual(out.headers, [
    { name: "Accept", value: "application/json" },
    { name: "Cookie", value: "" },
  ]);
});

test("isSafeMethod accepts only GET/HEAD/OPTIONS, case-insensitively", () => {
  assert.deepEqual(["get", "HEAD", "Options", "POST", "DELETE", ""].map(isSafeMethod), [true, true, true, false, false, false]);
});

function entry(method, url, extra = {}) {
  return { status: "completed", type: "xmlhttprequest", request: { method, url, headers: [] }, response: { statusCode: 200 }, ...extra };
}

test("selectCandidates skips unsafe methods by default, static assets, errors, and missing responses", () => {
  const history = [
    entry("GET", "https://app.test/api/a"),
    entry("POST", "https://app.test/api/b"),
    entry("GET", "https://app.test/logo.png", { type: "image" }),
    entry("GET", "https://app.test/api/c", { status: "error" }),
    entry("GET", "https://app.test/api/d", { response: null }),
  ];
  assert.deepEqual(selectCandidates(history).map((e) => e.request.url), ["https://app.test/api/a"]);
  assert.deepEqual(selectCandidates(history, { includeUnsafe: true }).map((e) => e.request.method), ["GET", "POST"]);
});

test("selectCandidates de-duplicates by method + URL (fragment ignored), keeping the newest capture", () => {
  const older = entry("GET", "https://app.test/api/a#x", { id: "old" });
  const newer = entry("GET", "https://app.test/api/a", { id: "new" });
  assert.deepEqual(selectCandidates([older, newer]).map((e) => e.id), ["new"]);
});

test("selectCandidates narrows by a case-insensitive URL substring", () => {
  const history = [entry("GET", "https://app.test/API/admin"), entry("GET", "https://app.test/public")];
  assert.equal(selectCandidates(history, { urlContains: " /api/ " }).length, 1);
});
