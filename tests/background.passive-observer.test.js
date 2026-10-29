import { test } from "node:test";
import assert from "node:assert/strict";
import { shouldObserve } from "../src/background/passive-observer.js";

const scope = { enabled: true, include: ["*.shop.example"], exclude: ["shop.example/logout"] };
const on = { captureBodiesWithoutIntercept: true };

test("in-scope web pages are observed when the setting is on", () => {
  assert.equal(shouldObserve("https://www.shop.example/cart", scope, on), true);
});

test("nothing is observed with the setting off, no scope, Scope disabled, or out of scope", () => {
  assert.equal(shouldObserve("https://www.shop.example/", scope, { captureBodiesWithoutIntercept: false }), false);
  assert.equal(shouldObserve("https://www.shop.example/", { enabled: true, include: [] }, on), false);
  assert.equal(shouldObserve("https://www.shop.example/", { ...scope, enabled: false }, on), false);
  assert.equal(shouldObserve("https://other.example/", scope, on), false);
  assert.equal(shouldObserve("https://shop.example/logout", scope, on), false);
});

test("non-web pages are never observed (Chrome refuses to debug them anyway)", () => {
  for (const url of ["chrome://settings", "chrome-extension://abc/page.html", "file:///tmp/x.html", "", undefined]) {
    assert.equal(shouldObserve(url, { enabled: true, include: ["*"] }, on), false, String(url));
  }
});
