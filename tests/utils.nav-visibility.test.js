import { test } from "node:test";
import assert from "node:assert/strict";
import { HIDEABLE_VIEWS, visibleViews } from "../src/utils/nav-visibility.js";
import { SETTINGS_DEFAULTS } from "../src/storage/settings.js";

const VIEWS = ["dashboard", "history", "findings", "intercept", "websockets", "repeater", "intruder", "access-control", "cookies", "decoder", "comparer", "match-replace", "scope", "settings"].map((id) => ({ id }));
const ids = (views) => views.map((v) => v.id);

test("exactly the eight requested views are hideable", () => {
  assert.deepEqual(ids(HIDEABLE_VIEWS), ["findings", "websockets", "access-control", "cookies", "decoder", "comparer", "match-replace", "scope"]);
});

test("by default WebSockets, Access Control, Decoder, Comparer, Match/Replace, and Scope are hidden", () => {
  assert.deepEqual(ids(visibleViews(VIEWS, SETTINGS_DEFAULTS.hiddenViews, "dashboard")), ["dashboard", "history", "findings", "intercept", "repeater", "intruder", "cookies", "settings"]);
});

test("a hidden view stays in the nav while it's the active one", () => {
  assert.ok(ids(visibleViews(VIEWS, ["decoder"], "decoder")).includes("decoder"));
  assert.ok(!ids(visibleViews(VIEWS, ["decoder"], "history")).includes("decoder"));
});

test("core views can never be hidden, even if settings name them", () => {
  assert.deepEqual(ids(visibleViews(VIEWS, ["dashboard", "history", "intercept", "repeater", "intruder", "settings", "bogus"], null)), ids(VIEWS));
});

test("no hidden list (or a missing one) shows everything", () => {
  assert.equal(visibleViews(VIEWS, undefined).length, VIEWS.length);
  assert.equal(visibleViews(VIEWS, []).length, VIEWS.length);
});

test("Scope is un-hidden on the change that first defines a scope — and only then", async () => {
  const { hiddenViewsAfterScopeChange } = await import("../src/utils/nav-visibility.js");
  assert.deepEqual(hiddenViewsAfterScopeChange(["decoder", "scope"], false, true), ["decoder"]);
  assert.equal(hiddenViewsAfterScopeChange(["decoder", "scope"], true, true), null); // already defined: re-hiding sticks
  assert.equal(hiddenViewsAfterScopeChange(["decoder", "scope"], false, false), null);
  assert.equal(hiddenViewsAfterScopeChange(["decoder"], false, true), null); // already visible
});
