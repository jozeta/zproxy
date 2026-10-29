import { test } from "node:test";
import assert from "node:assert/strict";
import { scopeIsDefined, summarizeFindings, badgeFor, createFindingsMonitor } from "../src/background/findings-monitor.js";

test("a scope is defined when it has at least one non-blank Include pattern", () => {
  assert.equal(scopeIsDefined({ enabled: true, include: ["a.test"] }), true);
  assert.equal(scopeIsDefined({ enabled: false, include: ["a.test"] }), true);
  assert.equal(scopeIsDefined({ enabled: true, include: ["  "] }), false);
  assert.equal(scopeIsDefined(null), false);
});

test("summarizeFindings counts distinct kinds of finding at their worst severity", () => {
  const byEntry = {
    a: [{ id: "cookie-missing-httponly", severity: "low" }, { id: "missing-csp", severity: "info" }],
    b: [{ id: "cookie-missing-httponly", severity: "medium" }],
    c: [{ id: "secret-aws-access-key", severity: "high" }, { id: "missing-csp", severity: "info" }],
  };
  const summary = summarizeFindings(["a", "b", "c"], (e) => byEntry[e]);
  assert.deepEqual(summary, { high: 1, medium: 1, low: 0, info: 1 });
});

test("the toolbar badge shows high + medium, red when anything is high, and nothing without a scope", () => {
  assert.deepEqual(badgeFor({ high: 1, medium: 2, low: 5, info: 9 }, true).text, "3");
  assert.equal(badgeFor({ high: 1, medium: 0, low: 0, info: 0 }, true).color, "#bf616a");
  assert.equal(badgeFor({ high: 0, medium: 2, low: 0, info: 0 }, true).color, "#d08770");
  assert.equal(badgeFor({ high: 0, medium: 0, low: 7, info: 3 }, true).text, "");
  assert.equal(badgeFor({ high: 4, medium: 4, low: 0, info: 0 }, false).text, "");
  assert.equal(badgeFor({ high: 150, medium: 0, low: 0, info: 0 }, true).text, "99+");
});

test("the monitor reports a summary only while a scope is defined, and notifies on change", async () => {
  const entry = { id: "1", startedAt: 1, request: { url: "http://a.test/", headers: [] }, response: { statusCode: 200, headers: [{ name: "Set-Cookie", value: "session=x" }] } };
  let scope = { enabled: true, include: ["a.test"] };
  const changes = [];
  const monitor = createFindingsMonitor({ getHistory: async () => [entry], getScope: async () => scope, onChange: (s) => changes.push(s) });
  monitor.schedule(0);
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(monitor.summary().active, true);
  assert.equal(monitor.summary().high, 1); // cookie set over plain HTTP
  scope = { enabled: true, include: [] };
  monitor.schedule(0);
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(monitor.summary(), { high: 0, medium: 0, low: 0, info: 0, active: false });
  assert.equal(changes.length, 2);
});
