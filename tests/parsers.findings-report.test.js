import { test } from "node:test";
import assert from "node:assert/strict";
import { buildFindingsMarkdown } from "../src/parsers/findings-report.js";

const occ = (url) => ({ entry: { request: { url } } });
const groups = [
  { id: "missing-csp", severity: "info", title: "No CSP", detail: "d1", occurrences: [occ("https://a.test/"), occ("https://a.test/")] },
  { id: "sql", severity: "medium", title: "SQL error in response", detail: "Use `prepared` statements", occurrences: [occ("https://a.test/q?id=1'")] },
];

test("the report summarizes counts per severity and lists findings most severe first", () => {
  const md = buildFindingsMarkdown(groups, { generatedAt: new Date("2026-10-29T00:00:00Z"), version: "0.2.0" });
  assert.match(md, /Generated 2026-10-29T00:00:00.000Z by ZProxy 0.2.0/);
  assert.match(md, /\| Medium \| 1 \|/);
  assert.match(md, /\| Info \| 1 \|/);
  assert.ok(md.indexOf("## Medium: SQL error") < md.indexOf("## Info: No CSP"));
});

test("affected URLs are de-duplicated and markdown in titles/details is escaped", () => {
  const md = buildFindingsMarkdown(groups);
  assert.match(md, /Seen 2 time\(s\) on 1 URL\(s\)/);
  assert.match(md, /Use \\`prepared\\` statements/);
});

test("an empty report says so instead of rendering nothing", () => {
  assert.match(buildFindingsMarkdown([]), /No passive findings/);
});
