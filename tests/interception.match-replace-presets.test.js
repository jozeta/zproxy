import { test } from "node:test";
import assert from "node:assert/strict";
import { testRule } from "../src/interception/match-replace.js";
import { MATCH_REPLACE_PRESETS } from "../src/interception/match-replace-presets.js";
import { toDnrRule, scopeToDnrDomains } from "../src/background/dnr-rules.js";

const preset = (id) => ({ enabled: false, ...MATCH_REPLACE_PRESETS.find((p) => p.id === id).rule });

test("testRule counts substring and regex replacements and shows the output", () => {
  assert.deepEqual(testRule({ matchType: "contains", match: "a", replace: "b" }, "banana"), { output: "bbnbnb", matches: 3, error: null });
  assert.deepEqual(testRule({ matchType: "regex", match: "n(a)", replace: "N$1" }, "banana"), { output: "baNaNa", matches: 2, error: null });
});

test("testRule reports an invalid regex and leaves the text untouched, as live traffic would", () => {
  const r = testRule({ matchType: "regex", match: "(", replace: "x" }, "abc");
  assert.equal(r.output, "abc");
  assert.equal(r.matches, 0);
  assert.ok(r.error);
});

test("testRule tests a rule even while it's disabled", () => {
  assert.equal(testRule({ enabled: false, matchType: "contains", match: "x", replace: "y" }, "x").output, "y");
});

test("preset ids are unique and every preset is complete", () => {
  assert.equal(new Set(MATCH_REPLACE_PRESETS.map((p) => p.id)).size, MATCH_REPLACE_PRESETS.length);
  for (const p of MATCH_REPLACE_PRESETS) {
    assert.ok(p.label && p.rule.name && ["static", "content"].includes(p.rule.engine), p.id);
  }
});

test("content presets rewrite realistic samples", () => {
  assert.equal(testRule(preset("unhide-fields"), `<input type="hidden" name="role"><input type='hidden'>`).output, `<input type="text" name="role"><input type='text'>`);
  assert.equal(testRule(preset("enable-controls"), `<button disabled>Go</button><input disabled="disabled" />`).output, `<button>Go</button><input />`);
  assert.equal(testRule(preset("admin-flag"), `{"user":"bob","isAdmin": false}`).output, `{"user":"bob","isAdmin": true}`);
  assert.equal(testRule(preset("strip-httponly"), "sid=1; Path=/; HttpOnly; Secure").output, "sid=1; Path=/; Secure");
});

test("static presets compile into scoped DNR rules once enabled", () => {
  const scope = scopeToDnrDomains({ enabled: true, include: ["lab.test"], exclude: [] });
  for (const p of MATCH_REPLACE_PRESETS.filter((x) => x.rule.engine === "static")) {
    const dnr = toDnrRule({ ...p.rule, enabled: true }, 0, scope);
    assert.ok(dnr, p.id);
    assert.equal(dnr.action.type, "modifyHeaders", p.id);
  }
  // Presets are added disabled, which compiles to nothing.
  assert.equal(toDnrRule(preset("remove-csp"), 0, scope), null);
});
