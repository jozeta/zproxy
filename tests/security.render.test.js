// Covers the "render isolation" claim in docs/SECURITY.md as far as this
// Node-only test harness can: unit-tests the pure-string escaping helper
// (src/utils/sanitize.js) against the XSS payloads named in the spec. The
// stronger guarantee — that captured HTML is actually rendered via a
// sandboxed `<iframe sandbox="">` with scripting disabled, never innerHTML —
// is a DOM/browser behavior that cannot be exercised without a browser (no
// jsdom dependency here, by the project's zero-dependency rule). That half is
// checked statically instead, in security.no-eval.test.js, and should be
// spot-checked manually in Chrome (see README "Manual verification checklist").
import { test } from "node:test";
import assert from "node:assert/strict";
import { escapeHtml } from "../src/utils/sanitize.js";

const XSS_PAYLOADS = [
  "<script>alert(document.domain)</script>",
  '<img src=x onerror=alert(1)>',
  "javascript:alert(1)",
  '"><svg onload=alert(1)>',
  "'-alert(1)-'",
];

test("escapeHtml neutralizes every characters an attacker needs to break out of an attribute or tag", () => {
  for (const payload of XSS_PAYLOADS) {
    const escaped = escapeHtml(payload);
    assert.equal(escaped.includes("<"), false, `escaped output still contains '<' for payload: ${payload}`);
    assert.equal(escaped.includes(">"), false, `escaped output still contains '>' for payload: ${payload}`);
    assert.equal(escaped.includes('"'), false, `escaped output still contains '"' for payload: ${payload}`);
  }
});

test("escapeHtml is stable (idempotent-safe) and round-trippable in intent: entities, not removal", () => {
  assert.equal(escapeHtml("<script>"), "&lt;script&gt;");
  assert.equal(escapeHtml(`a & b`), "a &amp; b");
  assert.equal(escapeHtml(`it's "quoted"`), "it&#39;s &quot;quoted&quot;");
});

test("escapeHtml coerces non-string input instead of throwing", () => {
  assert.equal(escapeHtml(null), "null");
  assert.equal(escapeHtml(42), "42");
});
