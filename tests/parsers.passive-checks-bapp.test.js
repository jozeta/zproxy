import { test } from "node:test";
import assert from "node:assert/strict";
import { checkResponse } from "../src/parsers/passive-checks.js";
import { extractJsEndpoints } from "../src/parsers/passive-checks-extended.js";

const H = (pairs) => pairs.map(([name, value]) => ({ name, value }));
const req = (url = "https://app.example.com/", headers = [], body = "") => ({ method: "GET", url, headers: H(headers), body });
const res = (headers = [], body = "") => ({ statusCode: 200, headers: H(headers), body });
const find = (r, s, id) => checkResponse(r, s).find((f) => f.id === id);

test("Hunt-style parameter names are mapped to what to test", () => {
  const f = find(req("https://app.example.com/view?file=report.pdf&next=/home&id=7"), res(), "interesting-parameters");
  assert.match(f.detail, /"file" → path traversal/);
  assert.match(f.detail, /"next" → SSRF \/ open redirect/);
  assert.match(f.detail, /"id" → IDOR/);
  const form = req("https://app.example.com/run", [["Content-Type", "application/x-www-form-urlencoded"]], "cmd=ls&x=1");
  assert.match(find(form, res(), "interesting-parameters").detail, /"cmd" → OS command injection/);
  assert.equal(find(req("https://app.example.com/?lang=en"), res(), "interesting-parameters"), undefined);
});

test("JS endpoint extraction finds API paths and absolute URLs, skipping assets and spec links", () => {
  const js = `fetch("/api/v2/users/" + id); const admin = '/internal/metrics'; img.src = "https://cdn.example.com/a.png";
              const docs = "https://www.w3.org/2000/svg"; axios.get(\`https://api.partner.test/v1/orders?limit=10\`);`;
  const eps = extractJsEndpoints(js);
  assert.ok(eps.includes("/api/v2/users/"));
  assert.ok(eps.includes("/internal/metrics"));
  assert.ok(eps.includes("https://api.partner.test/v1/orders?limit=10"));
  assert.ok(!eps.some((e) => e.endsWith(".png") || e.includes("w3.org")));
  assert.ok(find(req("https://app.example.com/app.js"), res([["Content-Type", "application/javascript"]], js), "js-endpoints"));
});

test("any reflected parameter value is reported as an injection candidate (not just ones with metacharacters)", () => {
  const html = [["Content-Type", "text/html"]];
  assert.ok(find(req("https://app.example.com/search?q=widgets"), res(html, "<p>Results for widgets</p>"), "reflected-parameters"));
  assert.equal(find(req("https://app.example.com/search?page=2"), res(html, "page 2"), "reflected-parameters"), undefined); // too short / trivial
});

test("cryptominers are flagged by domain or signature", () => {
  const html = [["Content-Type", "text/html"]];
  assert.equal(find(req(), res(html, '<script src="https://coinhive.com/lib/coinhive.min.js"></script>'), "cryptojacking-script").severity, "high");
  assert.ok(find(req(), res(html, "<script>var m = new CoinHive.Anonymous('key'); m.start();</script>"), "cryptojacking-script"));
});

test("Allow headers: TRACE is low, WebDAV/state-changing methods are info", () => {
  assert.equal(find(req(), res([["Allow", "GET, HEAD, TRACE"]]), "trace-method-allowed").severity, "low");
  assert.match(find(req(), res([["Allow", "GET, PUT, DELETE, PROPFIND"]]), "risky-methods-allowed").detail, /PUT, DELETE, PROPFIND/);
  assert.equal(find(req(), res([["Allow", "GET, POST, OPTIONS"]]), "risky-methods-allowed"), undefined);
});

test("Gitleaks-style secret formats are detected (synthetic values)", () => {
  const cases = {
    "secret-gitlab-token": "glpat-" + "x".repeat(20),
    "secret-slack-webhook": "https://hooks.slack.com/services/T0ABCDEF1/B0ABCDEF2/" + "a".repeat(24),
    "secret-digitalocean-token": "dop_v1_" + "a".repeat(64),
    "secret-google-oauth-secret": "GOCSPX-" + "A".repeat(28),
    "secret-stripe-restricted-key": "rk_live_" + "a".repeat(24),
  };
  for (const [id, secret] of Object.entries(cases)) {
    const f = find(req(), res([["Content-Type", "application/json"]], `{"config":"${secret}"}`), id);
    assert.ok(f, id);
    assert.ok(!f.detail.includes(secret), `${id} must be masked`);
  }
});
