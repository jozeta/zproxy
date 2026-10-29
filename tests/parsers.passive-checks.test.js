import { test } from "node:test";
import assert from "node:assert/strict";
import { checkResponse } from "../src/parsers/passive-checks.js";

function ids(findings) {
  return findings.map((f) => f.id);
}

test("checkResponse returns [] for a missing response or one with no headers", () => {
  assert.deepEqual(checkResponse({ url: "https://x.com/" }, null), []);
  assert.deepEqual(checkResponse({ url: "https://x.com/" }, {}), []);
});

test("a clean https/HTML response with every recommended header raises nothing", () => {
  const response = {
    headers: [
      // The OWASP Secure Headers project's recommended set.
      { name: "Content-Type", value: "text/html; charset=utf-8" },
      { name: "Content-Security-Policy", value: "default-src 'self'; object-src 'none'; base-uri 'self'" },
      { name: "X-Content-Type-Options", value: "nosniff" },
      { name: "X-Frame-Options", value: "DENY" },
      { name: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
      { name: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      { name: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
      { name: "Cross-Origin-Opener-Policy", value: "same-origin" },
    ],
  };
  assert.deepEqual(checkResponse({ url: "https://example.com/" }, response), []);
});

test("an HTML response missing security headers is flagged for each one", () => {
  const response = { headers: [{ name: "Content-Type", value: "text/html" }] };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  assert.ok(ids(findings).includes("missing-csp"));
  assert.ok(ids(findings).includes("missing-xcto"));
  assert.ok(ids(findings).includes("missing-xfo"));
  assert.ok(ids(findings).includes("missing-hsts"));
});

test("CSP frame-ancestors satisfies the clickjacking check even without X-Frame-Options", () => {
  const response = { headers: [{ name: "Content-Type", value: "text/html" }, { name: "Content-Security-Policy", value: "frame-ancestors 'none'" }] };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  assert.equal(ids(findings).includes("missing-xfo"), false);
});

test("security headers are not checked for a plain HTTP response's HSTS (moot) but still checked for CSP/XFO", () => {
  const response = { headers: [{ name: "Content-Type", value: "text/html" }] };
  const findings = checkResponse({ url: "http://example.com/" }, response);
  assert.equal(ids(findings).includes("missing-hsts"), false);
  assert.ok(ids(findings).includes("missing-csp"));
});

test("a cookie set over plain HTTP is flagged high and skips the Secure/HttpOnly/SameSite sub-checks", () => {
  const response = { headers: [{ name: "Set-Cookie", value: "session=abc123" }] };
  const findings = checkResponse({ url: "http://example.com/" }, response);
  assert.deepEqual(ids(findings), ["cookie-over-http"]);
  assert.equal(findings[0].severity, "high");
});

test("a cookie over https missing Secure/HttpOnly/SameSite is flagged for each, at higher severity for a session-looking name", () => {
  const response = { headers: [{ name: "Set-Cookie", value: "session_id=abc123" }] };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  assert.ok(ids(findings).includes("cookie-missing-secure"));
  assert.ok(ids(findings).includes("cookie-missing-httponly"));
  assert.ok(ids(findings).includes("cookie-missing-samesite"));
  assert.equal(findings.find((f) => f.id === "cookie-missing-httponly").severity, "medium");
});

test("a fully-flagged cookie is not raised when all three attributes are present", () => {
  // HSTS is checked on every https response, so include it to isolate the cookie checks.
  const response = {
    headers: [
      { name: "Set-Cookie", value: "id=abc123; Secure; HttpOnly; SameSite=Strict" },
      { name: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
    ],
  };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  assert.deepEqual(findings, []);
});

test("permissive CORS (wildcard origin + credentials) is flagged", () => {
  const response = {
    headers: [
      { name: "Access-Control-Allow-Origin", value: "*" },
      { name: "Access-Control-Allow-Credentials", value: "true" },
    ],
  };
  assert.ok(ids(checkResponse({ url: "https://example.com/" }, response)).includes("permissive-cors"));
});

test("wildcard CORS without credentials is not flagged (a legitimately common, safe pattern)", () => {
  const response = { headers: [{ name: "Access-Control-Allow-Origin", value: "*" }] };
  assert.equal(ids(checkResponse({ url: "https://example.com/" }, response)).includes("permissive-cors"), false);
});

test("a version number in the Server header is flagged as a verbose banner", () => {
  const response = { headers: [{ name: "Server", value: "nginx/1.18.0" }] };
  assert.ok(ids(checkResponse({ url: "https://example.com/" }, response)).includes("verbose-server-header"));
});

test("a Server header with no version number is not flagged", () => {
  const response = { headers: [{ name: "Server", value: "nginx" }] };
  assert.equal(ids(checkResponse({ url: "https://example.com/" }, response)).includes("verbose-server-header"), false);
});

// ---------- Secret scanning ----------

test("a high-confidence secret format (AWS access key) in the body is flagged high, with the value masked", () => {
  const response = { headers: [], body: "config: AWS_KEY=AKIAABCDEFGHIJKLMNOP end" };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  const finding = findings.find((f) => f.id === "secret-aws-access-key");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
  assert.equal(finding.detail.includes("AKIAABCDEFGHIJKLMNOP"), false); // never show the full secret
  assert.match(finding.detail, /AKIA…MNOP/);
});

test("a PEM private key block is flagged high", () => {
  const response = { headers: [], body: "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----" };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  assert.ok(findings.some((f) => f.id === "secret-private-key-block" && f.severity === "high"));
});

test("a generic 'secret = long value' assignment is flagged low, not high", () => {
  const response = { headers: [], body: 'client_secret: "abcdefghijklmnopqrstuvwx"' };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  const finding = findings.find((f) => f.id === "secret-generic-secret-assignment");
  assert.ok(finding);
  assert.equal(finding.severity, "low");
});

test("secret patterns are also checked against response headers, not just the body", () => {
  const response = { headers: [{ name: "X-Debug-Token", value: "AKIAABCDEFGHIJKLMNOP" }], body: "" };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  assert.ok(findings.some((f) => f.id === "secret-aws-access-key"));
});

test("ordinary body content raises no secret findings", () => {
  const response = { headers: [], body: "<html><body>Welcome back, alice!</body></html>" };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  assert.equal(findings.filter((f) => f.id.startsWith("secret-")).length, 0);
});

test("each secret signature is capped at 3 matches so one noisy pattern can't drown out the rest", () => {
  const many = Array.from({ length: 10 }, (_, i) => `AKIA${String(i).padStart(16, "0")}`).join(" ");
  const response = { headers: [], body: many };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  assert.equal(findings.filter((f) => f.id === "secret-aws-access-key").length, 3);
});

// ---------- Reflected-input detection ----------

test("a query param value containing an XSS-probe character that reflects unescaped is flagged", () => {
  const request = { url: 'https://example.com/search?q=%3Cscript%3Eevil%3C%2Fscript%3E', headers: [] };
  const response = { headers: [], body: "Results for <script>evil</script>" };
  const findings = checkResponse(request, response);
  const finding = findings.find((f) => f.id === "reflected-input");
  assert.ok(finding);
  assert.equal(finding.severity, "medium");
});

test("a plain (metacharacter-free) reflected value is NOT flagged — normal echoing isn't a signal on its own", () => {
  const request = { url: "https://example.com/greet?name=alice", headers: [] };
  const response = { headers: [], body: "Hello, alice!" };
  const findings = checkResponse(request, response);
  assert.equal(findings.some((f) => f.id === "reflected-input"), false);
});

test("a probe character that reflects HTML-entity-encoded (properly escaped) is NOT flagged", () => {
  const request = { url: 'https://example.com/search?q=%3Cb%3E', headers: [] };
  const response = { headers: [], body: "Results for &lt;b&gt;" };
  const findings = checkResponse(request, response);
  assert.equal(findings.some((f) => f.id === "reflected-input"), false);
});

test("a JSON request body's string values are checked for reflection too", () => {
  const request = {
    url: "https://example.com/api/comment",
    headers: [{ name: "Content-Type", value: "application/json" }],
    body: JSON.stringify({ text: '"><img src=x>', nested: { other: "fine" } }),
  };
  const response = { headers: [], body: 'Comment saved: "><img src=x>' };
  const findings = checkResponse(request, response);
  assert.ok(findings.some((f) => f.id === "reflected-input"));
});

test("a form-urlencoded request body's field values are checked for reflection too", () => {
  const request = {
    url: "https://example.com/submit",
    headers: [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
    body: "comment=" + encodeURIComponent("<img src=x>") + "&other=1",
  };
  const response = { headers: [], body: "You said: <img src=x>" };
  const findings = checkResponse(request, response);
  assert.ok(findings.some((f) => f.id === "reflected-input"));
});

test("reflected-input findings are capped so a page reflecting many params doesn't flood the list", () => {
  const params = Array.from({ length: 8 }, (_, i) => `p${i}=${encodeURIComponent(`<x${i}>`)}`).join("&");
  const request = { url: `https://example.com/?${params}`, headers: [] };
  const body = Array.from({ length: 8 }, (_, i) => `<x${i}>`).join(" ");
  const response = { headers: [], body };
  const findings = checkResponse(request, response);
  assert.ok(findings.filter((f) => f.id === "reflected-input").length <= 5);
});

test("findings come back sorted most-severe first", () => {
  const response = {
    headers: [
      { name: "Content-Type", value: "text/html" },
      { name: "Set-Cookie", value: "id=abc123" }, // over https, missing all three -> low/medium findings
    ],
  };
  const findings = checkResponse({ url: "https://example.com/" }, response);
  const severities = findings.map((f) => f.severity);
  const rank = { high: 3, medium: 2, low: 1, info: 0 };
  for (let i = 1; i < severities.length; i++) {
    assert.ok(rank[severities[i - 1]] >= rank[severities[i]]);
  }
});
