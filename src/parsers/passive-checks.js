// Passive, zero-request security observations derived entirely from a
// request/response pair ZProxy already captured — no active probing, no
// extra traffic, deliberately not a scanner. Every check here is a narrow,
// low-false-positive heuristic on headers/URL scheme/body content that's
// actually derivable from what's already on hand; nothing here claims a
// vulnerability exists, only that a specific defense-in-depth control looks
// absent, misconfigured, or that something worth a second look showed up.
// See src/parsers/cookies.js for the Set-Cookie parsing this reuses.
import { getHeaderValue } from "./headers.js";
import { parseAllSetCookies } from "./cookies.js";
import { parseQueryParams } from "./http.js";
import { tryParseJson, looksLikeJson } from "./json.js";
import { headersAsText } from "../intruder/search.js";

export const SEVERITY_ORDER = ["info", "low", "medium", "high"];

function isHtmlResponse(response) {
  const contentType = (getHeaderValue(response.headers, "content-type") || response.mimeType || "").toLowerCase();
  return contentType.includes("html");
}

function looksLikeSessionCookieName(name) {
  return /session|token|auth|sid|jwt/i.test(name || "");
}

/** Shows enough of a matched secret to recognize it without displaying the whole thing on screen (screenshots, screen-shares, shoulder surfers). */
function maskSecret(value) {
  if (value.length <= 8) return "•".repeat(value.length);
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

// Fixed-format signatures (specific enough that a match is rarely a
// coincidence) plus one deliberately broad, low-confidence catch-all for a
// "key/secret/token = <long string>" assignment shape. `pattern` must carry
// the "g" flag — checkSecrets() drives it with repeated exec() calls.
const SECRET_SIGNATURES = [
  { id: "aws-access-key", label: "AWS Access Key ID", severity: "high", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "aws-temp-key", label: "AWS temporary Access Key ID", severity: "high", pattern: /\b(?:ASIA)[0-9A-Z]{16}\b/g },
  { id: "github-token", label: "GitHub token", severity: "high", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: "slack-token", label: "Slack token", severity: "high", pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g },
  { id: "google-api-key", label: "Google API key", severity: "high", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { id: "stripe-key", label: "Stripe live API key", severity: "high", pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
  { id: "sendgrid-key", label: "SendGrid API key", severity: "high", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: "npm-token", label: "npm access token", severity: "high", pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "private-key-block", label: "Private key block", severity: "high", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  {
    id: "generic-secret-assignment",
    label: "possible hardcoded secret",
    severity: "low",
    pattern: /\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)["']?\s*[:=]\s*["']([A-Za-z0-9\-_+/=]{12,})["']/gi,
  },
];

/** Scans a response's body and headers for secret-shaped strings via SECRET_SIGNATURES. High-confidence, specific-prefix formats (AWS/GitHub/Slack/... keys, PEM blocks) score "high"; the one generic "key = long string" catch-all scores "low" since it's a shape, not a format, and false-positives accordingly. Capped at 3 matches per signature so one noisy pattern can't drown out everything else. */
function checkSecrets(response) {
  const findings = [];
  const haystack = `${response.body || ""}\n${headersAsText(response.headers)}`;
  if (!haystack.trim()) return findings;
  for (const sig of SECRET_SIGNATURES) {
    sig.pattern.lastIndex = 0;
    let match;
    let count = 0;
    while (count < 3 && (match = sig.pattern.exec(haystack))) {
      const secretValue = match[1] || match[0];
      findings.push({
        id: `secret-${sig.id}`,
        severity: sig.severity,
        title: `Possible ${sig.label} in response`,
        detail: `Matched the ${sig.label} pattern: ${maskSecret(secretValue)}. If this is real, treat it as compromised and rotate it — don't rely on this heuristic to rule a body out either way.`,
      });
      count++;
      if (match[0].length === 0) sig.pattern.lastIndex++;
    }
  }
  return findings;
}

const REFLECTION_PROBE_CHARS = /[<>"'`]/;
const MAX_REFLECTED_FINDINGS = 5;

/** Every string value the request actually supplied — URL query params, form-urlencoded body fields, and JSON body string leaves (via a real JSON.parse, never eval/regex-guessing) — that a passive reflection check can look for in the response. */
function extractReflectableValues(request) {
  const values = new Set();
  for (const p of parseQueryParams(request.url || "")) {
    if (p.value) values.add(p.value);
  }
  const body = request.body || "";
  const contentType = getHeaderValue(request.headers || [], "content-type") || "";
  if (looksLikeJson(body, contentType)) {
    const parsed = tryParseJson(body);
    if (parsed.ok) {
      const stack = [parsed.value];
      while (stack.length) {
        const cur = stack.pop();
        if (typeof cur === "string") values.add(cur);
        else if (cur && typeof cur === "object") stack.push(...Object.values(cur));
      }
    }
  } else if (body) {
    for (const pair of body.split("&")) {
      const eq = pair.indexOf("=");
      if (eq === -1) continue;
      try {
        const v = decodeURIComponent(pair.slice(eq + 1));
        if (v) values.add(v);
      } catch {
        /* not actually form-urlencoded — skip this pair */
      }
    }
  }
  return values;
}

/**
 * Flags a request-supplied value that contains an HTML/JS metacharacter
 * (< > " ' `) and reappears verbatim — not HTML-entity-encoded — in the
 * response body. Deliberately narrow: reflecting a plain value back (an
 * echoed username, a submitted ID) is normal and not flagged; reflecting an
 * unescaped probe character is the actual reflected-XSS-shaped signal, and
 * is exactly what sending a `<`/`"`-laced value via Repeater/Intruder and
 * checking the response is already testing for manually.
 */
function checkReflectedInput(request, response) {
  const findings = [];
  if (!request?.url || typeof response.body !== "string" || !response.body) return findings;
  const values = extractReflectableValues(request);
  for (const value of values) {
    if (value.length < 3 || !REFLECTION_PROBE_CHARS.test(value)) continue;
    if (response.body.includes(value)) {
      findings.push({
        id: "reflected-input",
        severity: "medium",
        title: "Request value reflected unescaped in response body",
        detail: `A value this request sent — "${value.length > 60 ? `${value.slice(0, 60)}…` : value}" — reappears verbatim (not HTML-entity-encoded) in the response body. Possible reflected-XSS injection point; worth confirming with a real payload via Repeater/Intruder.`,
      });
      if (findings.length >= MAX_REFLECTED_FINDINGS) break;
    }
  }
  return findings;
}

/** Findings for one request/response pair, most-severe first: security headers, cookie flags, CORS, server banners, secret-shaped strings in the response, and request values reflected unescaped in it. Returns [] for a missing response, or a response ZProxy has no headers for at all. */
export function checkResponse(request, response) {
  if (!response || !response.headers) return [];
  const findings = [];
  let scheme = "";
  try {
    scheme = new URL(request?.url || "").protocol;
  } catch {
    /* unparseable URL — scheme-dependent checks below just won't fire */
  }
  const isHttps = scheme === "https:";
  const html = isHtmlResponse(response);

  if (html) {
    if (!getHeaderValue(response.headers, "content-security-policy")) {
      findings.push({ id: "missing-csp", severity: "info", title: "No Content-Security-Policy header", detail: "An HTML response with no CSP has no browser-enforced defense-in-depth against injected scripts, even if the app is otherwise XSS-free today." });
    }
    if (!getHeaderValue(response.headers, "x-content-type-options")) {
      findings.push({ id: "missing-xcto", severity: "info", title: "No X-Content-Type-Options: nosniff", detail: "Without it, some browsers may MIME-sniff the response into an executable type regardless of the declared Content-Type." });
    }
    const csp = getHeaderValue(response.headers, "content-security-policy") || "";
    if (!getHeaderValue(response.headers, "x-frame-options") && !/frame-ancestors/i.test(csp)) {
      findings.push({ id: "missing-xfo", severity: "low", title: "No clickjacking defense (X-Frame-Options / CSP frame-ancestors)", detail: "The page can be framed by any other site, which is a precondition for clickjacking attacks." });
    }
  }
  if (isHttps && !getHeaderValue(response.headers, "strict-transport-security")) {
    findings.push({ id: "missing-hsts", severity: "info", title: "No Strict-Transport-Security header", detail: "An HTTPS response with no HSTS leaves future visits to this host able to be silently downgraded to plain HTTP by a network attacker." });
  }

  for (const cookie of parseAllSetCookies(response.headers)) {
    if (!isHttps) {
      findings.push({ id: "cookie-over-http", severity: "high", title: `Cookie "${cookie.name}" set over plain HTTP`, detail: "This cookie's value was sent in cleartext and can be read or replayed by anyone on the network path." });
      continue; // Secure/SameSite are moot for a cookie already sent unencrypted.
    }
    if (!cookie.secure) {
      findings.push({ id: "cookie-missing-secure", severity: "medium", title: `Cookie "${cookie.name}" missing Secure`, detail: "Without Secure, this cookie can also be sent over a future plain-HTTP request to the same host, exposing it on the wire." });
    }
    if (!cookie.httpOnly) {
      findings.push({
        id: "cookie-missing-httponly",
        severity: looksLikeSessionCookieName(cookie.name) ? "medium" : "low",
        title: `Cookie "${cookie.name}" missing HttpOnly`,
        detail: "Without HttpOnly, JavaScript on the page (including any injected via XSS) can read this cookie's value.",
      });
    }
    if (!cookie.sameSite) {
      findings.push({ id: "cookie-missing-samesite", severity: "low", title: `Cookie "${cookie.name}" missing SameSite`, detail: "Without SameSite, this cookie is attached to cross-site requests too, widening CSRF exposure." });
    }
  }

  const acao = getHeaderValue(response.headers, "access-control-allow-origin");
  const acac = (getHeaderValue(response.headers, "access-control-allow-credentials") || "").toLowerCase();
  if (acao === "*" && acac === "true") {
    findings.push({ id: "permissive-cors", severity: "medium", title: "CORS: wildcard origin with credentials allowed", detail: 'Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true is a real misconfiguration (browsers reject this combination outright when a request actually carries credentials, so it usually signals a broken/copy-pasted CORS setup rather than an intentional policy).' });
  }

  const serverBanner = [getHeaderValue(response.headers, "server"), getHeaderValue(response.headers, "x-powered-by")].filter(Boolean).join(" / ");
  if (/[0-9]+\.[0-9]+/.test(serverBanner)) {
    findings.push({ id: "verbose-server-header", severity: "info", title: "Server banner reveals a version number", detail: `"${serverBanner}" — useful for an attacker fingerprinting known vulnerabilities for that exact version.` });
  }

  findings.push(...checkSecrets(response));
  findings.push(...checkReflectedInput(request, response));

  return findings.sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity));
}
