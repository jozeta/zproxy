// Second tier of passive checks, run by passive-checks.js's checkResponse().
// Same contract as the first tier: zero extra requests, narrow heuristics
// over data already captured, and every finding phrased as "worth a look",
// never as a confirmed vulnerability. Grouped by what they read: response
// headers, cookies, the request itself, and the response body.
import { getHeaderValue } from "./headers.js";
import { parseAllSetCookies } from "./cookies.js";
import { parseQueryParams } from "./http.js";
import { decodeJwt } from "./jwt.js";

const SIX_MONTHS_S = 15_552_000;
const THIRTY_DAYS_S = 2_592_000;

function finding(id, severity, title, detail) {
  return { id, severity, title, detail };
}

function clip(text, max = 80) {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

// ---------------------------------------------------------------- headers --

/** CSP directives as a Map(name -> source list), lower-cased. */
export function parseCsp(csp) {
  const directives = new Map();
  for (const part of (csp || "").split(";")) {
    const [name, ...sources] = part.trim().toLowerCase().split(/\s+/);
    if (name && !directives.has(name)) directives.set(name, sources);
  }
  return directives;
}

/** Weaknesses in the effective script policy (script-src, falling back to default-src). */
export function cspScriptWeaknesses(csp) {
  const directives = parseCsp(csp);
  const sources = directives.get("script-src") || directives.get("default-src");
  if (!sources) return ["no script-src or default-src — scripts from anywhere are allowed"];
  const weaknesses = [];
  // A nonce or hash makes browsers ignore 'unsafe-inline' (CSP2+), so only flag it when neither is present.
  const hasNonceOrHash = sources.some((s) => /^'(nonce|sha256|sha384|sha512)-/.test(s));
  if (sources.includes("'unsafe-inline'") && !hasNonceOrHash) weaknesses.push("'unsafe-inline' allows injected inline scripts");
  if (sources.includes("'unsafe-eval'")) weaknesses.push("'unsafe-eval' allows building and running code from strings");
  if (sources.some((s) => s === "*" || s === "http:" || s === "https:" || s === "data:")) {
    weaknesses.push("a scheme-wide or * source allows scripts from (almost) any origin");
  }
  return weaknesses;
}

function checkHeaders(request, response, { isHttps, html }) {
  const out = [];
  const h = (name) => getHeaderValue(response.headers, name);

  const csp = h("content-security-policy");
  if (csp) {
    const weak = cspScriptWeaknesses(csp);
    if (weak.length) out.push(finding("weak-csp", "low", "Content-Security-Policy doesn't restrict scripts", `The policy is present but weak: ${weak.join("; ")}. It gives little protection if an XSS bug exists.`));
  } else if (html && h("content-security-policy-report-only")) {
    out.push(finding("csp-report-only", "info", "CSP is report-only", "Only Content-Security-Policy-Report-Only is set, so violations are reported but nothing is blocked."));
  }

  const hsts = h("strict-transport-security");
  if (isHttps && hsts) {
    const maxAge = Number((hsts.match(/max-age\s*=\s*"?(\d+)/i) || [])[1]);
    if (!Number.isFinite(maxAge) || maxAge < SIX_MONTHS_S) {
      out.push(finding("weak-hsts", "low", "HSTS max-age is short", `Strict-Transport-Security: "${clip(hsts)}" — under six months (or unparseable), so the downgrade protection lapses quickly between visits.`));
    }
  }

  const acao = h("access-control-allow-origin");
  const credentials = (h("access-control-allow-credentials") || "").toLowerCase() === "true";
  const origin = getHeaderValue(request?.headers || [], "origin");
  if (credentials && acao === "null") {
    out.push(finding("cors-null-origin", "medium", "CORS trusts the \"null\" origin with credentials", "Access-Control-Allow-Origin: null is sent by sandboxed iframes and local files, which any attacker can create — together with credentials, that lets them read authenticated responses."));
  } else if (credentials && origin && acao && acao !== "*" && acao === origin) {
    let sameOrigin = false;
    try {
      sameOrigin = new URL(request.url).origin === origin;
    } catch {
      /* ignore */
    }
    if (!sameOrigin) {
      out.push(finding("cors-reflected-origin", "medium", "CORS echoes a cross-site Origin with credentials", `The response allows "${clip(origin)}" — exactly the Origin this request sent — with credentials. If any Origin is echoed back, any site can read this response as the logged-in user. Confirm in Repeater with Origin: https://evil.example.`));
    }
  }

  const disclosure = ["x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime-version"].map((n) => [n, h(n)]).filter(([, v]) => v);
  if (disclosure.length) {
    out.push(finding("tech-disclosure-header", "info", "Headers disclose the technology stack", `${disclosure.map(([n, v]) => `${n}: ${clip(v, 40)}`).join(", ")} — fingerprinting help for an attacker; usually safe to remove.`));
  }

  if (html && !h("referrer-policy")) {
    out.push(finding("missing-referrer-policy", "info", "No Referrer-Policy header", "Without it, browsers fall back to their default policy; set one explicitly (e.g. strict-origin-when-cross-origin) so URLs with tokens or IDs don't leak to third parties."));
  } else if (/unsafe-url/i.test(h("referrer-policy") || "")) {
    out.push(finding("unsafe-referrer-policy", "low", "Referrer-Policy: unsafe-url", "The full URL — path and query string included — is sent as the Referer to every site this page links to or loads from."));
  }

  const sensitive = parseAllSetCookies(response.headers).length > 0 || !!getHeaderValue(request?.headers || [], "authorization");
  const cacheControl = (h("cache-control") || "").toLowerCase();
  if (sensitive && response.statusCode === 200 && !/no-store|private/.test(cacheControl)) {
    out.push(finding("cacheable-sensitive-response", "low", "Authenticated response may be cached", `This response ${getHeaderValue(request?.headers || [], "authorization") ? "answers an Authorization-bearing request" : "sets a cookie"} but Cache-Control ("${clip(cacheControl || "absent", 50)}") has neither no-store nor private, so a shared cache or proxy could keep and serve it to someone else.`));
  }

  const body = typeof response.body === "string" ? response.body.trim() : "";
  const contentType = (h("content-type") || "").toLowerCase();
  if (body && !contentType) {
    out.push(finding("missing-content-type", "low", "Response has a body but no Content-Type", "Browsers will guess (MIME-sniff) the type, which can turn user-controlled content into executable HTML or script."));
  } else if (contentType.includes("text/html") && /^[[{]/.test(body) && /[}\]]$/.test(body)) {
    try {
      JSON.parse(body);
      out.push(finding("json-served-as-html", "low", "JSON served as text/html", "A JSON body labelled text/html is rendered as HTML if opened directly, so any user-controlled string in it can become reflected XSS. Serve it as application/json."));
    } catch {
      /* not actually JSON */
    }
  }
  return out;
}

// ---------------------------------------------------------------- cookies --

function cookieLifetimeSeconds(cookie, now) {
  if (Number.isFinite(cookie.maxAge)) return cookie.maxAge;
  if (cookie.expires) {
    const t = Date.parse(cookie.expires);
    if (Number.isFinite(t)) return (t - now) / 1000;
  }
  return null;
}

function checkCookies(response, { isHttps, now }) {
  const out = [];
  for (const cookie of parseAllSetCookies(response.headers)) {
    if (/^none$/i.test(cookie.sameSite || "") && !cookie.secure && isHttps) {
      out.push(finding("cookie-samesite-none-insecure", "medium", `Cookie "${cookie.name}" is SameSite=None without Secure`, "Browsers reject SameSite=None cookies that aren't also Secure, so this cookie is silently dropped — or, in older browsers, sent cross-site in cleartext."));
    }
    const lifetime = cookieLifetimeSeconds(cookie, now);
    if (/session|token|auth|sid|jwt/i.test(cookie.name) && lifetime != null && lifetime > THIRTY_DAYS_S) {
      out.push(finding("long-lived-session-cookie", "low", `Session-like cookie "${cookie.name}" lives over 30 days`, `It persists for about ${Math.round(lifetime / 86400)} days, so a stolen copy stays useful for a long time. Session cookies usually expire with the browser or within hours.`));
    }
  }
  return out;
}

// ---------------------------------------------------------------- request --

const SENSITIVE_PARAM = /^(password|passwd|pwd|pass|secret|token|access_token|refresh_token|id_token|api_?key|apikey|auth|session|sessionid|session_id|sid|jwt|credit_?card|ccnum|ssn)$/i;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;

function checkRequest(request, { isHttps }) {
  const out = [];
  if (!request) return out;
  const params = parseQueryParams(request.url || "").filter((p) => SENSITIVE_PARAM.test(p.name) && p.value);
  if (params.length) {
    out.push(finding("sensitive-data-in-url", "medium", "Sensitive-looking value in the URL", `Query parameter(s) ${params.map((p) => `"${p.name}"`).join(", ")} carry a value. URLs end up in server logs, browser history, and Referer headers sent to other sites — secrets belong in a header or the body.`));
  }
  if (!isHttps) {
    const auth = getHeaderValue(request.headers || [], "authorization") || "";
    if (/^basic\s/i.test(auth)) {
      out.push(finding("basic-auth-over-http", "high", "Basic credentials sent over plain HTTP", "Authorization: Basic is just base64 — anyone on the network path can read the username and password."));
    }
    if (/(^|[&"\s])(password|passwd|pwd)("?\s*[:=])/i.test(request.body || "")) {
      out.push(finding("password-over-http", "high", "Password submitted over plain HTTP", "The request body contains a password field and was sent unencrypted."));
    }
  }
  return out;
}

/** JWTs anywhere in the request (headers/URL/body) or response body whose header says alg "none". */
function checkJwts(request, response) {
  const haystack = [
    request?.url || "",
    ...(request?.headers || []).map((h) => h.value),
    request?.body || "",
    typeof response.body === "string" ? response.body : "",
    ...(response.headers || []).map((h) => h.value),
  ].join("\n");
  const seen = new Set();
  for (const match of haystack.matchAll(JWT_PATTERN)) {
    if (seen.has(match[0])) continue;
    seen.add(match[0]);
    const decoded = decodeJwt(match[0]);
    if (decoded.ok && String(decoded.header?.alg || "").toLowerCase() === "none") {
      return [finding("jwt-alg-none", "high", "JWT with alg \"none\"", "A token in this exchange declares no signature algorithm. If the server accepts it, anyone can forge tokens — test by editing the payload in Repeater.")];
    }
  }
  return [];
}

// ------------------------------------------------------------------- body --

const ERROR_SIGNATURES = [
  { severity: "medium", label: "SQL error", pattern: /You have an error in your SQL syntax|SQLSTATE\[|ORA-\d{5}|PG::[A-Za-z]+Error|Unclosed quotation mark after the character string|sqlite3?\.OperationalError|Microsoft OLE DB Provider for SQL Server/i },
  { severity: "low", label: "Java stack trace", pattern: /\bat [\w$.]+\([\w$]+\.java:\d+\)/ },
  { severity: "low", label: ".NET exception", pattern: /\bSystem\.[\w.]+Exception\b.*?(\n|\r|<br)|Server Error in '\/.*' Application/ },
  { severity: "low", label: "Python traceback", pattern: /Traceback \(most recent call last\)/ },
  { severity: "low", label: "PHP error", pattern: /(Fatal error|Warning|Parse error|Notice): .{1,200} in \/[^\s<]+\.php on line \d+/ },
  { severity: "low", label: "Node.js stack trace", pattern: /\bat [\w.<>$ ]+ \(\/[^\s)]+\.js:\d+:\d+\)/ },
];

const PRIVATE_IP = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/;

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function checkBody(request, response, { isHttps, html }) {
  const out = [];
  const body = typeof response.body === "string" ? response.body : "";

  if (body) {
    for (const sig of ERROR_SIGNATURES) {
      if (sig.pattern.test(body)) {
        out.push(finding(`error-disclosure-${sig.label.toLowerCase().replace(/[^a-z]+/g, "-")}`, sig.severity, `${sig.label} in response`, `The body contains what looks like a ${sig.label}. Error details reveal internals (paths, queries, versions) and an SQL error in particular often means input reaches a query unescaped — worth probing for injection.`));
      }
    }
    if (/<title>\s*Index of \//i.test(body)) {
      out.push(finding("directory-listing", "low", "Directory listing enabled", "The server lists a directory's files, which can expose backups, configs, or source that was never linked."));
    }
    const requestHost = hostOf(request?.url || "");
    const ip = body.match(PRIVATE_IP) || (response.headers || []).map((h) => h.value).join("\n").match(PRIVATE_IP);
    if (ip && !PRIVATE_IP.test(requestHost)) {
      out.push(finding("private-ip-disclosure", "info", "Internal IP address disclosed", `"${ip[0]}" appears in the response — it reveals internal network layout to an outside visitor.`));
    }
  }

  if (html && isHttps && body) {
    const mixed = body.match(/<(script|iframe|link|img|form)\b[^>]*\b(src|href|action)\s*=\s*["']?http:\/\/[^"'\s>]+/i);
    if (mixed) {
      const isForm = mixed[1].toLowerCase() === "form";
      out.push(
        isForm
          ? finding("insecure-form-action", "medium", "Form on an HTTPS page submits over HTTP", `A <form> posts to "${clip(mixed[0].split(/=\s*["']?/).pop())}" — whatever is typed into it (often credentials) travels unencrypted.`)
          : finding("mixed-content", "low", "HTTPS page loads content over HTTP", `"${clip(mixed[0])}" — browsers block or warn on mixed content, and anything that does load can be tampered with in transit.`)
      );
    }
  }

  // Open redirect: a 3xx to another host, where that destination came from the request itself.
  const location = getHeaderValue(response.headers || [], "location") || "";
  if (response.statusCode >= 300 && response.statusCode < 400 && /^(https?:)?\/\//i.test(location)) {
    const target = hostOf(location.startsWith("//") ? `https:${location}` : location);
    const requestHost = hostOf(request?.url || "");
    if (target && requestHost && target !== requestHost) {
      const fromParam = parseQueryParams(request.url || "").some((p) => p.value && (p.value === location || p.value.includes(target)));
      if (fromParam) {
        out.push(finding("open-redirect-candidate", "medium", "Redirect target taken from a request parameter", `This response redirects to ${clip(location)} — a different host that came from the request's own query string. If any value is accepted, it's an open redirect (phishing, OAuth token theft). Try an external URL in Repeater.`));
      }
    }
  }
  return out;
}

/** Every second-tier finding for one exchange. `now` is injectable for tests. */
export function checkAdvanced(request, response, { isHttps, html, now = Date.now() } = {}) {
  return [
    ...checkHeaders(request, response, { isHttps, html }),
    ...checkCookies(response, { isHttps, now }),
    ...checkRequest(request, { isHttps }),
    ...checkJwts(request, response),
    ...checkBody(request, response, { isHttps, html }),
  ];
}
