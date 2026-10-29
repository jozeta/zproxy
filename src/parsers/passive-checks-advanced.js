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

// Response headers that only reveal the stack, versions, or internal topology
// — from the OWASP Secure Headers project's headers_remove.json (read
// 2026-10-29), minus pure tracing IDs. Server and X-Powered-By are handled
// by the version-banner check in passive-checks.js.
const DISCLOSURE_HEADERS = [
  "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-generated-by", "x-runtime-version", "x-php-version",
  "x-powered-by-plesk", "x-powered-cms", "x-server-powered-by", "x-cf-powered-by", "powered-by", "x-cms", "x-framework",
  "x-joomla-version", "x-umbraco-version", "x-owa-version", "x-cocoon-version", "liferay-portal", "oraclecommercecloud-version",
  "x-backend-server", "x-beserver", "x-feserver", "x-calculatedbetarget", "x-diaginfo", "x-varnish-backend", "x-varnish-server",
  "x-envoy-upstream-service-time", "x-envoy-original-dst-host", "x-kong-upstream-latency", "x-kong-proxy-latency",
  "x-nextjs-cache", "x-nextjs-matched-path", "x-redirect-by", "x-turbo-charged-by", "x-mod-pagespeed", "x-page-speed",
  "x-litespeed-cache", "x-gitlab-meta", "teamcity-node-id", "x-jitsi-release", "x-woodpecker-version",
];

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

  const disclosure = DISCLOSURE_HEADERS.map((n) => [n, h(n)]).filter(([, v]) => v);
  if (disclosure.length) {
    const versioned = disclosure.some(([, v]) => /\d+\.\d+/.test(v));
    out.push(finding("tech-disclosure-header", versioned ? "low" : "info", "Headers disclose the technology stack or internals", `${disclosure.map(([n, v]) => `${n}: ${clip(v, 40)}`).join(", ")} — fingerprinting help for an attacker${versioned ? " (with version numbers, which map straight to known CVEs)" : ""}; usually safe to remove.`));
  }
  const sourceFiles = h("x-sourcefiles");
  if (sourceFiles) {
    out.push(finding("aspnet-sourcefiles-header", "low", "X-SourceFiles header exposes a server path", `ASP.NET debug builds send X-SourceFiles with the base64-encoded physical path of the source file (${clip(sourceFiles, 40)}) — it means the app is running a debug build.`));
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

// Detailed error messages: framework debug pages, stack traces, database
// and template-engine errors, and leaked filesystem paths. Each finding id
// is "error-disclosure-<label>"; `why` says what the leak gives an attacker.
const STACK_TRACE_WHY = "Stack traces reveal file paths, framework and library versions, and code structure — and show that errors aren't being caught before they reach users.";
const ERROR_SIGNATURES = [
  // Debug pages that are dangerous in themselves.
  { severity: "high", label: "Werkzeug debugger", pattern: /Werkzeug Debugger|The debugger caught an exception in your WSGI application|[?&]__debugger__=yes/, why: "The Werkzeug interactive debugger is enabled. Its console executes arbitrary Python on the server (its PIN can often be derived from leaked system details) — remote code execution." },
  { severity: "high", label: "Django debug page", pattern: /You're seeing this error because you have <code>DEBUG = True<\/code>|DEBUG = True<\/code> in your Django settings/, why: "Django is running with DEBUG = True: the error page dumps settings, environment details, SQL queries, and the URL routing table." },
  { severity: "high", label: "Laravel debug page", pattern: /Illuminate\\[A-Za-z\\]+Exception|whoops-container|Whoops, looks like something went wrong|facade\/ignition|spatie\/laravel-ignition|laravel\/framework\/src\/Illuminate/, why: "Laravel debug mode (APP_DEBUG) is on: the Ignition/Whoops page exposes environment variables and source. Old Ignition versions allow remote code execution (CVE-2021-3129)." },
  { severity: "medium", label: "Symfony debug page", pattern: /Symfony\\Component\\[A-Za-z\\]+Exception|class="sf-toolbar|Symfony Exception<\/h1>|sf-dump/, why: "Symfony is in debug mode: the exception page and profiler toolbar expose source, configuration, and request data." },
  { severity: "medium", label: "Rails debug page", pattern: /Action Controller: Exception caught|<h1>Routing Error<\/h1>[\s\S]{0,400}Rails\.root|ActiveRecord::(StatementInvalid|RecordNotFound)/, why: "Rails is showing its development error page: routes, source snippets, and request parameters are exposed." },
  { severity: "medium", label: "ASP.NET detailed error", pattern: /Server Error in '\/.*' Application|ASP\.NET is configured to show verbose error messages|<b>\s*Exception Details:\s*<\/b>|<b>\s*Stack Trace:\s*<\/b>/, why: "ASP.NET customErrors is off: the 'yellow screen of death' shows the exception, a stack trace, source lines, and framework versions." },
  { severity: "medium", label: "Xdebug output", pattern: /class=['"]xdebug-error|<th[^>]*>Call Stack<\/th>[\s\S]{0,300}Memory/, why: "The Xdebug extension is loaded in production — it renders full call stacks and variables in error output, and its remote debugger can be abused for code execution." },
  { severity: "medium", label: "ColdFusion error", pattern: /ColdFusion (Error|cannot determine)|coldfusion\.runtime\.|The error occurred in [A-Z]:\\.*\.cfm/i, why: "ColdFusion's robust exception information is enabled: templates, paths, and SQL are exposed." },
  { severity: "medium", label: "GraphQL stack trace", pattern: /"extensions"\s*:\s*\{[^}]{0,200}"(exception|stacktrace)"/, why: "GraphQL errors include server stack traces (debug mode) — internals and file paths are exposed to every client." },
  // Data-layer errors: often a sign that input reaches a query unescaped.
  {
    severity: "medium",
    label: "SQL error",
    pattern: /You have an error in your SQL syntax|SQLSTATE\[|ORA-\d{5}|PG::[A-Za-z]+Error|PSQLException|syntax error at or near "|Unclosed quotation mark after the character string|Incorrect syntax near '|System\.Data\.SqlClient\.SqlException|sqlite3?\.OperationalError|SQLITE_ERROR|Microsoft OLE DB Provider for SQL Server|\[ODBC [^\]]*Driver\]|mysqli?_(fetch|query|num_rows)\(|MySqlException|com\.mysql\.jdbc|org\.postgresql\.util|DB2 SQL error|org\.hibernate\.(QueryException|exception)/i,
    why: "Database error text often means request input reaches a query without parameterization — probe the parameter for SQL injection. It also reveals the database engine and query structure.",
  },
  { severity: "medium", label: "NoSQL error", pattern: /MongoError|MongoServerError|E11000 duplicate key error|CastError: Cast to ObjectId failed|couchdb.*"error"\s*:\s*"query_parse_error"/i, why: "Database errors from MongoDB/CouchDB suggest input reaches a query — probe for NoSQL injection (e.g. {\"$ne\": null})." },
  { severity: "medium", label: "Template engine error", pattern: /jinja2\.exceptions|TemplateSyntaxError|Twig(_Error|\\Error)|freemarker\.(core|template)\.|org\.apache\.velocity|Smarty(Compiler)?Exception|Liquid (syntax )?error|org\.thymeleaf\.exceptions|Handlebars(\.js)? error/i, why: "A template engine error usually means input reached a template — a strong hint of server-side template injection (try {{7*7}})." },
  { severity: "medium", label: "LDAP error", pattern: /javax\.naming\.(directory|NameNotFoundException|InvalidNameException)|LDAPException|ldap_(search|bind)\(\)|Invalid DN syntax/i, why: "LDAP errors suggest input reaches a directory query — probe for LDAP injection." },
  { severity: "low", label: "XML parser error", pattern: /SAXParseException|XML Parsing Error|DOMDocument::loadXML|lxml\.etree\.XMLSyntaxError|System\.Xml\.XmlException|XMLStreamException/, why: "The server parses XML from requests — check whether it resolves external entities (XXE)." },
  { severity: "low", label: "Search engine error", pattern: /SearchPhaseExecutionException|SearchParseException|"type"\s*:\s*"(query_shard_exception|parsing_exception)"|org\.apache\.solr\.(search|common)/, why: "Elasticsearch/Solr errors reveal the search backend and query structure — input may be injectable into the query DSL." },
  // Language-level stack traces.
  { severity: "low", label: "Java stack trace", pattern: /\bat [\w$.]+\([\w$]+\.java:\d+\)/, why: STACK_TRACE_WHY },
  { severity: "low", label: ".NET exception", pattern: /\bSystem\.[\w.]+Exception\b.*?(\n|\r|<br)/, why: STACK_TRACE_WHY },
  { severity: "low", label: "Python traceback", pattern: /Traceback \(most recent call last\)/, why: STACK_TRACE_WHY },
  { severity: "low", label: "PHP error", pattern: /(Fatal error|Warning|Parse error|Notice|Deprecated): .{1,200} in (\/|[A-Z]:\\)[^\s<]+\.php on line \d+|PHP (Fatal|Parse) error:|Uncaught (Exception|Error|TypeError)\b.{0,200} in \//, why: STACK_TRACE_WHY },
  { severity: "low", label: "Node.js stack trace", pattern: /\bat [\w.<>$ ]+ \(\/[^\s)]+\.js:\d+:\d+\)/, why: STACK_TRACE_WHY },
  { severity: "low", label: "Ruby exception", pattern: /\.rb:\d+:in `[^']+'/, why: STACK_TRACE_WHY },
  { severity: "low", label: "Go panic", pattern: /goroutine \d+ \[running\]:|panic: runtime error:/, why: STACK_TRACE_WHY },
  { severity: "low", label: "Perl error", pattern: / at \/[^\s]+\.p[lm] line \d+\./, why: STACK_TRACE_WHY },
  { severity: "low", label: "Spring Whitelabel error page", pattern: /Whitelabel Error Page/, why: "Spring Boot's default error page — it confirms the stack, and with server.error.include-stacktrace on, includes traces." },
  { severity: "low", label: "Tomcat error page", pattern: /Apache Tomcat\/\d+\.\d+\.\d+ - Error report|<h3>Apache Tomcat\/\d/, why: "The default Tomcat error page reveals the exact Tomcat version — look it up for known CVEs." },
  { severity: "low", label: "JBoss/WildFly error", pattern: /JBWEB\d{6}|JBoss Web\/\d|WFLYUT\d{4}/, why: "The application server's default error output reveals the JBoss/WildFly version." },
  // Filesystem paths in error output.
  {
    severity: "low",
    label: "Full path disclosure",
    pattern: /(?:\/var\/www|\/home\/[a-z0-9_-]+|\/usr\/(?:local\/)?(?:lib|share|src)|\/srv\/|\/opt\/|\/app\/)[\w./-]*\.(?:php|py|rb|js|ts|java|go|cs|pl|jsp|aspx?|cfm)\b|[A-Z]:\\(?:inetpub|Users|Program Files|xampp|wamp|Windows)\\[\w\\ .-]+/,
    why: "A server-side filesystem path is visible. Paths help an attacker aim path-traversal and file-inclusion payloads, and reveal usernames and directory layout.",
  },
];

const PRIVATE_IP = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/;
// Internal-only DNS names (cloud-internal, corporate) — never meant for outside
// visitors. ".local"/".lan" are left out: they collide with ordinary JavaScript
// property access (this.local), and scripts are skipped below for the same reason.
const INTERNAL_HOSTNAME = /\b(?:[a-z0-9-]+\.)+(?:internal|corp|intranet|localdomain)\b(?![.-][a-z])|\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.[a-z0-9.-]*(?:ec2\.internal|compute\.internal)\b/i;
// Web/app server version strings rendered into a page (default error pages, footers).
const IN_PAGE_BANNER = /\b(Apache|nginx|Microsoft-IIS|LiteSpeed|openresty|Jetty|lighttpd|Caddy|gunicorn|Werkzeug|Kestrel|Tomcat|PHP)\/\d+\.\d+(?:\.\d+)?(?:\s*\([^)]{1,40}\))?/;

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
    const scanned = body.slice(0, 300_000);
    for (const sig of ERROR_SIGNATURES) {
      const m = scanned.match(sig.pattern);
      if (m) {
        out.push(finding(`error-disclosure-${sig.label.toLowerCase().replace(/[^a-z]+/g, "-").replace(/-$/, "")}`, sig.severity, `${sig.label} in response`, `Matched "${clip(m[0].replace(/\s+/g, " "), 60)}". ${sig.why}`));
      }
    }
    if (/<title>\s*(Index of \/|Directory listing for \/)|\[To Parent Directory\]|<a href="\.\.\/">\.\.\/<\/a>|>Parent Directory<\/a>/i.test(scanned)) {
      out.push(finding("directory-listing", "low", "Directory listing enabled", "The server lists a directory's files, which can expose backups, configs, or source that was never linked."));
    }
    const requestHost = hostOf(request?.url || "");
    const headerText = (response.headers || []).map((h) => h.value).join("\n");
    const ip = scanned.match(PRIVATE_IP) || headerText.match(PRIVATE_IP);
    if (ip && !PRIVATE_IP.test(requestHost)) {
      out.push(finding("private-ip-disclosure", "info", "Internal IP address disclosed", `"${ip[0]}" appears in the response — it reveals internal network layout to an outside visitor.`));
    }
    const isScript = /javascript|ecmascript/i.test(getHeaderValue(response.headers || [], "content-type") || "");
    const internalHost = (isScript ? null : scanned.match(INTERNAL_HOSTNAME)) || headerText.match(INTERNAL_HOSTNAME);
    if (internalHost && !INTERNAL_HOSTNAME.test(requestHost)) {
      out.push(finding("internal-hostname-disclosure", "info", "Internal hostname disclosed", `"${clip(internalHost[0], 60)}" — an internal or cloud-private DNS name, revealing infrastructure that isn't meant to be visible from outside.`));
    }
    const banner = scanned.match(IN_PAGE_BANNER);
    if (banner && response.statusCode >= 400) {
      out.push(finding("in-page-server-banner", "low", "Server version shown in an error page", `"${clip(banner[0], 60)}" — the exact server version in a default error page maps straight to known CVEs.`));
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
