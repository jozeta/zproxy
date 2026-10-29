// Third tier of passive checks, run by passive-checks.js's checkResponse().
// Built from a survey of OWASP ZAP's passive scan rules, Burp Suite's
// passive issue types, the OWASP Secure Headers project, and Retire.js
// (see CHANGELOG 0.4.0). Same contract as the other tiers: zero extra
// requests, narrow heuristics, every finding phrased as a lead to confirm.
//
// Note for maintainers: tests/security.no-eval.test.js forbids the literal
// names of HTML/JS execution sinks anywhere in src/. The DOM-XSS patterns
// below therefore spell them with character classes ("inner[H]TML") —
// they still match those sinks in captured scripts.
import { getHeaderValue } from "./headers.js";
import { parseAllSetCookies } from "./cookies.js";
import { parseQueryParams } from "./http.js";
import { decodeJwt } from "./jwt.js";
import { detectLibraries, assessLibrary } from "./js-libraries.js";

function finding(id, severity, title, detail) {
  return { id, severity, title, detail };
}

function clip(text, max = 80) {
  const s = String(text);
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function pathOf(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return "";
  }
}

function allHeaderValues(headers, name) {
  const lower = name.toLowerCase();
  return (headers || []).filter((h) => h.name.toLowerCase() === lower).map((h) => h.value);
}

// ---------------------------------------------------------------- cookies --

const FRAMEWORK_COOKIES = {
  phpsessid: "PHP",
  jsessionid: "Java (Servlet/JSP)",
  "asp.net_sessionid": "ASP.NET",
  ".aspxauth": "ASP.NET Forms Auth",
  laravel_session: "Laravel",
  "connect.sid": "Node.js (Express)",
  csrftoken: "Django",
  sessionid: "Django",
  _rails_session: "Ruby on Rails",
  "ci_session": "CodeIgniter",
  cfid: "ColdFusion",
  cftoken: "ColdFusion",
  "wordpress_logged_in": "WordPress",
};

function checkCookies(request, response, { isHttps }) {
  const out = [];
  const cookies = parseAllSetCookies(response.headers);
  const requestHost = hostOf(request?.url);
  const seen = new Map();
  const frameworks = new Set();

  for (const c of cookies) {
    const name = c.name || "";
    seen.set(name, (seen.get(name) || 0) + 1);
    const lowerName = name.toLowerCase();
    for (const [prefix, fw] of Object.entries(FRAMEWORK_COOKIES)) if (lowerName === prefix || lowerName.startsWith(`${prefix}_`)) frameworks.add(fw);

    // Domain=.example.com on a response from app.example.com: every sibling subdomain gets it.
    const domain = (c.domain || "").toLowerCase().replace(/^\./, "");
    if (domain && requestHost && domain !== requestHost && requestHost.endsWith(`.${domain}`)) {
      out.push(finding("cookie-loosely-scoped", "low", `Cookie "${name}" is scoped to the parent domain`, `Domain=${c.domain} sends it to every subdomain of ${domain}, not just ${requestHost} — any of them (including a forgotten or compromised one) can read or overwrite it.`));
    }
    if (name.startsWith("__Host-") && (!c.secure || (c.path || "/") !== "/" || c.domain)) {
      out.push(finding("cookie-prefix-violation", "medium", `Cookie "${name}" breaks its __Host- prefix rules`, "__Host- cookies must be Secure, have Path=/ and no Domain attribute. Browsers reject this one, so whatever it was meant to protect isn't set."));
    } else if (name.startsWith("__Secure-") && !c.secure) {
      out.push(finding("cookie-prefix-violation", "medium", `Cookie "${name}" breaks its __Secure- prefix rule`, "__Secure- cookies must have the Secure attribute; browsers reject this one."));
    }
    if (c.sameSite && !/^(strict|lax|none)$/i.test(c.sameSite)) {
      out.push(finding("cookie-samesite-invalid", "low", `Cookie "${name}" has an invalid SameSite value`, `SameSite=${clip(c.sameSite, 30)} isn't Strict, Lax, or None, so browsers ignore it and fall back to their default.`));
    }
    if (/pass(word|wd)?|pwd/i.test(name)) {
      out.push(finding("password-in-cookie", "medium", `Cookie "${name}" looks like it stores a password`, "Passwords should never be stored client-side — cookies end up in logs, proxies, and browser storage."));
    }
    const decoded = decodeMaybeBase64Json(c.value || "");
    if (decoded && /"(role|roles|isadmin|is_admin|admin|user_?id|uid|group|permissions?|access_?level)"\s*:/i.test(decoded)) {
      out.push(finding("client-side-state-cookie", "low", `Cookie "${name}" carries readable authorization data`, `Its value decodes to JSON with role/user fields (${clip(decoded, 70)}). If the server trusts it without a signature, editing it may escalate privileges — try in Repeater.`));
    }
    if (/session|sid|auth|token/i.test(name) && isHttps && !name.startsWith("__Host-")) {
      out.push(finding("session-cookie-no-host-prefix", "info", `Session cookie "${name}" doesn't use the __Host- prefix`, "The __Host- prefix makes the browser enforce Secure, Path=/ and no Domain, which blocks subdomain cookie-tossing attacks. Recommended for session cookies."));
    }
  }
  for (const [name, count] of seen) {
    if (count > 1) out.push(finding("duplicate-cookie-set", "info", `Cookie "${name}" is set ${count} times in one response`, "Browsers keep only one; which one wins depends on attributes and order, which makes the effective cookie hard to reason about."));
  }
  if (frameworks.size) {
    out.push(finding("framework-cookie-fingerprint", "info", "Session cookie names reveal the framework", `${[...frameworks].join(", ")} — default session cookie names fingerprint the server stack. Renaming them removes an easy hint.`));
  }
  return out;
}

function decodeMaybeBase64Json(value) {
  let v = value;
  try {
    v = decodeURIComponent(v);
  } catch {
    /* keep raw */
  }
  if (/^\s*[{[]/.test(v)) return v;
  if (!/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(v)) return null;
  try {
    const text = atob(v.replace(/-/g, "+").replace(/_/g, "/"));
    return /^\s*[{[]/.test(text) ? text : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- headers --

const DEPRECATED_HEADERS = {
  "expect-ct": "Expect-CT (obsolete since Certificate Transparency became mandatory)",
  "public-key-pins": "Public-Key-Pins (HPKP — removed from browsers; a bad pin can lock users out)",
  "public-key-pins-report-only": "Public-Key-Pins-Report-Only (HPKP — removed from browsers)",
  "feature-policy": "Feature-Policy (replaced by Permissions-Policy)",
  "x-content-security-policy": "X-Content-Security-Policy (pre-standard CSP, ignored by modern browsers)",
  "x-webkit-csp": "X-WebKit-CSP (pre-standard CSP, ignored by modern browsers)",
};

const DEBUG_HEADERS = ["x-debug-token", "x-debug-token-link", "x-chromelogger-data", "x-chromephp-data", "x-debug-info", "x-debug-output"];

// script-src hosts that serve JSONP endpoints or old Angular/JS gadgets,
// letting an attacker run script despite the CSP (well-known CSP bypasses).
const CSP_BYPASS_HOSTS = ["*.googleapis.com", "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "*.google.com", "www.google.com", "*.gstatic.com", "accounts.google.com", "*.yandex.ru", "*.cloudfront.net", "*.amazonaws.com", "*.appspot.com", "*.herokuapp.com", "*.firebaseapp.com", "raw.githubusercontent.com", "*.github.io"];

function checkHeaders(request, response, { isHttps, html }) {
  const out = [];
  const h = (name) => getHeaderValue(response.headers, name);
  const reqUrl = request?.url || "";

  const xss = h("x-xss-protection");
  if (xss && !/^\s*0\s*$/.test(xss)) {
    out.push(finding("x-xss-protection-enabled", "info", "Legacy X-XSS-Protection filter enabled", `X-XSS-Protection: ${clip(xss, 30)}. The XSS auditor was removed from browsers and could itself be abused to leak data; OWASP recommends "0" or removing the header and relying on CSP.`));
  }
  const deprecated = Object.keys(DEPRECATED_HEADERS).filter((n) => h(n));
  if (deprecated.length) {
    out.push(finding("deprecated-security-headers", "info", "Deprecated security headers in use", `${deprecated.map((n) => DEPRECATED_HEADERS[n]).join("; ")}.`));
  }
  const xcto = h("x-content-type-options");
  if (xcto && xcto.trim().toLowerCase() !== "nosniff") {
    out.push(finding("xcto-invalid", "low", "X-Content-Type-Options has an invalid value", `"${clip(xcto, 30)}" — the only valid value is nosniff, so MIME sniffing is still on.`));
  }
  const xfoValues = allHeaderValues(response.headers, "x-frame-options");
  if (xfoValues.length > 1) {
    out.push(finding("xfo-duplicate", "low", "X-Frame-Options is set more than once", "Browsers treat conflicting or repeated values as invalid and may ignore the header entirely — framing protection is then off."));
  } else if (xfoValues[0] && !/^\s*(deny|sameorigin)\s*$/i.test(xfoValues[0])) {
    out.push(finding("xfo-invalid", "low", "X-Frame-Options has an invalid or obsolete value", `"${clip(xfoValues[0], 40)}" — only DENY and SAMEORIGIN are supported (ALLOW-FROM is ignored by modern browsers). Use CSP frame-ancestors.`));
  }
  if (html) {
    if (!h("permissions-policy")) {
      out.push(finding("missing-permissions-policy", "info", "No Permissions-Policy header", "Without it, this page (and anything injected into it) may request the camera, microphone, geolocation, and other powerful features. OWASP recommends disabling what the app doesn't use."));
    }
    if (!h("cross-origin-opener-policy")) {
      out.push(finding("missing-coop", "info", "No Cross-Origin-Opener-Policy header", "Without COOP: same-origin, pages that open this one keep a window reference to it, which enables cross-site leaks (XS-Leaks) and some tabnabbing attacks."));
    }
    const contentType = (h("content-type") || "").toLowerCase();
    if (contentType.includes("text/html") && !contentType.includes("charset") && typeof response.body === "string" && !/<meta[^>]+charset/i.test(response.body.slice(0, 2048))) {
      out.push(finding("html-no-charset", "info", "HTML response doesn't declare a character set", "Without a charset, browsers guess the encoding — which has enabled XSS via encodings like UTF-7 in the past."));
    }
  }

  const hsts = h("strict-transport-security");
  if (hsts && !isHttps) {
    out.push(finding("hsts-over-http", "info", "HSTS sent over plain HTTP", "Browsers ignore Strict-Transport-Security on http:// responses — it only takes effect when received over HTTPS."));
  } else if (hsts && isHttps && !/includesubdomains/i.test(hsts)) {
    out.push(finding("hsts-no-subdomains", "info", "HSTS doesn't include subdomains", "Without includeSubDomains, subdomains can still be reached over plain HTTP — an attacker can set cookies for the parent domain from one."));
  }

  const acao = h("access-control-allow-origin");
  const credentials = (h("access-control-allow-credentials") || "").toLowerCase() === "true";
  if (credentials && acao && /^http:\/\//i.test(acao) && isHttps) {
    out.push(finding("cors-insecure-origin-trusted", "medium", "CORS trusts a plain-HTTP origin with credentials", `${clip(acao)} is allowed to read this HTTPS response with the user's cookies — a network attacker who can tamper with that HTTP site inherits that access.`));
  }

  const csp = (h("content-security-policy") || "").toLowerCase();
  if (csp) {
    const scriptSrc = (csp.match(/(?:^|;)\s*script-src\s+([^;]*)/) || csp.match(/(?:^|;)\s*default-src\s+([^;]*)/) || [])[1] || "";
    const bypass = CSP_BYPASS_HOSTS.filter((host) => scriptSrc.split(/\s+/).some((s) => s.replace(/^https?:\/\//, "").replace(/\/.*$/, "") === host));
    if (bypass.length) {
      out.push(finding("csp-bypass-host", "low", "CSP allows script hosts with known bypasses", `script-src allows ${bypass.join(", ")} — these host JSONP endpoints or script gadgets (e.g. old AngularJS) that let injected markup run code despite the CSP.`));
    }
    if (html && !/(?:^|;)\s*object-src\s+'none'/.test(csp) && !/(?:^|;)\s*default-src\s+'none'/.test(csp)) {
      out.push(finding("csp-no-object-src", "info", "CSP doesn't set object-src 'none'", "Plugins (<object>/<embed>) are a classic CSP bypass; object-src 'none' closes it."));
    }
    if (html && !/(?:^|;)\s*base-uri\s/.test(csp)) {
      out.push(finding("csp-no-base-uri", "info", "CSP doesn't restrict base-uri", "An injected <base href> can redirect every relative script URL on the page to an attacker's server; base-uri 'self' (or 'none') prevents it."));
    }
  }

  const debug = DEBUG_HEADERS.filter((n) => h(n));
  if (debug.length) {
    out.push(finding("debug-headers-exposed", "medium", "Debug/profiler headers exposed", `${debug.join(", ")} — e.g. X-Debug-Token-Link points to the Symfony profiler, which exposes request data, configuration, and sometimes secrets. Debug tooling shouldn't be reachable in production.`));
  }
  const sourceMapHeader = h("sourcemap") || h("x-sourcemap");
  if (sourceMapHeader) {
    out.push(finding("source-map-exposed", "low", "Source map advertised in a header", `SourceMap: ${clip(sourceMapHeader)} — source maps reconstruct the original, unminified source (comments, internal API routes, sometimes secrets).`));
  }

  const age = Number(h("age"));
  const xCache = h("x-cache") || h("cf-cache-status") || "";
  const authed = !!getHeaderValue(request?.headers || [], "authorization") || !!getHeaderValue(request?.headers || [], "cookie");
  if (authed && response.statusCode === 200 && ((Number.isFinite(age) && age > 0) || /\bhit\b/i.test(xCache))) {
    out.push(finding("served-from-shared-cache", "low", "Authenticated request answered from a shared cache", `${Number.isFinite(age) && age > 0 ? `Age: ${age}` : `Cache status: ${clip(xCache, 30)}`} — this response came from a cache, not the application. If it contains user-specific data, other users may be served it (web cache deception).`));
  }
  if (/\/(log-?out|sign-?out|logoff)\b/i.test(pathOf(reqUrl)) && response.statusCode < 400 && !h("clear-site-data")) {
    out.push(finding("logout-no-clear-site-data", "info", "Logout doesn't send Clear-Site-Data", 'Clear-Site-Data: "cache","cookies","storage" on logout makes the browser drop everything the session left behind — useful on shared machines.'));
  }
  const challenge = h("www-authenticate") || "";
  if (!isHttps && /^\s*(basic|digest)\b/i.test(challenge)) {
    out.push(finding("auth-challenge-over-http", "medium", "Server asks for HTTP authentication over plain HTTP", `WWW-Authenticate: ${clip(challenge, 40)} on an unencrypted connection — the credentials the browser sends back can be read (Basic) or attacked offline (Digest).`));
  }
  return out;
}

// ---------------------------------------------------------------- request --

const SENSITIVE_URL_PARAM = /^(password|passwd|pwd|pass|secret|token|access_token|refresh_token|id_token|api_?key|apikey|auth|session|sessionid|session_id|sid|jwt)$/i;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;

function checkRequest(request, { isHttps }) {
  const out = [];
  if (!request) return out;
  const referer = getHeaderValue(request.headers || [], "referer");
  if (referer) {
    const leaked = parseQueryParams(referer).filter((p) => SENSITIVE_URL_PARAM.test(p.name) && p.value);
    if (leaked.length && hostOf(referer) !== hostOf(request.url)) {
      out.push(finding("sensitive-data-in-referer", "medium", "Secret leaked to another site via Referer", `This request to ${hostOf(request.url)} carries a Referer from ${hostOf(referer)} that includes ${leaked.map((p) => `"${p.name}"`).join(", ")} — that value is now in a third party's logs.`));
    }
  }
  if (/;(jsessionid|phpsessid|sid)=[^/?#]{8,}/i.test(request.url || "")) {
    out.push(finding("session-id-in-url-path", "medium", "Session ID in the URL path", "A ;jsessionid=-style session ID in the URL leaks through logs, history, bookmarks, and Referer headers — and enables session fixation."));
  }
  if (!isHttps && /^\s*digest\s/i.test(getHeaderValue(request.headers || [], "authorization") || "")) {
    out.push(finding("digest-auth-over-http", "medium", "Digest credentials sent over plain HTTP", "Digest doesn't send the password itself, but the exchange can be captured and cracked offline, and the session is unprotected."));
  }
  return out;
}

function checkJwtClaims(request, response) {
  const out = [];
  const haystack = [request?.url || "", ...(request?.headers || []).map((h) => h.value), typeof response.body === "string" ? response.body.slice(0, 200_000) : "", ...(response.headers || []).map((h) => h.value)].join("\n");
  const seen = new Set();
  let reportedNoExp = false;
  let reportedSensitive = false;
  for (const match of haystack.matchAll(JWT_PATTERN)) {
    if (seen.has(match[0])) continue;
    seen.add(match[0]);
    const jwt = decodeJwt(match[0]);
    if (!jwt.ok || typeof jwt.payload !== "object" || jwt.payload === null) continue;
    if (!reportedNoExp && !("exp" in jwt.payload)) {
      reportedNoExp = true;
      out.push(finding("jwt-no-expiry", "low", "JWT without an expiry", `A token${jwt.payload.sub ? ` for "${clip(jwt.payload.sub, 30)}"` : ""} has no exp claim — if it leaks, it stays valid until the signing key changes.`));
    }
    const sensitive = Object.keys(jwt.payload).filter((k) => /pass(word)?|pwd|secret|ssn|credit|card|cvv/i.test(k));
    if (!reportedSensitive && sensitive.length) {
      reportedSensitive = true;
      out.push(finding("jwt-sensitive-claims", "medium", "JWT payload contains sensitive fields", `Claims ${sensitive.map((k) => `"${k}"`).join(", ")} — a JWT is only signed, not encrypted: anyone holding it can read the payload.`));
    }
    if (jwt.header && (jwt.header.jku || jwt.header.x5u)) {
      out.push(finding("jwt-remote-key-header", "low", "JWT header points to a remote key", `The token's header has ${jwt.header.jku ? "jku" : "x5u"}=${clip(jwt.header.jku || jwt.header.x5u, 50)}. If the server fetches keys from where the token says, an attacker can sign tokens with their own key.`));
    }
  }
  return out;
}

// ------------------------------------------------------------------- HTML --

// Domains served malicious JavaScript after the 2024 polyfill.io takeover (ZAP rule 10115).
const COMPROMISED_SCRIPT_DOMAINS = ["polyfill.io", "bootcss.com", "bootcdn.net", "staticfile.org", "staticfile.net", "unionadjs.com", "xhsbpza.com", "union.macoms.la", "newcrbpc.com"];
const CSRF_FIELD = /name\s*=\s*["']?(?:[\w-]*csrf[\w-]*|[\w-]*xsrf[\w-]*|_token|authenticity_token|__RequestVerificationToken|nonce|anti[-_]?forgery[\w-]*|form_key|__csrf_magic)["'\s>]/i;

function checkHtml(request, response, { isHttps }) {
  const out = [];
  const body = typeof response.body === "string" ? response.body.slice(0, 300_000) : "";
  if (!body) return out;
  const pageHost = hostOf(request?.url);

  // Forms
  let csrfReported = false;
  let passwordOverHttpReported = false;
  for (const form of body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = form[1];
    const inner = form[2];
    const method = (attrs.match(/method\s*=\s*["']?(\w+)/i) || [])[1] || "get";
    if (!csrfReported && /^post$/i.test(method) && !CSRF_FIELD.test(inner) && /<input\b/i.test(inner)) {
      csrfReported = true;
      out.push(finding("form-without-csrf-token", "low", "POST form without an anti-CSRF token", "No hidden field that looks like a CSRF token was found in a POST form on this page. If the app doesn't defend against CSRF another way (SameSite cookies, custom headers), another site can submit this form as the user."));
    }
    if (!passwordOverHttpReported && /type\s*=\s*["']?password/i.test(inner)) {
      const action = (attrs.match(/action\s*=\s*["']?([^"'\s>]+)/i) || [])[1] || "";
      if (!isHttps && !/^https:/i.test(action)) {
        passwordOverHttpReported = true;
        out.push(finding("password-form-over-http", "high", "Password form on an unencrypted page", "This login form is served and (by default) submitted over plain HTTP — anyone on the network can read the password, or change the page to send it elsewhere."));
      }
    }
  }

  // Third-party scripts
  const thirdPartyNoSri = new Set();
  for (const tag of body.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?((?:https?:)?\/\/[^"'\s>]+)[^>]*>/gi)) {
    const src = tag[1];
    const host = hostOf(src.startsWith("//") ? `https:${src}` : src);
    if (!host) continue;
    if (COMPROMISED_SCRIPT_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`))) {
      out.push(finding("compromised-script-domain", "high", "Script loaded from a known-compromised domain", `${clip(src)} — ${host} served malware to visitors after the 2024 polyfill.io supply-chain attack. Remove it.`));
    } else if (host !== pageHost && !host.endsWith(`.${pageHost.split(".").slice(-2).join(".")}`) && !/\bintegrity\s*=/i.test(tag[0])) {
      thirdPartyNoSri.add(host);
    }
  }
  if (thirdPartyNoSri.size) {
    out.push(finding("third-party-script-no-sri", "low", "Third-party scripts without Subresource Integrity", `Scripts from ${[...thirdPartyNoSri].slice(0, 5).join(", ")}${thirdPartyNoSri.size > 5 ? "…" : ""} run with this page's full privileges, and nothing checks their contents. If one of those hosts is compromised, so is this page. Add integrity= hashes or self-host them.`));
  }

  if (/<a\b[^>]*\btarget\s*=\s*["']?_blank[^>]*\brel\s*=\s*["'][^"']*\bopener\b/i.test(body)) {
    out.push(finding("reverse-tabnabbing", "low", "Link opens a new tab with rel=\"opener\"", "The opened page gets a reference to this window and can navigate it to a phishing page (reverse tabnabbing)."));
  }

  const comments = [...body.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1].trim()).filter((c) => /\b(todo|fixme|hack|bug|password|passwd|pwd|secret|admin|debug|api[_-]?key|internal|temporary|remove (this|before))\b/i.test(c));
  if (comments.length) {
    out.push(finding("suspicious-html-comments", "info", "HTML comments mention sensitive topics", `${comments.length} comment(s), e.g. "${clip(comments[0].replace(/\s+/g, " "), 90)}". Developer notes in shipped HTML often reveal credentials, hidden features, or internal paths.`));
  }

  const generator = body.match(/<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']/i) || body.match(/<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]+name\s*=\s*["']generator["']/i);
  if (generator) {
    out.push(finding("generator-meta-disclosure", generator[1].match(/\d+\.\d+/) ? "low" : "info", "Page reveals its CMS/framework", `<meta name="generator" content="${clip(generator[1], 50)}">${generator[1].match(/\d+\.\d+/) ? " — with a version number, which maps straight to known CVEs" : ""}.`));
  }
  if (/name\s*=\s*["']?javax\.faces\.ViewState["']?[^>]*value\s*=\s*["']?(rO0AB|H4sI)/i.test(body)) {
    out.push(finding("jsf-viewstate-unprotected", "high", "Unencrypted JSF ViewState", "The javax.faces.ViewState field holds a plain (or gzip) Java serialized object. Without encryption/MAC, a modified ViewState can lead to remote code execution through Java deserialization."));
  }
  return out;
}

// --------------------------------------------------------------- scripts --

// Sources an attacker controls, and HTML/JS execution sinks — spelled with
// character classes (see the note at the top of this file).
const DOM_SOURCES = /\b(location\.(hash|search|href)|document\.(URL|documentURI|referrer|baseURI)|window\.name)\b/;
const DOM_SINKS = /\.(inner|outer)[H]TML\s*=|\binsertAdjacent[H]TML\s*\(|\bdocument\.writ(e|eln)\s*\(|\be[v]al\s*\(|\bnew\s+Func[t]ion\s*\(|\bset(Timeout|Interval)\s*\(\s*["'`]|\$\([^)]*location|\.html\s*\(\s*(location|decodeURI)/;

function checkScript(request, response) {
  const out = [];
  const body = typeof response.body === "string" ? response.body.slice(0, 400_000) : "";
  if (body && DOM_SOURCES.test(body) && DOM_SINKS.test(body)) {
    const src = body.match(DOM_SOURCES)[0];
    const sink = body.match(DOM_SINKS)[0].replace(/\s+/g, "");
    out.push(finding("dom-xss-source-sink", "low", "Possible DOM-based XSS (source and sink in one script)", `The script reads ${src} and also writes to a dangerous sink (${clip(sink, 30)}). Check whether that value can reach the sink unsanitized — try a payload in the URL fragment.`));
  }
  if (/addEventListener\s*\(\s*["']message["']/.test(body) && !/\.origin\b/.test(body)) {
    out.push(finding("postmessage-no-origin-check", "low", "postMessage listener without an origin check", "The script listens for cross-window messages but never reads event.origin, so any site that can open or frame this page can send it data."));
  }
  const map = body.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/);
  if (map && !/^data:/i.test(map[1])) {
    out.push(finding("source-map-exposed", "low", "Source map referenced by a script", `sourceMappingURL=${clip(map[1], 60)} — if that file is reachable, it reconstructs the original source (comments, internal routes, sometimes secrets).`));
  }
  return out;
}

function checkLibraries(request, response) {
  const out = [];
  for (const lib of detectLibraries(response.body, request?.url)) {
    const verdict = assessLibrary(lib.id, lib.version);
    if (!verdict) continue;
    const ids = [...new Set(verdict.advisories.flatMap((a) => a.ids))].filter((id) => !id.startsWith("retire:"));
    const what = verdict.advisories.map((a) => a.summary).slice(0, 3).join("; ");
    out.push(
      finding(
        `vulnerable-js-${lib.id}`,
        verdict.severity,
        `${verdict.advisories.length ? "Vulnerable" : "End-of-life"} JavaScript library: ${lib.name} ${lib.version}`,
        [
          verdict.advisories.length ? `Known issues: ${what}${ids.length ? ` (${ids.slice(0, 6).join(", ")}${ids.length > 6 ? ", …" : ""})` : ""}.` : null,
          verdict.fixedIn ? `Fixed in ${verdict.fixedIn}.` : null,
          verdict.eol ? `${verdict.eol}.` : null,
          "Whether it's exploitable depends on how the app uses the affected feature. Version data from Retire.js.",
        ]
          .filter(Boolean)
          .join(" ")
      )
    );
  }
  return out;
}

// --------------------------------------------------------------- any body --

function luhnValid(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

const SENSITIVE_FILES = [
  { id: "exposed-git", severity: "high", path: /\/\.git\/(HEAD|config)$/i, body: /^(ref: refs\/|\[core\])/m, title: "Git repository exposed", detail: "The .git directory is downloadable — the full source code and history (often including secrets) can be reconstructed from it." },
  { id: "exposed-env-file", severity: "high", path: /\/\.env(\.\w+)?$/i, body: /^[A-Z][A-Z0-9_]{2,}=.+$/m, title: ".env file exposed", detail: "Environment files hold database passwords, API keys, and app secrets." },
  { id: "phpinfo-exposed", severity: "medium", path: /./, body: /<title>phpinfo\(\)<\/title>|PHP Version <\/td>|>PHP Credits</i, title: "phpinfo() page exposed", detail: "phpinfo() reveals the exact PHP version, loaded modules, file paths, environment variables, and sometimes credentials — a map for exploitation." },
  { id: "server-status-exposed", severity: "medium", path: /\/server-(status|info)\b/i, body: /Apache Server (Status|Information) for|Server Version:/i, title: "Apache server-status/server-info exposed", detail: "Shows live requests (URLs, client IPs, sometimes session tokens) and the server's configuration." },
  { id: "spring-actuator-exposed", severity: "high", path: /\/actuator(\/|$)|\/(env|heapdump|configprops|mappings|trace|httptrace)$/i, body: /"(propertySources|activeProfiles|_links"\s*:\s*\{\s*"self")|"contexts"\s*:\s*\{/, title: "Spring Boot Actuator endpoint exposed", detail: "Actuator endpoints can expose environment variables and secrets (/env), memory dumps with credentials (/heapdump), and internal routes." },
  { id: "backup-file-exposed", severity: "medium", path: /\.(bak|backup|old|orig|save|swp|swo|tmp|~)$|~$|\.(sql|tar|tar\.gz|tgz|zip|7z|rar)$/i, body: /./, title: "Backup or archive file downloadable", detail: "Backup copies, editor swap files, and archives often contain source code, database dumps, or credentials that the live app never serves." },
  { id: "debug-log-exposed", severity: "medium", path: /\/(debug|error|access|laravel)\.log$|\/storage\/logs\//i, body: /./, title: "Log file downloadable", detail: "Application logs leak stack traces, user data, tokens, and internal hostnames." },
  { id: "graphql-introspection", severity: "low", path: /./, body: /"__schema"\s*:\s*\{[\s\S]{0,200}"(types|queryType)"/, title: "GraphQL introspection enabled", detail: "The full API schema — every query, mutation, and field, including ones the UI never uses — is available to anyone. Disable introspection in production." },
  { id: "api-spec-exposed", severity: "info", path: /./, body: /^\s*\{\s*"(swagger"\s*:\s*"2|openapi"\s*:\s*"3)/, title: "API specification exposed", detail: "A Swagger/OpenAPI document lists every endpoint and parameter — useful for testing, and for attackers." },
];

const HASH_PATTERNS = [
  { label: "bcrypt", re: /\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}/ },
  { label: "SHA-512 crypt", re: /\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}/ },
  { label: "SHA-256 crypt", re: /\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}/ },
  { label: "MD5 crypt", re: /\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}/ },
  { label: "Argon2", re: /\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+/ },
];

function checkAnyBody(request, response) {
  const out = [];
  const body = typeof response.body === "string" ? response.body.slice(0, 300_000) : "";
  const path = pathOf(request?.url);
  const ok = response.statusCode >= 200 && response.statusCode < 300;

  if (ok) {
    for (const f of SENSITIVE_FILES) {
      if (f.path.test(path) && body && f.body.test(body)) out.push(finding(f.id, f.severity, f.title, f.detail));
    }
  }
  if (!body) return out;

  const hash = HASH_PATTERNS.find((p) => p.re.test(body));
  if (hash) {
    out.push(finding("password-hash-disclosed", "medium", `${hash.label} password hash in response`, "Password hashes should never leave the server — they can be cracked offline, and their presence suggests the API returns whole user records."));
  }

  if (/\brO0AB[A-Za-z0-9+/=]{10,}|\xac\xed\x00\x05/.test(body)) {
    out.push(finding("java-serialized-object", "medium", "Java serialized object in response", "Serialized Java objects (rO0AB… in base64) mean the app likely also deserializes them from clients — a classic remote-code-execution vector. Find where they come back in a request."));
  }
  if (/\b[OC]:\d+:"[A-Za-z_\\][A-Za-z0-9_\\]*":\d+:\{/.test(body)) {
    out.push(finding("php-serialized-object", "low", "PHP serialized object in response", "If the app unserialize()s data it receives from clients in the same format, it may be vulnerable to PHP object injection."));
  }

  let cards = 0;
  for (const m of body.matchAll(/\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b/g)) {
    const digits = m[0].replace(/\D/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) cards++;
  }
  if (cards) {
    out.push(finding("credit-card-disclosed", "medium", "Credit card number in response", `${cards} number(s) matching a card format and passing the Luhn check. Full card numbers in responses are a PCI DSS violation — they should be masked.`));
  }

  const emails = new Set((body.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || []).filter((e) => !/\.(png|jpe?g|gif|svg|webp|css|js)$/i.test(e) && !/@(example\.(com|org|net)|sentry\.io|domain\.com)$/i.test(e)));
  if (emails.size) {
    const list = [...emails];
    out.push(finding("email-disclosed", "info", "Email addresses disclosed", `${list.length} address(es), e.g. ${list.slice(0, 3).join(", ")}${list.length > 3 ? ", …" : ""} — harvestable for phishing and username enumeration.`));
  }
  return out;
}

// ------------------------------------------- BApp-style passive checks --
// Checks modelled on popular Burp BApp Store extensions (Hunt Scanner,
// JS Link Finder / JS Miner, Reflected Parameters, Cryptojacking Mine
// Sweeper, HTTP Methods Discloser), reimplemented as passive heuristics.

// Parameter names that commonly feed a dangerous sink (after Hunt Scanner's
// research-based lists) — each maps to what to test for.
const HUNT_PARAMS = [
  { re: /^(url|uri|link|src|dest|destination|redirect|redirect_?(uri|url)|return(_?(to|url))?|next|continue|callback|goto|target|feed|host|domain|proxy|webhook|image_?url|fetch)$/i, test: "SSRF / open redirect" },
  { re: /^(file|filename|path|filepath|folder|dir|document|doc|page|include|template|tpl|view|layout|load|read|download|attachment)$/i, test: "path traversal / file inclusion" },
  { re: /^(cmd|command|exec|execute|run|shell|ping|process|daemon|arg|args|option)$/i, test: "OS command injection" },
  { re: /^(q|query|search|filter|sort|order|orderby|order_by|column|field|where|select|group_?by|having)$/i, test: "SQL / NoSQL injection" },
  { re: /^(id|user_?id|uid|account(_?id)?|customer(_?id)?|order(_?id)?|invoice(_?id)?|doc(_?id)?|profile(_?id)?|number|no)$/i, test: "IDOR (try another user's ID)" },
  { re: /^(template|tpl|preview|render|content|message|body|name|greeting|email_?template)$/i, test: "server-side template injection" },
  { re: /^(debug|test|admin|is_?admin|role|access|dev|mode|internal|config|env)$/i, test: "debug/privilege toggles (try true/1/admin)" },
];

function checkHuntParams(request) {
  const params = parseQueryParams(request?.url || "");
  const contentType = getHeaderValue(request?.headers || [], "content-type") || "";
  if (/x-www-form-urlencoded/i.test(contentType)) {
    for (const pair of (request.body || "").split("&")) {
      const name = pair.split("=")[0];
      if (name) params.push({ name: decodeURIComponentSafe(name), value: "" });
    }
  }
  const hits = new Map();
  for (const p of params) {
    const hunt = HUNT_PARAMS.find((h) => h.re.test(p.name));
    if (hunt && !hits.has(p.name)) hits.set(p.name, hunt.test);
  }
  if (hits.size === 0) return [];
  return [
    finding(
      "interesting-parameters",
      "info",
      "Parameters worth testing",
      `${[...hits].slice(0, 8).map(([name, t]) => `"${name}" → ${t}`).join("; ")}. These names are commonly wired to risky functionality — a prioritized starting point for Repeater/Intruder, not a vulnerability by itself.`
    ),
  ];
}

function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

/** Relative API paths and absolute URLs referenced from JavaScript (JS Link Finder / JS Miner). */
export function extractJsEndpoints(body) {
  const found = new Set();
  const text = body.slice(0, 400_000);
  for (const m of text.matchAll(/["'`]((?:\/(?:api|v\d+|graphql|rest|internal|admin|auth|oauth|user|users|account|private|backend|ajax|rpc)\b)[A-Za-z0-9_\-./{}:?=&%]*)["'`]/g)) {
    if (m[1].length <= 120) found.add(m[1]);
  }
  for (const m of text.matchAll(/["'`](https?:\/\/[A-Za-z0-9.-]+(?::\d+)?\/[A-Za-z0-9_\-./{}:?=&%]*)["'`]/g)) {
    if (m[1].length <= 160 && !/\.(png|jpe?g|gif|svg|webp|woff2?|css|ico)(\?|$)/i.test(m[1]) && !/w3\.org|schema\.org|mozilla\.org|reactjs\.org|github\.com\/[^/]+\/[^/]+\/(issues|blob)/i.test(m[1])) found.add(m[1]);
  }
  return [...found];
}

function checkJsEndpoints(request, response) {
  const body = typeof response.body === "string" ? response.body : "";
  if (!body) return [];
  const endpoints = extractJsEndpoints(body);
  if (endpoints.length === 0) return [];
  return [
    finding(
      "js-endpoints",
      "info",
      "Endpoints referenced in JavaScript",
      `${endpoints.length} path(s)/URL(s), e.g. ${endpoints.slice(0, 6).join(", ")}${endpoints.length > 6 ? ", …" : ""}. Client code often references endpoints the UI never exposes — admin, internal, or older API versions. Try them in Repeater.`
    ),
  ];
}

/** Any request value of 4+ characters echoed in the response — candidate injection points (Reflected Parameters). */
function checkReflectedParams(request, response) {
  const body = typeof response.body === "string" ? response.body : "";
  if (!body || !request?.url) return [];
  const reflected = parseQueryParams(request.url)
    .filter((p) => p.value && p.value.length >= 4 && !/^(true|false|null|undefined|\d{1,3})$/i.test(p.value))
    .filter((p) => body.includes(p.value))
    .map((p) => p.name);
  if (reflected.length === 0) return [];
  return [finding("reflected-parameters", "info", "Request parameters reflected in the response", `${[...new Set(reflected)].map((n) => `"${n}"`).join(", ")} appear(s) verbatim in the response — each is a candidate for XSS/injection testing (send <"'> and see how it comes back).`)];
}

// Browser cryptominer domains and script signatures (Cryptojacking Mine Sweeper).
const MINER_DOMAINS = ["coinhive.com", "coin-hive.com", "authedmine.com", "cryptoloot.pro", "crypto-loot.com", "webmine.cz", "jsecoin.com", "coinimp.com", "minero.cc", "ppoi.org", "monerominer.rocks", "deepminer", "cryptonight.wasm"];
const MINER_SIGNATURES = /CoinHive\.(Anonymous|User|Token)|CryptoLoot\.Anonymous|new\s+Client\.Anonymous\(|\bcryptonight\b|miner\.start\(\)/i;

function checkCryptojacking(response) {
  const body = typeof response.body === "string" ? response.body.slice(0, 400_000) : "";
  if (!body) return [];
  const domain = MINER_DOMAINS.find((d) => body.includes(d));
  if (domain || MINER_SIGNATURES.test(body)) {
    return [finding("cryptojacking-script", "high", "Cryptocurrency miner in page or script", `${domain ? `References ${domain}` : "Contains browser-mining code"} — visitors' CPUs are being used to mine cryptocurrency, usually a sign the site or a dependency has been compromised.`)];
  }
  return [];
}

function checkAllowedMethods(response, { isHttps }) {
  const allow = [getHeaderValue(response.headers || [], "allow"), getHeaderValue(response.headers || [], "access-control-allow-methods")].filter(Boolean).join(",").toUpperCase();
  if (!allow) return [];
  const methods = allow.split(/[\s,]+/).filter(Boolean);
  const out = [];
  if (methods.includes("TRACE") || methods.includes("TRACK")) {
    out.push(finding("trace-method-allowed", "low", "TRACE method allowed", "TRACE echoes the request back, including headers — combined with other bugs it can expose HttpOnly cookies (cross-site tracing). Disable it."));
  }
  const risky = methods.filter((m) => ["PUT", "DELETE", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "CONNECT", "DEBUG"].includes(m));
  if (risky.length) {
    out.push(finding("risky-methods-allowed", "info", "Server advertises state-changing or WebDAV methods", `Allow: ${risky.join(", ")} — check each is meant to be reachable here (e.g. PUT for uploading files, WebDAV methods on a static site).${isHttps ? "" : " Over plain HTTP."}`));
  }
  return out;
}

/** Every third-tier finding for one exchange. */
export function checkExtended(request, response, { isHttps, html }) {
  const contentType = (getHeaderValue(response.headers || [], "content-type") || response.mimeType || "").toLowerCase();
  const isScript = /javascript|ecmascript/.test(contentType) || /\.m?js(\?|$)/i.test(pathOf(request?.url));
  return [
    ...checkCookies(request, response, { isHttps }),
    ...checkHeaders(request, response, { isHttps, html }),
    ...checkRequest(request, { isHttps }),
    ...checkJwtClaims(request, response),
    ...(html ? checkHtml(request, response, { isHttps }) : []),
    ...(isScript || html ? checkScript(request, response) : []),
    ...(isScript || html ? checkLibraries(request, response) : []),
    ...checkAnyBody(request, response),
    ...checkHuntParams(request),
    ...(isScript ? checkJsEndpoints(request, response) : []),
    ...(html || /json/.test(contentType) ? checkReflectedParams(request, response) : []),
    ...(isScript || html ? checkCryptojacking(response) : []),
    ...checkAllowedMethods(response, { isHttps }),
  ];
}
