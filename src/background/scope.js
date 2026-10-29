// Scope determines which hosts ZProxy will ever look at, for both the
// always-on history capture (webRequest) and debugger-based interception.
// Deliberately fails CLOSED: an empty/disabled scope means "capture nothing",
// not "capture everything" — see docs/THREAT_MODEL.md C2.

export function hostMatchesPattern(host, pattern) {
  if (!pattern) return false;
  const normalizedHost = host.toLowerCase();
  const normalizedPattern = pattern.toLowerCase().trim();
  if (normalizedPattern.startsWith("*.")) {
    const base = normalizedPattern.slice(2);
    return normalizedHost === base || normalizedHost.endsWith(`.${base}`);
  }
  if (normalizedPattern.includes("*")) {
    const escaped = normalizedPattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    try {
      return new RegExp(`^${escaped}$`).test(normalizedHost);
    } catch {
      return false;
    }
  }
  return normalizedHost === normalizedPattern;
}

/**
 * Splits a scope pattern of the form `[scheme://]host[:port][/path]` into
 * its parts — every part but the host optional, so a plain host pattern
 * ("example.com", "*.example.com") parses exactly as it always did. The
 * path is a glob (`*` = any run of characters) matched as a PREFIX of the
 * URL's pathname: "/api/" covers "/api/users" and "/api/v2/x". (Note
 * "/api" would also cover "/apifoo" — end it with "/" to stop at a segment.)
 */
export function parseScopePattern(pattern) {
  let rest = (pattern || "").trim().toLowerCase();
  let scheme = null;
  const schemeMatch = rest.match(/^([a-z][a-z0-9+.-]*):\/\//);
  if (schemeMatch) {
    scheme = schemeMatch[1];
    rest = rest.slice(schemeMatch[0].length);
  }
  let path = null;
  const slash = rest.indexOf("/");
  if (slash !== -1) {
    path = rest.slice(slash);
    rest = rest.slice(0, slash);
  }
  let port = null;
  // A bracketed IPv6 literal ("[::1]:8080") has colons of its own.
  const portMatch = rest.match(/^(\[[^\]]*\]|[^:]*):(\d+)$/);
  if (portMatch) {
    rest = portMatch[1];
    port = portMatch[2];
  }
  return { scheme, host: rest, port, path };
}

/** True when the pattern restricts more than the host (scheme, port, or path). */
export function isHostOnlyPattern(pattern) {
  const parsed = parseScopePattern(pattern);
  return !parsed.scheme && !parsed.port && !parsed.path;
}

const DEFAULT_PORTS = { "http:": "80", "https:": "443", "ws:": "80", "wss:": "443" };

function pathMatchesGlob(pathname, glob) {
  const source = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  try {
    return new RegExp(`^${source}`).test(pathname.toLowerCase());
  } catch {
    return false;
  }
}

/** Matches an already-parsed URL against one scope pattern (see parseScopePattern). */
export function urlMatchesScopePattern(parsedUrl, pattern) {
  const p = parseScopePattern(pattern);
  // .hostname (not .host) — .host includes a non-default port
  // ("localhost:8787"), which would never match a plain "localhost"
  // pattern and silently fail every request on any target that isn't
  // running on the default port for its scheme (extremely common for
  // local dev servers, including examples/test-lab). Ports are only
  // compared when the pattern names one.
  if (!hostMatchesPattern(parsedUrl.hostname, p.host)) return false;
  if (p.scheme && `${p.scheme}:` !== parsedUrl.protocol) return false;
  if (p.port && p.port !== (parsedUrl.port || DEFAULT_PORTS[parsedUrl.protocol])) return false;
  if (p.path && !pathMatchesGlob(parsedUrl.pathname, p.path)) return false;
  return true;
}

export function isInScope(url, scopeConfig) {
  if (!scopeConfig || !scopeConfig.enabled) return false;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const excluded = (scopeConfig.exclude || []).some((p) => urlMatchesScopePattern(parsed, p));
  if (excluded) return false;

  const include = scopeConfig.include || [];
  if (include.length === 0) return false;
  return include.some((p) => urlMatchesScopePattern(parsed, p));
}

export const DEFAULT_SCOPE = Object.freeze({
  enabled: false,
  include: [],
  exclude: [],
});

/**
 * Adds `host` to an Include pattern and turns Scope on, used when the user
 * clicks Intercept on a tab — "attach to this tab" should mean "this tab's
 * host is in scope," not silently pausing nothing until they separately
 * find and configure Scope. A no-op if an existing pattern already covers
 * the host (including via a *.domain wildcard), so it never creates
 * needless duplicate/narrower entries.
 */
export function addHostToScope(scopeConfig, host) {
  const base = scopeConfig || DEFAULT_SCOPE;
  const include = base.include ? [...base.include] : [];
  // Only a host-only pattern covers the whole host — "example.com/api/"
  // doesn't, so attaching to a tab on that host still adds the plain host.
  const alreadyCovered = include.some((p) => isHostOnlyPattern(p) && hostMatchesPattern(host, p));
  return {
    enabled: true,
    include: alreadyCovered ? include : [...include, host],
    exclude: base.exclude ? [...base.exclude] : [],
  };
}

// Two-label public suffixes ("co.uk") under which the registrable domain
// needs three labels. Not the full Public Suffix List — ZProxy bundles no
// data files — just the common ones, so "shop.example.co.uk" becomes
// "*.example.co.uk" and never "*.co.uk" (which would put every site in the
// country in scope). A suffix missing from this table makes the pattern one
// label too broad for that country, so the Scope view always shows the
// exact pattern on the button before anything is added.
const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "sch.uk", "nhs.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "govt.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my",
  "co.in", "net.in", "org.in", "gov.in", "co.za", "org.za", "gov.za", "com.br", "net.br", "org.br", "gov.br", "com.ar", "com.mx", "gob.mx",
  "com.tr", "gov.tr", "com.ua", "co.il", "org.il", "gov.il", "com.sa", "com.eg", "com.ng", "co.ke", "co.id", "or.id", "go.id", "com.ph", "com.vn", "co.th", "in.th",
]);

/**
 * The Scope pattern for "this site including its subdomains", from a page's
 * hostname: the registrable domain as a wildcard — app.shop.example.com →
 * "*.example.com" (which also matches example.com itself). IP addresses,
 * single-label hosts (localhost), and anything that would reduce to a bare
 * public suffix get the exact hostname instead. Returns null for an empty
 * or non-host value.
 */
export function domainScopePattern(hostname) {
  const host = (hostname || "").trim().toLowerCase().replace(/\.$/, "");
  if (!host || /[\s/:]/.test(host.replace(/^\[.*\]$/, "x"))) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) return host; // IPv4/IPv6 literal
  const labels = host.split(".");
  if (labels.length === 1) return host; // localhost, intranet names
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) {
    return labels.length >= 3 ? `*.${labels.slice(-3).join(".")}` : host;
  }
  return `*.${lastTwo}`;
}

/**
 * Adds `pattern` to Include and switches Scope on — a no-op for Include if
 * an identical pattern is already there. Like addHostToScope(), never
 * touches Exclude.
 */
export function addPatternToScope(scopeConfig, pattern) {
  const base = scopeConfig || DEFAULT_SCOPE;
  const include = base.include ? [...base.include] : [];
  const exists = include.some((p) => p.trim().toLowerCase() === pattern.toLowerCase());
  return {
    enabled: true,
    include: exists ? include : [...include, pattern],
    exclude: base.exclude ? [...base.exclude] : [],
  };
}

/**
 * Would `cookie` (a chrome.cookies.Cookie: {domain, path, hostOnly, secure})
 * be sent to some in-scope URL? Host-only cookies go to exactly one host, so
 * that host must be in Scope (Exclude and path patterns applied). A domain
 * cookie (".example.com") goes to the domain and every subdomain, so it
 * counts when any Include pattern's host overlaps it — the same domain, a
 * host under it (Scope "app.example.com" still receives ".example.com"
 * cookies), or a wildcard above it. Ignores the "Scope enabled" switch: this
 * answers "is it relevant to my target", for filtering the Cookies view.
 */
export function cookieMatchesScope(cookie, scopeConfig) {
  const include = (scopeConfig?.include || []).filter((p) => (p || "").trim());
  if (include.length === 0 || !cookie?.domain) return false;
  const domain = cookie.domain.toLowerCase().replace(/^\./, "");
  const scheme = cookie.secure ? "https" : "http";
  if (cookie.hostOnly || !cookie.domain.startsWith(".")) {
    return isInScope(`${scheme}://${domain}${cookie.path || "/"}`, { ...scopeConfig, enabled: true });
  }
  return include.some((pattern) => {
    const host = parseScopePattern(pattern).host;
    const base = host.startsWith("*.") ? host.slice(2) : host;
    if (base.includes("*")) return hostMatchesPattern(domain, host); // mid-pattern wildcard: best effort
    return base === domain || base.endsWith(`.${domain}`) || (host.startsWith("*.") && domain.endsWith(`.${base}`));
  });
}
