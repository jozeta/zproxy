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
