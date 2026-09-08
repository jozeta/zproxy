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

export function isInScope(url, scopeConfig) {
  if (!scopeConfig || !scopeConfig.enabled) return false;
  let host;
  try {
    // .hostname (not .host) — .host includes a non-default port
    // ("localhost:8787"), which would never match a plain "localhost"
    // pattern and silently fail every request on any target that isn't
    // running on the default port for its scheme (extremely common for
    // local dev servers, including examples/test-lab).
    host = new URL(url).hostname;
  } catch {
    return false;
  }
  const excluded = (scopeConfig.exclude || []).some((p) => hostMatchesPattern(host, p));
  if (excluded) return false;

  const include = scopeConfig.include || [];
  if (include.length === 0) return false;
  return include.some((p) => hostMatchesPattern(host, p));
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
  const alreadyCovered = include.some((p) => hostMatchesPattern(host, p));
  return {
    enabled: true,
    include: alreadyCovered ? include : [...include, host],
    exclude: base.exclude ? [...base.exclude] : [],
  };
}
