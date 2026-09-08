// <all_urls> is an optional host permission (see manifest.json) — requested
// explicitly at first use (Intercept/Repeater/Cookies), never granted
// silently at install. `debugger` is NOT optional here: Chrome refuses to
// let a handful of high-risk permissions (debugger among them) be declared
// as `optional_permissions` at all ("Permission 'debugger' cannot be listed
// as optional. This permission will be omitted.") — so it's a required
// permission, granted like `storage`/`cookies`/etc. at install time. See
// docs/CAPABILITIES.md "Debugger caveats" and docs/SECURITY.md #2.

export async function hasHostAccess() {
  return chrome.permissions.contains({ origins: ["<all_urls>"] });
}

export async function requestHostAccess() {
  return chrome.permissions.request({ origins: ["<all_urls>"] });
}

/** Always true post-install — kept so callers don't need a special case. */
export async function hasDebuggerPermission() {
  return chrome.permissions.contains({ permissions: ["debugger"] });
}
