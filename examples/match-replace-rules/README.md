# Example Match & Replace rule sets

Import these from **Match & Replace → Import** in the ZProxy side panel. Each file is a JSON array of rule objects in the shape `src/interception/match-replace.js` and `src/background/dnr-rules.js` expect.

Two engines, two different guarantees — see `docs/CAPABILITIES.md` for the full explanation:

- **`static`** (declarativeNetRequest-backed): runs even with Intercept detached, but can only unconditionally **set/remove** a header or **redirect** a URL. It cannot see or condition on the current header/body content.
- **`content`** (debugger-backed): does real substring/regex find-and-replace against the actual header/body bytes, but only while Intercept is attached to the tab.

## Files

- **`mark-lab-traffic.static.json`** — `static` engine. Adds an `X-ZProxy-Lab: 1` request header to everything in scope, so you can grep it out of server access logs. Works with no debugger attached — good first rule to try.
- **`toggle-feature-flag.content.json`** — `content` engine. Flips `"featureXEnabled":false` to `"featureXEnabled":true` in response bodies — the classic "unlock a client-gated feature" exercise against `examples/test-lab`'s `/api/flags` endpoint. Requires Intercept attached (and Pause can be off — this rule runs on every paused response either way).
- **`downgrade-referrer.content.json`** — `content` engine. Rewrites `Referer: https://...` to `http://...` on requests, to see how a target reacts to a weaker referrer without hand-editing every request.

## A note on the `static` redirect action

`static` + `location: "url"` maps to a DNR `redirect` action, which replaces the whole URL — it can't rewrite just the host and keep the original path/query (DNR redirects aren't "find and replace" on the URL string). That's a real API limitation, not an oversight, which is why no redirect example is included here — a `content` rule on `location: "url"` (see `toggle-feature-flag.content.json` for the pattern) is the honest way to do partial URL rewrites, and only while Intercept is attached.
