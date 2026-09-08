# ZProxy — Chrome MV3 Capability Matrix

This document is the required Phase 1 deliverable: a factual accounting of what a
Manifest V3 Chrome extension can and cannot do with respect to HTTP interception,
produced **before** any interception code was written. Every row below reflects the
actual behavior of the Chrome extension platform as of Chrome 124+, not aspiration.

## The one fact that shapes everything else

A Chrome extension never sees raw TCP/TLS traffic. It never terminates HTTPS and
never performs a certificate-level MITM. Every API discussed below (`webRequest`,
`declarativeNetRequest`, `chrome.debugger`/CDP) operates **inside the browser
process, after TLS has already been decrypted by Chrome's network stack**, and
exposes/edits traffic at the HTTP semantic layer (method, URL, headers, body),
not at the byte/socket layer.

This means ZProxy can legitimately show and edit "what your browser is about to
send/received", which is what testers actually use Burp/ZAP for day-to-day — but
ZProxy is **not** and cannot become a transparent network proxy, and it cannot
intercept traffic from other applications, only from Chrome tabs it has
permission for.

## Capability matrix

| # | Feature | Chrome API | Possible in MV3? | Notes / Implementation |
|---|---|---|---|---|
| 1 | Observe requests (method, URL, headers, timing, type) | `chrome.webRequest` (non-blocking) | ✅ Yes, but only for hosts with a granted host permission | Cheap, no debugger banner. `chrome.webRequest` fires only for hosts the extension currently has host permission for — true for blocking *and* non-blocking listeners alike — so History still needs the same optional `<all_urls>` permission as Intercept/Repeater/Cookies granted at least once before it observes anything. `onBeforeRequest`, `onSendHeaders`, `onHeadersReceived`, `onCompleted`, `onErrorOccurred`. |
| 2 | Read outgoing request body | `chrome.webRequest` (`requestBody` on `onBeforeRequest`) | ✅ Yes, with caveats | Raw bytes/form fields available for most bodies. Multipart file parts are exposed as opaque byte blobs (filenames/boundaries readable, but Chrome does not fully decode multipart for the extension). |
| 3 | Modify request headers (add/remove/replace) | `declarativeNetRequest` (dynamic session rules) | ✅ Yes | Declarative, no debugger banner, applies even when the panel is closed. This is what powers static Match & Replace and the header table. |
| 4 | Modify request URL / redirect / block | `declarativeNetRequest` | ✅ Yes | `redirect`, `block` actions. Used for scope-based blocking and URL match/replace. |
| 5 | Modify **response** headers | `declarativeNetRequest` (`modifyHeaders` on response) | ✅ Yes | Same rule action supports `responseHeaders`. Static only — cannot be conditioned on response body content. |
| 6 | **Pause** a request before it is sent (true intercept-and-hold) | `chrome.debugger` + CDP `Fetch.enable` (request stage) | ✅ Yes, with strong caveats | `webRequest` blocking (`extraHeaders`/blocking callbacks) is **removed for standard extensions in MV3** (Chrome only honors it for force-installed enterprise policy extensions). CDP `Fetch` domain is the only path left for a real pause. Requires `chrome.debugger` permission, shows Chrome's persistent "ZProxy is debugging this browser" infobar, and is scoped per-tab. See "Debugger caveats" below. |
| 7 | Modify request body while paused | CDP `Fetch.continueRequest` (`postData`) | ✅ Yes | Only available while a debugger session + `Fetch` domain is active for that tab. |
| 8 | **Pause** a response before it reaches the page | CDP `Fetch.enable` (response stage) | ✅ Yes, with same debugger caveats as #6 | `Fetch.enable`'s `patterns` list controls which stage(s) pause at all — the Settings/Intercept-view "Intercept: requests/responses/both" control (`settings.interceptStage`, `buildFetchPatterns()` in `src/background/interception.js`) simply omits a stage's pattern entirely when the user doesn't want it paused, applied live to already-attached tabs via `refreshFetchPatternsForAttachedTabs()`. The same function also filters by `Fetch.RequestPattern.resourceType` so Settings' "skip intercepting these resource types" (CSS/images/fonts/media/scripts) works the same way: an excluded type gets no pattern at all, so it's never paused — not paused-then-auto-forwarded. Since `Fetch.enable`'s patterns are an allow-list, excluding even one type means enumerating every other type explicitly rather than a single catch-all `"*"` pattern — and that "every other type" list is deliberately **not** the full `Network.ResourceType` enum from the protocol docs. Confirmed at runtime (`{"code":-32602,"message":"Unknown resource type in fetch filter: 'TextTrack'"}`) and against Chromium's own implementation (`content/browser/devtools/protocol/fetch_handler.cc`, `AddInterceptedResourceType()`): `Fetch.enable` only recognizes 12 strings (`Document`, `Stylesheet`, `Image`, `Media`, `Font`, `Script`, `XHR`, `Fetch`, `EventSource`, `CSPViolationReport`, `Ping`, `Other`) — `TextTrack`, `Preflight`, `WebSocket`, `Manifest`, `SignedExchange`, and `FedCM` are valid `Network.ResourceType` values used elsewhere in CDP but are rejected outright here. (`WebSocket` traffic was never routed through `Fetch.requestPaused` anyway — see row 14/15 above.) |
| 9 | Read response body | CDP `Fetch.getResponseBody` / `Network.getResponseBody` | ✅ Yes, debugger only | **Not possible via `webRequest` at all** — Chrome never exposes response bytes through that API. This is the single biggest reason `chrome.debugger` is required for true response inspection/editing. This has a knock-on effect for History's "edited" before/after comparison (`entry.editDiff`, `src/background/edited-tracker.js`): History's own `request`/`response` fields (sourced from `webRequest`) can never be used as "what was actually sent" — they never carry a response body at all (this row), and `onBeforeRequest` never reflects a `Fetch`-level URL/method override either (row 6's note). So the comparison view stores its own explicit `{ original, edited }` snapshots captured directly from the interceptor at edit time, rather than trusting the entry's own fields for the "edited" side. |
| 10 | Modify response body / status / headers before delivery | CDP `Fetch.fulfillRequest` | ✅ Yes, debugger only | This is real response rewriting, not a simulation — the bytes ZProxy supplies are what the renderer receives. |
| 11 | Cookie inspection & editing (`document.cookie`-level, `HttpOnly`, `Secure`, `SameSite`, per-domain) | `chrome.cookies` | ✅ Yes | Full CRUD, independent of interception mode. |
| 12 | `Cookie` request header inspection | `chrome.webRequest` header list | ✅ Yes | Read-only view alongside the cookie store view. |
| 13 | `Set-Cookie` response header inspection | `chrome.webRequest` (`onHeadersReceived`, `extraHeaders`) | ✅ Yes | Chrome exposes raw `Set-Cookie` lines here even though it hides them from `fetch()`/page JS. |
| 14 | WebSocket frame observation | CDP `Network.webSocketFrameSent` / `webSocketFrameReceived` (debugger) | ✅ Yes, observation only | |
| 15 | WebSocket frame **modification** | — | ❌ No | Chrome/CDP has no `fulfill`-style hook for WebSocket frames; by the time the event fires the frame has already been delivered. Documented limitation — see below. |
| 16 | True HTTPS MITM (byte-level, cert swap, non-Chrome-traffic) | — | ❌ No, not for a browser extension | Would require a local TLS-terminating proxy + a trusted root CA installed on the OS. Out of scope for the MV3 extension; see `docs/NATIVE_PROXY.md` for how a future companion process could add this. |
| 17 | Intercepting traffic from other browser profiles, other browsers, or non-browser processes | — | ❌ No | Extensions are sandboxed to the installing browser/profile. |
| 18 | Running with all-scripts-blocked so captured HTML can never execute in the UI | Extension page CSP + never using `innerHTML`/`eval` on captured data | ✅ Yes | Enforced throughout the UI layer — see `docs/SECURITY.md`. |

## Debugger caveats (`chrome.debugger`) — read before enabling Intercept

Enabling **Intercept** mode attaches the Chrome DevTools Protocol to the current
tab. This is the only way to get a real pause-and-edit workflow and real response
bodies, but it comes with real, user-visible costs that ZProxy must never hide:

- **Permission**: requires the `debugger` permission, declared up front in
  `manifest.json` and reviewable by the user/Web Store.
- **Visible warning**: Chrome shows a persistent yellow infobar
  ("ZProxy started debugging this browser") on every tab being debugged. This
  cannot be suppressed or hidden — it is a deliberate Chrome anti-abuse measure.
  ZProxy's UI surfaces the same state so the two never disagree.
- **One debugger client per tab**: if DevTools is already open on the target tab,
  `chrome.debugger.attach` fails. ZProxy detects this and reports it rather than
  silently doing nothing.
- **Only ordinary web pages are debuggable**: `chrome.debugger.attach` refuses
  `chrome://` pages, the Chrome Web Store, and any `chrome-extension://` page —
  including, confirmed at runtime, one belonging to a *different* extension
  (`"Cannot access a chrome-extension:// URL of different extension"`). If the
  active tab is showing something other than an `http(s)://` page when
  Intercept is clicked, ZProxy checks for this up front (`isDebuggableUrl()`
  in `src/ui/sidepanel/app.js` and `src/ui/popup/popup.js`) and asks the user
  to switch tabs first, rather than surfacing that raw Chrome error after an
  unnecessary permission prompt.
- **Per-tab scope, not global**: attaching to tab A does not intercept tab B.
  Combined with Scope rules, this keeps ZProxy from accidentally intercepting
  every open tab.
- **Performance**: pausing `Fetch` events blocks that request until ZProxy
  responds (forward/drop/edit) — a forgotten paused request hangs the page's
  network activity for that resource indefinitely. ZProxy shows a visible
  pending-request list so this is never silent. There is a
  `autoForwardTimeoutMs` setting displayed in Settings, but — honestly — it is
  not yet wired to anything; nothing currently reads it or auto-forwards a
  stale paused item. Until that's built, the practical mitigation is
  `detachTab()` (`src/background/interception.js`) resolving every still-
  pending item, unmodified, before it actually detaches the debugger —
  turning Intercept off is what guarantees nothing is left hanging, not a
  timeout.
- **Security surface**: the `debugger` permission is powerful (it's the same API
  DevTools itself uses). ZProxy uses it strictly for `Fetch`/`Network` domains it
  needs and detaches immediately when Intercept is turned off.

Because of this, ZProxy treats interception as an **explicit, opt-in, per-tab,
scope-gated action** — never something that happens silently in the background.
Passive history capture (`webRequest`) needs none of this and is always cheap.

## What this means for the MVP architecture

| Capability tier | API used | Debugger required? | Always available? |
|---|---|---|---|
| Traffic history (metadata + request bodies) | `webRequest` | No | Once `<all_urls>` host permission has been granted (any of Scope/Intercept/Repeater/Cookies triggers the same prompt) and a tab is in Scope |
| Header/URL match & replace, static header edits | `declarativeNetRequest` | No | Yes |
| Cookie inspector/editor | `chrome.cookies` | No | Yes |
| Request/response **pause, edit, forward/drop** | `chrome.debugger` + CDP `Fetch` | **Yes** | Only while Intercept is explicitly enabled for the tab |
| Response body view/edit | `chrome.debugger` + CDP `Fetch`/`Network` | **Yes** | Only while Intercept (or the lighter "Capture bodies" debugger mode) is on |
| Body-content match & replace | `chrome.debugger` + CDP `Fetch` | **Yes** | Only applies while Intercept is on, since body rewriting has no non-debugger path |
| WebSocket frame log | `chrome.debugger` + CDP `Network` | **Yes** | Observation only, never modification |
| Repeater (resend a captured/edited request) | `fetch()` from an extension page with host permission | No | Yes |

This tiering is reflected directly in the code layout: `src/interception/` holds
the debugger-dependent modules, `src/background/traffic-manager.js` and the DNR
rule managers hold the always-available modules, and the UI clearly labels which
mode (`Passive`, `Capture Bodies`, `Intercept`) is active per tab so a tester is
never confused about which guarantees currently apply.

### Repeater's honest limitation

Repeater (`src/ui/sidepanel/views/repeater.js`) sends the edited request for real
via `fetch()` from the side panel page. With the optional `<all_urls>` host
permission granted, extension-page `fetch()` is exempt from CORS (a documented
Chrome extension capability), so cross-origin responses come back fully
readable. What it **cannot** do — because the restriction is enforced by the
Fetch spec itself, not by CORS or by Chrome extensions specifically — is let a
script set `Host`, `Origin`, `Cookie`, `Content-Length`, and a handful of other
"forbidden request headers" to an arbitrary value. Repeater drops these before
sending and warns in the UI rather than silently pretending the edit took
effect.
