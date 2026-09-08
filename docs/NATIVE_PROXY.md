# Optional Future Native Proxy Component (not implemented in the MVP)

`docs/CAPABILITIES.md` identifies two things a browser extension structurally
cannot do: true TLS MITM at the byte level, and traffic from non-Chrome
processes. Both require code running outside the browser sandbox. This
document specifies the seam for that, so adding it later doesn't require
rearchitecting ZProxy — **no native code ships today.**

## Where the seam would live

**Honest current state:** `src/background/interception.js` calls
`chrome.debugger.attach`/`sendCommand` directly today — there is no
`InterceptionBackend` abstraction in the code yet. Introducing one wasn't
justified for an MVP with exactly one backend (see the project's own
"don't design for hypothetical future requirements" rule); this section
specifies what that seam would look like *if and when* a second backend
(the `NativeMessagingBackend` below) is actually being built, so that future
work has a target shape instead of starting from nothing:

```js
// InterceptionBackend (proposed interface, not yet extracted from
// src/background/interception.js)
attach(tabId)                        -> Promise<void>
detach(tabId)                        -> Promise<void>
onRequestPaused(tabId, handler)      -> void
onResponsePaused(tabId, handler)     -> void
continueRequest(tabId, id, patch)    -> Promise<void>
fulfillResponse(tabId, id, patch)    -> Promise<void>
failRequest(tabId, id, reason)       -> Promise<void>
```

The eventual `ChromeDebuggerBackend` would be today's
`src/background/interception.js` + `src/interception/request-interceptor.js`
+ `response-interceptor.js`, refactored behind that interface at the point a
second implementation actually exists to justify it.

## The future `NativeMessagingBackend`

A local companion process (e.g. a small Rust/Go binary using
`mitmproxy`-style techniques, installed and trusted by the user outside the
extension) would:

1. Register as a Chrome Native Messaging host
   (`chrome.runtime.connectNative`), with the extension ID allow-listed in its
   host manifest — this is the standard, Chrome-blessed way for an extension
   to talk to a local trusted process without arbitrary sockets/CORS issues.
2. Optionally configure the OS/browser proxy settings
   (`chrome.proxy` API, needs the `proxy` permission) to route traffic through
   itself for true request/response byte-level control, including a locally
   generated MITM CA the user explicitly installs and trusts (mirroring how
   Burp/mitmproxy/Charles work today — this is unavoidable and must remain an
   explicit, documented, user-driven installation step, never silent).
3. Stream intercepted events back over the native messaging port in the same
   pending-item shape (`{kind, fetchRequestId, tabId, request, response?}`)
   the UI already consumes via `intercept:pending`/`intercept:event`, so
   `src/ui/sidepanel/views/intercept.js` would need zero changes.

## Why this is not built now

- It requires code outside the reviewable, sandboxed extension boundary —
  a materially different trust and install story than "load one extension."
- It requires the user to install and trust a local root CA, a significant
  security-relevant step that must not be bundled into an MVP casually.
- The MV3 capability set (Section: Capability matrix) already covers the
  stated MVP feature list without it. Building it prematurely would violate
  the project's own "prioritize working, technically correct functionality
  over feature count" rule.

If/when this is built, it should ship as a clearly separate, optional
download, with its own threat model addendum covering the installed root CA.
