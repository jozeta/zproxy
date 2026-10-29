# ZProxy Security Model

## Design principles

1. **Local-only.** ZProxy has no backend, no analytics SDK, no remote config, no
   telemetry. Every network request the extension itself makes is either (a)
   a request the user explicitly directed through Repeater/Intercept, or (b)
   nothing else. There is no third network path. `manifest.json` declares no
   `content_security_policy` `connect-src` allowance beyond `'self'`, so the
   extension pages themselves cannot be coerced into phoning home.
2. **Minimum permissions.** See the table in `README.md` — every permission maps
   to one feature. `<all_urls>` is requested as an **optional permission** at
   first-use, not baked into install. `debugger` is the one exception: Chrome
   refuses to let it be declared optional at all ("Permission 'debugger'
   cannot be listed as optional"), so it's a required install-time
   permission. It is used only for tabs explicitly attached via Intercept,
   or — while a Scope is defined and "Capture response bodies without
   Intercept" is on — in observe-only mode (Network domain only, never
   Fetch, so nothing is paused or modified) on tabs showing in-scope pages.
   Chrome's debugging banner is shown in both cases, and dismissing it
   stops observation of that tab until it closes.
3. **Captured content is untrusted input, always.** A response body captured
   from a target application may contain attacker-controlled or malicious
   HTML/JS (that's often the point of testing it). ZProxy's own UI must never
   execute it.

## Preview isolation — how captured HTML/JS/CSS is shown without executing it

Every view that displays a request or response body (History detail, Intercept
panel, Repeater response, Match & Replace preview) uses **one** rendering path,
implemented once in `src/utils/sanitize.js`. `tests/security.render.test.js`
unit-tests the pure-string `escapeHtml` half of this against the spec's named
XSS payloads; the iframe-sandboxing half is a DOM/browser behavior that this
Node-only test harness can't exercise directly (no jsdom — the project takes
no dependencies), so it's covered instead by the static source scan in
`tests/security.no-eval.test.js` and should be spot-checked manually in Chrome
before release (see README "Manual verification checklist").

- Bodies are always placed into the DOM via `textContent` / a `<textarea>`
  value, never `innerHTML`, `insertAdjacentHTML`, `document.write`, or template
  literals interpolated into markup.
- Syntax highlighting (`src/ui/components/code-view.js`) is a pure tokenizer
  that returns `{text, className}` spans and builds DOM nodes with
  `createElement`/`textContent` — it never re-parses the string as HTML.
- The optional "Rendered preview" tab for HTML responses (useful for eyeballing
  a modified page before forwarding it) loads the body into a **sandboxed
  iframe** (`<iframe sandbox="allow-same-origin-DISABLED" srcdoc="...">` — note
  `allow-scripts` and `allow-same-origin` are both **omitted**, so scripts in
  the preview cannot execute and the frame cannot reach extension APIs or
  cookies). This is opt-in per-response and clearly labeled
  "Preview only — scripts disabled".
- The extension's own pages set a strict CSP in `manifest.json`
  (`script-src 'self'; object-src 'self'`), so even a bug that accidentally
  injected a `<script>` tag into extension HTML would not execute inline or
  remote script.
- No `eval`, `new Function`, or remote script loading anywhere in the codebase
  (verified by `tests/security.no-eval.test.js`, which greps the shipped
  source for these patterns as a regression guard).

## Sensitive data handling

- **History storage defaults to `chrome.storage.session`**, which Chrome keeps
  in memory only and clears on browser restart — captured `Authorization`
  headers, session cookies, and tokens are not written to disk by default.
  A Settings toggle lets an advanced user opt into `chrome.storage.local`
  persistence for a single investigation session, with a visible warning.
- **History has a hard size cap** (`settings.maxHistoryEntries`, default 1000).
  Oldest entries are evicted first (ring buffer), bounding both memory and the
  amount of sensitive data retained.
- **"Clear History" / "Clear Cookies" / "Clear Temporary Data"** are one click
  in Settings and in the History toolbar, and also run automatically when the
  extension is disabled or uninstalled (`chrome.storage` is cleared by Chrome
  on uninstall).
- **Console logging is minimal by construction, not by a runtime filter.**
  The original two `console.error` lines in `src/background/service-worker.js`
  (a declarativeNetRequest sync failure, `err.message` only) are joined, as
  of this writing, by temporary diagnostic `console.log` calls in
  `src/background/edited-tracker.js`, `src/interception/request-interceptor.js`,
  and `src/background/traffic-manager.js` added to debug the History "edited"
  indicator correlation logic. Those log **method + URL only** — never
  headers, cookies, or body content — but a URL's query string can still
  carry sensitive values, so they should be removed (or gated behind an
  explicit debug setting) once that feature is verified working, not left in
  permanently. `src/utils/redact.js` (`redactHeadersForLog`/
  `redactEntryForLog`) remains the required helper for any logging that
  *does* touch a full request/response object — stripping
  `Authorization`/`Cookie`/`Set-Cookie`/`Proxy-Authorization`/`X-Api-Key` —
  and is a hard requirement in code review for such a call.
- **No third-party destinations.** Export (HAR/JSON/cURL/raw) writes a local
  file via the browser's download flow; it does not upload anywhere.

## Threat model summary (full detail in `docs/THREAT_MODEL.md`)

| Actor | Can they... | Mitigation |
|---|---|---|
| The website being tested | Serve malicious HTML/JS hoping it executes inside ZProxy's UI | Preview isolation above — captured content never executes in the extension context |
| The website being tested | Exfiltrate ZProxy's captured data | ZProxy makes no requests except ones the user initiates; no ambient network path from page → extension data |
| A malicious/compromised extension update | Add telemetry silently | Extension is intentionally dependency-free and reviewable; no build step obscures behavior |
| A user on a shared machine | Read another user's leftover captured tokens | Session-only storage by default + explicit Clear actions |
| ZProxy itself, misused | Used to attack a site the tester is not authorized to test | Out of scope for software controls — this is a policy/authorization matter; see README "Authorized use only" |
