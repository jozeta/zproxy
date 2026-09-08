# ZProxy Architecture

See `docs/CAPABILITIES.md` first — it explains *why* the system is split the way
it is. This document describes *how* the pieces fit together.

## High-level component diagram

```
                     ┌────────────────────────────────────────────┐
                     │              Service Worker                │
                     │           src/background/*.js               │
                     │                                              │
  chrome.webRequest ─┼─▶ traffic-manager.js ──▶ storage/history.js  │
  (always-on,        │        │                                    │
   per-tab scope)    │        │ emits events over runtime port      │
                     │        ▼                                    │
                     │   scope.js  (Scope.isInScope(url))          │
                     │        ▲                                    │
                     │        │                                    │
  declarativeNetRequest ◀─────┼── match-replace.js (static rules)   │
  (dynamic rules)     │        │        + storage/rules.js          │
                     │        │                                    │
  chrome.debugger  ──┼─▶ interception.js ──▶ request-interceptor.js │
  (opt-in per tab)   │        │              response-interceptor.js│
                     │        │              websocket-interceptor.js│
                     │        ▼                                    │
                     │   pending-queue (in-memory, per tab)         │
                     └───────────────┬──────────────────────────────┘
                                      │ chrome.runtime messaging
                                      ▼
                     ┌────────────────────────────────────────────┐
                     │         Side Panel UI (the "app")           │
                     │        src/ui/sidepanel/*                   │
                     │  Dashboard / History / Intercept / Repeater │
                     │  Cookies / Match-Replace / Scope / Settings │
                     └────────────────────────────────────────────┘
                                      │
                     ┌────────────────────────────────────────────┐
                     │              Popup (quick toggle)           │
                     │           src/ui/popup/*                    │
                     └────────────────────────────────────────────┘
```

## Why a service worker + side panel, not devtools panel or content scripts

- **Service worker** (`src/background/service-worker.js`) is the only place that
  can hold `chrome.debugger` sessions, `webRequest` listeners, and DNR rule state.
  It is the single source of truth. It is ephemeral (MV3 can kill it), so all
  state that must survive a restart lives in `chrome.storage` (settings, rules,
  scope) or `chrome.storage.session` (history — see `docs/SECURITY.md` for why
  history defaults to session-only, non-disk storage).
- **Side panel** (`chrome.sidePanel`) rather than a DevTools panel: DevTools
  panels only exist while DevTools is open on a page, and a DevTools panel
  cannot itself hold a `chrome.debugger` session (only one client may attach).
  A side panel is a normal extension page, persists across tab switches, and
  functions like a lightweight "app" docked next to the browser — matching the
  "browser-native" MVP requirement without a devtools dependency.
- **No content scripts are used for interception.** Content scripts run inside
  the page's origin and are the wrong trust boundary for a security tool —
  ZProxy never injects code into the page being tested. The only exception is
  the intentionally sandboxed rendering of captured HTML for preview (see
  `docs/SECURITY.md`, "Preview isolation").

## Module map

```
zproxy/
├── manifest.json
├── src/
│   ├── background/
│   │   ├── service-worker.js     entry point; wires everything below
│   │   ├── traffic-manager.js    webRequest listeners -> history entries
│   │   ├── interception.js       chrome.debugger lifecycle per tab
│   │   └── permissions.js        optional-permission requests (debugger, <all_urls>)
│   ├── interception/
│   │   ├── request-interceptor.js   CDP Fetch request-stage pause/edit/forward/drop
│   │   ├── response-interceptor.js  CDP Fetch response-stage pause/edit/forward/drop
│   │   ├── websocket-interceptor.js CDP Network websocket frame observation
│   │   └── match-replace.js         applies body-level rules during a debugger pause
│   ├── intruder/
│   │   ├── positions.js  §payload§ marker finding/substitution + auto-mark heuristics
│   │   ├── payloads.js   payload generators: simple list, numbers, brute forcer
│   │   └── combine.js    Sniper/Battering ram/Pitchfork/Cluster bomb combination logic
│   ├── storage/
│   │   ├── history.js    ring-buffer history store (chrome.storage.session)
│   │   ├── settings.js   user settings (chrome.storage.local)
│   │   └── rules.js      match/replace + scope rule persistence (chrome.storage.local)
│   ├── parsers/
│   │   ├── http.js       request/response <-> raw HTTP text, curl, HAR
│   │   ├── json.js       safe parse/pretty-print/validate
│   │   ├── jwt.js        base64url decode (no verification, ever)
│   │   ├── cookies.js    Cookie / Set-Cookie header parsing
│   │   └── headers.js    header list <-> map helpers, dedupe/case-insensitive ops
│   ├── ui/
│   │   ├── sidepanel/    the main app (dashboard, history, repeater, intercept, ...)
│   │   ├── popup/        quick intercept toggle + scope indicator
│   │   └── components/   shared, framework-free UI widgets (table, tabs, editor)
│   └── utils/
│       ├── sanitize.js   escaping/sandboxing helpers, used by every view that
│       │                 renders captured data (see docs/SECURITY.md)
│       └── bytes.js      size formatting, truncation for large bodies
├── tests/                node --test unit tests for parsers/match-replace/security
├── examples/
│   ├── match-replace-rules/   importable example rule sets
│   └── test-lab/              a tiny local HTTP app for practicing the workflow
└── docs/
```

## Data flow: the five workflows

**1. Passive history (always on, in Scope)**
`webRequest.onBeforeRequest/onSendHeaders/onHeadersReceived/onCompleted` →
`traffic-manager.js` builds one `HistoryEntry` per request id → `storage/history.js`
appends to the ring buffer → side panel's History view re-renders via a
`chrome.runtime` push message (`history:new-entry`).

**2. Header/URL match & replace (always on, in Scope, no debugger)**
Rules in `storage/rules.js` are compiled into `declarativeNetRequest` dynamic
rules by `match-replace.js`'s DNR half whenever rules change. Chrome applies
them natively; ZProxy never sees the traffic for this path, which is exactly
why it's fast and always-on.

**3. Intercept (opt-in per tab)**
User clicks "Intercept" for a tab → `interception.js` calls
`chrome.debugger.attach` → enables CDP `Fetch` for both request and response
stages, filtered by Scope → each paused event becomes a `PendingItem` pushed to
the side panel's Intercept view → user chooses Forward / Drop / Edit & Forward /
Forward & Don't Intercept Again / Send to Repeater → `request-interceptor.js` or
`response-interceptor.js` calls the matching CDP `Fetch.continueRequest` /
`Fetch.fulfillRequest` / `Fetch.failRequest`.

**4. Repeater**
User sends a `HistoryEntry` (or a `PendingItem`) to Repeater → the side panel
holds an editable copy → "Send" performs a `fetch()` from the side panel's
extension-page context (which has host permissions, so it isn't blocked by the
target's CORS policy the way page JS would be) → response is displayed in the
same panel, independent of history/interception.

**5. Intruder**
User marks `§payload§` positions in a base request (typed fresh, or sent over
from History/Intercept/Repeater) → configures an attack type and one or more
payload sets (`src/intruder/payloads.js`) → `src/intruder/combine.js` yields
one payload tuple per attack request according to the chosen attack type →
`src/intruder/positions.js` substitutes each tuple into the base request →
the side panel sends every generated request sequentially via the same
`fetch()`-from-extension-page mechanism Repeater uses (`components/http-send.js`)
and renders a live results table (status/length/time/grep-match), independent
of history/interception. No debugger involved — same reach and limits as
Repeater.

## Future native-proxy hook (not built in the MVP)

`src/background/permissions.js` and `interception.js` are written against a
small internal interface (`InterceptionBackend`) with one implementation today
(`ChromeDebuggerBackend`). `docs/NATIVE_PROXY.md` specifies a second
implementation (`NativeMessagingBackend`) that would talk to a local companion
process over `chrome.runtime.connectNative` for true TCP/TLS MITM. No code for
that backend exists yet — this is a documented seam, not a stub pretending to
work.
