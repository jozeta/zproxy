# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ZProxy is a browser-native Chrome (Manifest V3) extension for inspecting and intercepting your
own browser's HTTP traffic: a Burp/ZAP-style workflow (Intercept, History, Repeater, Intruder,
Decoder, Comparer, Findings, Match & Replace, Cookies, Scope) with no companion app, CA
certificate or backend. Plain ES modules, no build step. Version in `manifest.json` and
`CHANGELOG.md`. For authorized testing only (`docs/THREAT_MODEL.md`).

## Commands

```sh
npm test                          # node --test tests/ (Node 18+, no npm install needed)
npm ci && npm run lint            # ESLint (dev-only dependency), incl. the unsafe-DOM rule
node examples/test-lab/server.js  # tiny local practice target
```

Run the extension: `chrome://extensions` → Developer mode → **Load unpacked** → repo root, then open
the side panel. After edits, reload the extension. Unit tests cover only the pure, browser-free
modules: anything touching `chrome.*` must be checked with the README's manual verification
checklist.

## Architecture (see docs/ARCHITECTURE.md, docs/CAPABILITIES.md)

- `src/background/`: service worker: passive `webRequest` capture, DNR rule sync
  (`dnr-rules.js`), debugger lifecycle (`interception.js`), `scope.js`, permissions, traffic
  manager, body/edited trackers, findings monitor.
- `src/interception/`: CDP `Fetch`-stage request/response/WebSocket handling, Match & Replace
  engine and presets, conditional "pause only when" rules.
- **Pure modules (unit-tested):** `src/authz/`, `src/intruder/`, `src/parsers/`,
  `src/utils/` (bytes, redact, sanitize, hash, shortcuts).
- `src/storage/`: `chrome.storage` wrappers (settings, rules/scope, intercept rules, history ring
  buffer).
- `src/ui/`: `components/` (RPC client, inspector, exporter, sender), `sidepanel/views/` (one per
  tool), `popup/`.

Interception needs `chrome.debugger` (CDP `Fetch`): MV3 has no blocking `webRequest`. Chrome's
"is debugging this browser" infobar is expected and cannot be hidden.

## Rules (tests and docs enforce these)

- **No mock functionality:** every feature uses a real Chrome API, or the docs say plainly that
  it doesn't and why. Keep `docs/CAPABILITIES.md` honest.
- **Scope fails closed:** an empty or disabled scope captures nothing, never everything.
- **Never execute captured content in the UI:** render with `textContent` / DOM nodes or a
  `sandbox=""` iframe. No `innerHTML`, `eval` or `document.write` (`tests/security.*.test.js`
  scan the source).
- History defaults to `chrome.storage.session` (memory-only) because traffic holds tokens and
  cookies; redact secrets in logs (`src/utils/redact.js`).
- No telemetry and no requests the user didn't initiate. `<all_urls>` is requested
  just-in-time, never assumed. Justify any new permission in the README permissions table.
- Put new logic in a pure module with a `node:test` test where possible.

## App standards

This repo follows the app standards in `~/Desktop/code/tools/standards/STANDARDS.md` (rule IDs,
severities; decisions and waivers in `.claude-standards`). `claude-check --repo .` checks it.
