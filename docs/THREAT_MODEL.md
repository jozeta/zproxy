# ZProxy Threat Model

Scope: the ZProxy Chrome extension itself. Not in scope: the security posture
of applications the tester points ZProxy at (that's the tester's job, using
ZProxy as a tool).

## Assets

1. Captured HTTP traffic (may contain credentials, session tokens, PII).
2. Match/replace rules and scope configuration (reveal what a tester is testing).
3. The extension's own execution context (has `cookies`, `debugger`, and host
   permissions — a powerful capability if hijacked).

## Actors & abuse cases

### A. The web application under test (untrusted, adversarial by design)

- **A1 — Stored XSS via captured content.** A response body containing
  `<script>` or `<img onerror=...>` is captured and later displayed in
  ZProxy's UI. *Mitigation:* preview isolation (`docs/SECURITY.md`); verified
  by `tests/security.render.test.js` using exactly these payloads.
- **A2 — JWT/crypto trust confusion.** A forged JWT with `alg: none` or a
  mismatched signature is decoded and a user assumes decoding implies
  validity. *Mitigation:* the JWT inspector decodes only, never claims
  validity, and displays a persistent "signature not verified" notice.
- **A3 — Data exfiltration via a proxied response.** A malicious page tries to
  use `fetch`/`XHR` to reach ZProxy's storage or messaging surface.
  *Mitigation:* `chrome.storage` and `chrome.runtime` messaging are not
  reachable from page JS at all (there's no `externally_connectable` entry in
  `manifest.json`), so no page script can talk to the extension.

### B. A malicious or compromised local process

- **B1 — Another extension inspects ZProxy's data.** *Mitigation:* ZProxy
  stores data in its own isolated `chrome.storage` partition; no
  `externally_connectable`; no shared globals.
- **B2 — Native messaging host abuse.** Not applicable in the MVP — no native
  component ships (see `docs/NATIVE_PROXY.md`); if implemented later, the
  native host must authenticate the calling extension ID and vice versa.

### C. Misuse by the tester (policy, not software, boundary)

- **C1 — Using ZProxy against a target without authorization.** Software
  controls cannot fully prevent this; ZProxy mitigates by being explicit and
  effortful to enable broad interception (Scope defaults to "nothing in
  scope", `<all_urls>` is an optional host permission granted per use —
  `debugger` is a required install-time permission, since Chrome does not
  allow it to be optional, but it grants no capability on its own until a
  tab is explicitly attached — and the intercept banner from Chrome itself
  is always visible) rather than quietly intercepting everything by default.
- **C2 — Accidental interception of unrelated browsing** (e.g. the tester's
  banking session) while Intercept is left on. *Mitigation:* Scope UI is
  designed so "everything" is never the silent default (see `README.md`'s
  core workflow and `src/background/scope.js`'s fail-closed `isInScope`);
  the popup always shows current Intercept state and scope count; a single
  click disables Intercept. Clicking Intercept on a tab does auto-add
  *that tab's exact host* to Scope's Include list (`addHostToScope` in
  `src/background/scope.js`) — a deliberate convenience so attaching to a
  tab doesn't silently pause nothing until Scope is separately configured —
  but it never adds a wildcard, never touches other hosts, and never
  overrides an existing Exclude entry for that host.

## Non-goals

- Defeating the target application's authentication/authorization —
  ZProxy is a traffic tool, not an exploit framework.
- Detecting or evading endpoint security/AV/EDR on the tester's machine.
- Protecting the tester from a malicious *extension marketplace* listing
  claiming to be ZProxy — mitigated at the distribution layer (sideload from
  source / verified listing), not in this codebase.
