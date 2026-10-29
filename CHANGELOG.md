# Changelog

ZProxy follows [semantic versioning](https://semver.org/). The version
lives in `manifest.json` — Settings and the side panel header read it from
there at runtime. `package.json`, the README's version line, and the newest
entry below must match it; `tests/version.test.js` fails if they drift, so
a release bumps all four together.

## 0.3.0 — 2026-10-29

### Added
- Settings → **Hide from navigation**: choose which of Findings, WebSockets,
  Access Control, Cookies, Decoder, Comparer, Match/Replace, and Scope
  appear in the side navigation. Hidden views still open when another view
  sends you there, and stay listed while open.
- The Scope badge in the header now opens the Scope view.

### Changed
- WebSockets, Access Control, Decoder, Comparer, Match/Replace, and Scope
  are hidden from the navigation by default. An install that changed any
  setting earlier keeps its saved list until Settings → Reset settings to
  defaults.
- The README has new screenshots of the Nordic interface.

### Fixed
- The method and URL fields in History, Intercept, and Repeater now use the
  theme's input styling (they had no `type` attribute, so the Nordic
  input styles never matched them).

## 0.2.0 — 2026-10-29

### Added
- **Nordic interface**: Polar Night (dark) and Snow Storm (light) themes plus
  "Match system", a custom icon set, an icon navigation rail that expands
  with the panel width, and micro-animations that respect reduced-motion.
- **Resizable panes** in Intercept, Repeater, and Findings — drag the
  handle or use the arrow keys; the size is remembered.
- **Findings**: 25+ new passive checks (weak CSP, short HSTS, reflected or
  `null` CORS origins, cacheable authenticated responses, JSON served as
  HTML, long-lived session cookies, secrets in URLs, credentials over HTTP,
  `alg: none` JWTs, SQL errors and stack traces, directory listings,
  internal IPs, mixed content, insecure form actions, open-redirect
  candidates), severity counts and stripes, and a Markdown report export.
- **Repeater**: rename and duplicate tabs, Pretty/Raw/Headers/Preview
  response views, find-in-response with highlighting, per-tab timeout,
  redirect notice, copy as cURL, import from cURL, tabs kept until the
  browser closes, per-tab send history, response diff, parallel send group.
- **Intruder**: seven new payload types (built-in fuzz lists, dates, case
  modification, character substitution, username generator, character
  blocks, null payloads), eleven new processing rules (find & replace, skip
  if matches, full/double URL-encoding, HTML, Base64url, hex, Unicode
  escape, reverse, trim, MD5), concurrency, retries, stop on first
  Grep-Match hit, and CSV export with formula-injection protection.
- **Decoder**: Base64url, URL (all characters), Unicode escape, binary,
  char codes, ROT13, and Gzip/deflate modes; Smart decode for layered
  encodings; Undo and Copy; an Inspect panel (JWT contents, Unix
  timestamps, length); MD5, CRC-32, and HMAC-SHA-256 hashes.
- **Match & Replace**: ten presets, a live rule tester with regex error
  reporting, duplicate, reorder, enable/disable all, and filtering.
- **Access Control** view (Autorize-style authorization testing),
  **WebSockets** view, response bodies in History while Intercept is
  attached, Cookie/Origin/Referer editing in Repeater, path/scheme/port
  Scope patterns, and Settings → Reset settings to defaults.

### Changed
- Intercept defaults to pausing requests only, and skips CSS, images,
  fonts, media, and scripts.

### Fixed
- Static Match & Replace rules now apply only to in-scope hosts (they
  previously applied to every site the browser visited).
- Turning off "Persist history to disk" now removes the on-disk copy.
- Editing a large or binary response no longer truncates or corrupts it;
  Forward keeps content-rule changes; several History capture races.

## 0.1.0

- Initial release: History, Intercept, Repeater, Intruder, Decoder,
  Comparer, Findings, Match & Replace, Cookies, Scope, Settings.
