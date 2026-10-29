# Changelog

ZProxy follows [semantic versioning](https://semver.org/). The version
lives in `manifest.json` — Settings and the side panel header read it from
there at runtime. `package.json`, the README's version line, and the newest
entry below must match it; `tests/version.test.js` fails if they drift, so
a release bumps all four together.

## 0.4.0 — 2026-10-30

### Added
- **Findings, much broader** — researched against OWASP ZAP's passive scan
  rules, Burp's passive issue types and BApp Store extensions, the OWASP
  Secure Headers project, Retire.js, and Gitleaks:
  - **Vulnerable JavaScript libraries** (jQuery, jQuery UI, AngularJS,
    Bootstrap, Lodash, Underscore, Moment, Handlebars, DOMPurify, Vue, React,
    axios, CKEditor, TinyMCE and more), detected from license banners and
    CDN URLs and matched against Retire.js version ranges with CVEs.
  - **Detailed error messages**: Werkzeug/Django/Laravel/Symfony/Rails debug
    pages, ASP.NET yellow screens, Xdebug, SQL/NoSQL/LDAP/template-engine/XML
    errors, stack traces for Java, .NET, Python, PHP, Node, Ruby, Go and Perl,
    default Tomcat/JBoss/Spring error pages, and full path disclosure.
  - **Information leakage**: phpinfo(), server-status, Spring Actuator,
    exposed .git and .env, backup and log files, GraphQL introspection, API
    specs, internal IPs and hostnames, server banners in error pages, ~40
    disclosure headers (OWASP list), X-Powered-By, generator meta tags,
    framework session cookie names, emails, card numbers (Luhn-checked),
    password hashes, serialized Java/PHP objects.
  - **Cookies**: parent-domain scoping, broken __Host-/__Secure- prefixes,
    invalid SameSite, duplicate cookies, passwords and readable role data in
    cookies, session cookies without __Host-.
  - **Headers**: legacy X-XSS-Protection, deprecated headers (HPKP,
    Expect-CT, Feature-Policy), invalid X-Frame-Options/nosniff, missing
    Permissions-Policy and COOP, HSTS without includeSubDomains, CSP hosts
    with known bypasses, missing object-src/base-uri, debug/profiler headers,
    source maps, shared-cache hits on authenticated responses, logout without
    Clear-Site-Data, HTTP auth challenges over HTTP, TRACE and WebDAV methods.
  - **Pages and scripts**: POST forms without CSRF tokens, password forms
    over HTTP, third-party scripts without SRI, known-compromised script
    domains (polyfill.io), DOM-XSS source/sink pairs, postMessage listeners
    without origin checks, rel=opener, unencrypted JSF ViewState,
    cryptominers, endpoints referenced in JavaScript, reflected parameters,
    and parameter names worth testing (Hunt-style).
  - **Tokens and secrets**: JWTs without expiry, with sensitive claims, or
    with remote key headers; secrets in Referer and session IDs in URL paths;
    16 more secret formats (GitLab, OpenAI, Anthropic, Slack and Discord
    webhooks, Azure, DigitalOcean, Shopify, Vault, …).
- **Findings always active while a Scope is defined**: a live count on the
  Findings nav item and on ZProxy's toolbar icon (high + medium), and
  Findings can't be hidden from the navigation.
- **Response bodies without Intercept**: while a Scope is defined, the
  debugger attaches in observe-only mode to in-scope tabs (Settings →
  "Capture response bodies without Intercept"; Chrome shows its debugging
  banner while active).
- **Findings severity chips are independent toggles.**
- **Intruder**: ten more payload types — Custom iterator, Regex generator,
  Encoding variants, Illegal Unicode, Character frobber, Bit flipper, ECB
  block shuffler, IP ranges, Random strings, UUIDs.
- **Scope → Add current site**: adds the active tab's domain with all
  subdomains (country domains like .co.uk handled).
- **Cookies → In scope** filter.

### Changed
- Defining a Scope for the first time un-hides the Scope view.

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
