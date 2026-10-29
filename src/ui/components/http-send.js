// Shared by Repeater, Intruder, and Access Control: all send a request "for
// real" via fetch() from this extension page. With the <all_urls> optional
// host permission granted, extension-page fetches are exempt from CORS (a
// documented Chrome extension capability) so cross-origin responses come
// back readable — but the Fetch spec still forbids scripts from setting a
// handful of headers (Host, Origin, Cookie, Content-Length, ...) on any
// request, extension or not. See docs/CAPABILITIES.md.
//
// Three of those — Cookie, Origin, Referer — are exactly what CSRF, CORS,
// and session/authorization testing need to control, so they're applied
// another way: a short-lived declarativeNetRequest SESSION rule, installed
// just before the fetch and removed right after, that sets them on this one
// request. The rule is pinned to the exact URL and method, and to requests
// with no tab (tabIds: [TAB_ID_NONE]) — i.e. this extension's own fetches,
// never the tester's browsing. The remaining forbidden headers describe
// connection framing (Host, Content-Length, Connection, ...) and are still
// dropped. UNVERIFIED in a live browser at the time of writing: Chrome's DNR
// docs don't say outright whether rules apply to an extension's own
// requests — see the README's manual checklist (test-lab /api/echo-headers).
export const FORBIDDEN_REQUEST_HEADERS = new Set([
  "host",
  "origin",
  "cookie",
  "cookie2",
  "date",
  "dnt",
  "connection",
  "content-length",
  "expect",
  "keep-alive",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "via",
  "referer",
]);

/** Forbidden headers that are still sent with the edited value, via a DNR session rule (see above). */
export const DNR_OVERRIDABLE_HEADERS = new Set(["cookie", "origin", "referer"]);

const RULE_ID_BASE = 900_000;
let nextRuleOffset = 0;
const DNR_METHODS = new Set(["connect", "delete", "get", "head", "options", "patch", "post", "put"]);
const TAB_ID_NONE = -1; // chrome.tabs.TAB_ID_NONE

function hasDnr() {
  return typeof chrome !== "undefined" && !!chrome.declarativeNetRequest?.updateSessionRules;
}

/** The {name, value} headers in `headers` that need a DNR override (last one wins per name). */
export function headerOverrides(headers) {
  const byName = new Map();
  for (const h of headers || []) {
    const lower = h.name.toLowerCase();
    if (DNR_OVERRIDABLE_HEADERS.has(lower)) byName.set(lower, { name: lower, value: h.value });
  }
  return [...byName.values()];
}

/**
 * Pure — the DNR session rule applying `overrides` to `request`. An empty
 * value REMOVES the header (an empty "Cookie:" line means "send no
 * cookies", e.g. to test as an unauthenticated user). Whenever Cookie is
 * overridden, the response's Set-Cookie is stripped too: otherwise replaying
 * as another user could log the tester's own browser in as that user (the
 * fetch shares the browser's cookie jar).
 */
export function buildOverrideRule(id, request, overrides) {
  const url = new URL(request.url);
  url.hash = "";
  const method = request.method.toLowerCase();
  const href = url.href;
  // urlFilter treats * ^ | as syntax; a URL containing them gets an escaped regex instead.
  const urlCondition = /[*^|]/.test(href) ? { regexFilter: `^${href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$` } : { urlFilter: `|${href}|` };
  const action = {
    type: "modifyHeaders",
    requestHeaders: overrides.map((o) => (o.value === "" ? { header: o.name, operation: "remove" } : { header: o.name, operation: "set", value: o.value })),
  };
  if (overrides.some((o) => o.name === "cookie")) action.responseHeaders = [{ header: "set-cookie", operation: "remove" }];
  return {
    id,
    priority: 1_000_000, // above any static Match & Replace rule touching the same header
    condition: {
      ...urlCondition,
      requestMethods: [DNR_METHODS.has(method) ? method : "other"],
      tabIds: [TAB_ID_NONE],
      resourceTypes: ["xmlhttprequest"],
    },
    action,
  };
}

// Two in-flight overrides for the same method+URL would have identical
// conditions with different values, and DNR would apply only one of them to
// both requests — so overridden sends to the same target are serialized.
const targetLocks = new Map(); // "METHOD url" -> Promise

async function withTargetLock(key, fn) {
  const previous = targetLocks.get(key) || Promise.resolve();
  let release;
  const current = new Promise((resolve) => (release = resolve));
  const chained = previous.then(() => current);
  targetLocks.set(key, chained);
  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (targetLocks.get(key) === chained) targetLocks.delete(key);
  }
}

async function withOverrideRule(rule, fn) {
  await chrome.declarativeNetRequest.updateSessionRules({ addRules: [rule] });
  try {
    return await fn();
  } finally {
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [rule.id] }).catch(() => {});
  }
}

function allocateRuleId() {
  const id = RULE_ID_BASE + nextRuleOffset;
  nextRuleOffset = (nextRuleOffset + 1) % 50_000;
  return id;
}

async function rawSend(request, signal, overrides) {
  const startedAt = Date.now();
  try {
    const headers = new Headers();
    for (const h of request.headers) {
      if (FORBIDDEN_REQUEST_HEADERS.has(h.name.toLowerCase())) continue;
      try {
        headers.append(h.name, h.value);
      } catch {
        /* invalid header name/value — skip rather than fail the whole send */
      }
    }
    const hasBody = !["GET", "HEAD"].includes(request.method.toUpperCase()) && request.body;
    const res = await fetch(request.url, {
      method: request.method,
      headers,
      body: hasBody ? request.body : undefined,
      credentials: "include",
      signal,
    });
    const body = await res.text();
    return {
      ok: true,
      response: {
        statusCode: res.status,
        statusText: res.statusText,
        headers: [...res.headers.entries()].map(([name, value]) => ({ name, value })),
        body,
        durationMs: Date.now() - startedAt,
        // fetch() follows redirects transparently; this is the only trace of it.
        redirected: res.redirected,
        finalUrl: res.url,
      },
      overriddenHeaders: overrides.map((o) => o.name),
    };
  } catch (err) {
    if (err?.name === "TimeoutError") return { ok: false, timedOut: true, error: `Timed out after ${Date.now() - startedAt}ms with no response` };
    if (err?.name === "AbortError") return { ok: false, aborted: true, error: "Aborted" };
    return { ok: false, error: `Request failed: ${err.message} (network error, blocked by CORS/CSP, or an invalid URL)` };
  }
}

/** The caller's abort signal, combined with a timeout when `timeoutMs` > 0 (aborts with a TimeoutError). */
function withTimeout(signal, timeoutMs) {
  if (!(timeoutMs > 0)) return signal;
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

function overrideSetupError(err) {
  return { ok: false, error: `Could not apply the Cookie/Origin/Referer override: ${err.message}` };
}

/**
 * Sends `request` ({method, url, headers, body}) via fetch() and returns
 * either {ok: true, response: {statusCode, statusText, headers, body, durationMs, redirected, finalUrl}, overriddenHeaders}
 * or {ok: false, error} — never throws, so callers (esp. a loop sending many
 * requests in a row) don't need their own try/catch around every call.
 * `timeoutMs` (optional) gives up on a request that hasn't answered in time.
 */
export async function sendRequest(request, { signal: callerSignal, timeoutMs } = {}) {
  const signal = withTimeout(callerSignal, timeoutMs);
  const overrides = headerOverrides(request.headers);
  if (overrides.length === 0 || !hasDnr()) return rawSend(request, signal, []);
  let rule;
  try {
    rule = buildOverrideRule(allocateRuleId(), request, overrides);
  } catch {
    return rawSend(request, signal, []); // unparseable URL — fetch() reports it properly
  }
  return withTargetLock(`${request.method} ${request.url}`, () =>
    withOverrideRule(rule, () => rawSend(request, signal, overrides)).catch(overrideSetupError)
  );
}

/**
 * Sends every request at once (Repeater's "send group" race-condition
 * test). When every request targets the same method+URL with the same
 * Cookie/Origin/Referer values — the normal case, N copies of one request —
 * a single shared override rule covers them all so they still go out
 * concurrently. Mixed overrides for one target can't share a rule, so those
 * fall back to sendRequest()'s per-target serialization.
 */
export async function sendRequestGroup(requests, { signal: callerSignal, timeoutMs } = {}) {
  const signal = withTimeout(callerSignal, timeoutMs);
  const overrideSets = requests.map((r) => headerOverrides(r.headers));
  const needsOverride = overrideSets.some((o) => o.length > 0);
  const signature = (r, o) => `${r.method} ${r.url} ${JSON.stringify(o)}`;
  const shareable = needsOverride && hasDnr() && requests.every((r, i) => signature(r, overrideSets[i]) === signature(requests[0], overrideSets[0]));
  if (!shareable) return Promise.all(requests.map((r) => sendRequest(r, { signal })));
  let rule;
  try {
    rule = buildOverrideRule(allocateRuleId(), requests[0], overrideSets[0]);
  } catch {
    return Promise.all(requests.map((r) => rawSend(r, signal, [])));
  }
  return withTargetLock(`${requests[0].method} ${requests[0].url}`, () =>
    withOverrideRule(rule, () => Promise.all(requests.map((r) => rawSend(r, signal, overrideSets[0])))).catch((err) =>
      requests.map(() => overrideSetupError(err))
    )
  );
}
