// Always-on, cheap traffic capture via chrome.webRequest (observation only —
// no blocking callbacks, since MV3 no longer allows those for normal
// extensions; see docs/CAPABILITIES.md row 6). This is the source of the
// History feed and works whether or not Intercept/debugger mode is active.
import { addHistoryEntry } from "../storage/history.js";
import { isInScope } from "./scope.js";
import { getScope } from "../storage/rules.js";
import { toHeaderList, getHeaderValue } from "../parsers/headers.js";
import { consumeEdited } from "./edited-tracker.js";
import { consumeResponseBody } from "./body-tracker.js";

const pending = new Map(); // requestId -> in-progress HistoryEntry
// requestId -> Promise<boolean>. The scope check is async (getScope() reads
// chrome.storage when its cache is cold — e.g. right after the service
// worker wakes for the very request being captured), so the entry is
// registered synchronously and the check is awaited only when finalizing.
// Awaiting it up front instead let onSendHeaders arrive before the entry
// existed, silently dropping that request's headers.
const scopeChecks = new Map();

function bodyFromRequestBody(requestBody) {
  if (!requestBody || requestBody.error) return null;
  if (requestBody.formData) {
    const params = new URLSearchParams();
    for (const [key, values] of Object.entries(requestBody.formData)) {
      for (const v of values) params.append(key, v);
    }
    return params.toString();
  }
  if (requestBody.raw) {
    try {
      const decoder = new TextDecoder("utf-8", { fatal: false });
      return requestBody.raw.map((part) => (part.bytes ? decoder.decode(part.bytes) : "")).join("");
    } catch {
      return null;
    }
  }
  return null;
}

let onEntryCallback = null;
export function onTrafficEntry(cb) {
  onEntryCallback = cb;
}

// chrome.webRequest only ever fires for hosts the extension currently has
// host permission for — regardless of blocking vs. non-blocking — and
// <all_urls> is an OPTIONAL host permission here (see manifest.json),
// ungranted at fresh install. Registering the listeners before any host
// permission is granted is harmless but logs Chrome's own
// "You need to request host permissions..." notice and, more importantly,
// won't actually observe anything until a permission exists. So this waits
// for at least one host permission (granted via Scope, Intercept, Cookies,
// or Repeater — they all request the same <all_urls> permission) before
// attaching, and retries on chrome.permissions.onAdded.
let trafficListenersAttached = false;

export function registerTrafficListeners() {
  chrome.permissions.contains({ origins: ["<all_urls>"] }).then((has) => {
    if (has) attachTrafficListeners();
  });
  chrome.permissions.onAdded.addListener((added) => {
    if (added.origins && added.origins.length > 0) attachTrafficListeners();
  });
}

function attachTrafficListeners() {
  if (trafficListenersAttached) return;
  trafficListenersAttached = true;
  const filter = { urls: ["<all_urls>"] };

  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (details.tabId < 0) return;
      const entry = {
        id: details.requestId,
        tabId: details.tabId,
        type: details.type,
        startedAt: Date.now(),
        status: "pending",
        request: {
          method: details.method,
          url: details.url,
          httpVersion: "HTTP/1.1",
          headers: [],
          body: null,
        },
        response: null,
      };
      pending.set(details.requestId, entry);
      const check = getScope()
        .then((scope) => {
          if (!isInScope(details.url, scope)) return false;
          // Decoded only once known in scope — this listener sees every request in the browser.
          entry.request.body = bodyFromRequestBody(details.requestBody);
          return true;
        })
        .catch(() => false)
        .then((inScope) => {
          // A redirect re-fires onBeforeRequest with the same requestId; only
          // drop the entry if it's still the one this check was for.
          if (!inScope && pending.get(details.requestId) === entry) pending.delete(details.requestId);
          return inScope;
        });
      scopeChecks.set(details.requestId, check);
    },
    filter,
    ["requestBody"]
  );

  chrome.webRequest.onSendHeaders.addListener(
    (details) => {
      const item = pending.get(details.requestId);
      if (!item) return;
      item.request.headers = toHeaderList(details.requestHeaders || []);
    },
    filter,
    ["requestHeaders", "extraHeaders"]
  );

  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      const item = pending.get(details.requestId);
      if (!item) return;
      const headers = toHeaderList(details.responseHeaders || []);
      item.response = {
        statusCode: details.statusCode,
        statusText: (details.statusLine || "").split(" ").slice(2).join(" "),
        headers,
        body: null, // webRequest never exposes response bytes — see docs/CAPABILITIES.md row 9
        mimeType: (getHeaderValue(headers, "content-type") || "").split(";")[0],
      };
    },
    filter,
    ["responseHeaders", "extraHeaders"]
  );

  chrome.webRequest.onCompleted.addListener(
    (details) =>
      finalize(details, (item) => {
        item.status = "completed";
        item.responseSize = details.responseSize ?? null;
        if (item.response) item.response.statusCode = details.statusCode;
      }),
    filter
  );

  chrome.webRequest.onErrorOccurred.addListener(
    (details) =>
      finalize(details, (item) => {
        item.status = "error";
        item.error = details.error;
      }),
    filter
  );
}

async function finalize(details, applyOutcome) {
  // Removed before the !item return: an out-of-scope request's entry is
  // already gone by now, but its check must not linger in the map.
  const check = scopeChecks.get(details.requestId);
  scopeChecks.delete(details.requestId);
  const item = pending.get(details.requestId);
  if (!item) return;
  // Captured before awaiting: duration is when the request finished, not when the scope check resolved.
  const durationMs = Date.now() - item.startedAt;
  pending.delete(details.requestId);
  if (!(await check)) return;
  applyOutcome(item);
  item.durationMs = durationMs;
  // Correlates with an Intercept edit for this same method+URL, if any —
  // see edited-tracker.js for why this can't use a shared request ID.
  // completedAt = startedAt + durationMs, matching how edited-tracker.js
  // anchors matches against the pause moment rather than "now".
  const editDiff = consumeEdited(item.request.method, item.request.url, item.startedAt + item.durationMs);
  if (editDiff) {
    item.edited = true;
    item.editDiff = editDiff;
  }
  // A body CDP already read for this request (Intercept attached) — see
  // body-tracker.js. If it arrives after this point instead, it patches
  // the saved entry directly.
  if (item.response) {
    const body = consumeResponseBody(item.request.method, item.request.url, item.startedAt + item.durationMs);
    if (body != null) item.response.body = body;
  }
  await addHistoryEntry(item);
  onEntryCallback?.(item);
}
