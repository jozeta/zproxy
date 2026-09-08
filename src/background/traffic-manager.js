// Always-on, cheap traffic capture via chrome.webRequest (observation only —
// no blocking callbacks, since MV3 no longer allows those for normal
// extensions; see docs/CAPABILITIES.md row 6). This is the source of the
// History feed and works whether or not Intercept/debugger mode is active.
import { addHistoryEntry } from "../storage/history.js";
import { isInScope } from "./scope.js";
import { getScope } from "../storage/rules.js";
import { toHeaderList, getHeaderValue } from "../parsers/headers.js";
import { consumeEdited } from "./edited-tracker.js";

const pending = new Map(); // requestId -> in-progress HistoryEntry

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
    async (details) => {
      if (details.tabId < 0) return;
      const scope = await getScope();
      if (!isInScope(details.url, scope)) return;
      pending.set(details.requestId, {
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
          body: bodyFromRequestBody(details.requestBody),
        },
        response: null,
      });
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

  chrome.webRequest.onCompleted.addListener(async (details) => {
    const item = pending.get(details.requestId);
    if (!item) return;
    pending.delete(details.requestId);
    item.status = "completed";
    item.durationMs = Date.now() - item.startedAt;
    item.responseSize = details.responseSize ?? null;
    if (item.response) item.response.statusCode = details.statusCode;
    // Correlates with an Intercept edit for this same method+URL, if any —
    // see edited-tracker.js for why this can't use a shared request ID.
    // completedAt = startedAt + durationMs, matching how edited-tracker.js
    // anchors matches against the pause moment rather than "now".
    const editDiff = consumeEdited(item.request.method, item.request.url, item.startedAt + item.durationMs);
    if (editDiff) {
      item.edited = true;
      item.editDiff = editDiff;
    }
    await addHistoryEntry(item);
    onEntryCallback?.(item);
  }, filter);

  chrome.webRequest.onErrorOccurred.addListener(async (details) => {
    const item = pending.get(details.requestId);
    if (!item) return;
    pending.delete(details.requestId);
    item.status = "error";
    item.error = details.error;
    item.durationMs = Date.now() - item.startedAt;
    const editDiff = consumeEdited(item.request.method, item.request.url, item.startedAt + item.durationMs);
    if (editDiff) {
      item.edited = true;
      item.editDiff = editDiff;
    }
    await addHistoryEntry(item);
    onEntryCallback?.(item);
  }, filter);
}
