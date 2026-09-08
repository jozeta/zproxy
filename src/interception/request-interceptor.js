// Request-stage handling for CDP Fetch.requestPaused (chrome.debugger backend).
// See docs/CAPABILITIES.md rows 6/7 — this is the only way to get a real
// pause-and-edit-before-send workflow in an MV3 extension.
import { textToBase64 } from "../utils/bytes.js";
import { withCorrectedFramingHeaders, headersEqual } from "../parsers/headers.js";
import { markEdited } from "../background/edited-tracker.js";
import { shouldPauseForRules } from "./intercept-rules.js";

const pendingByTab = new Map(); // tabId -> Map(fetchRequestId -> PendingItem)
const dontInterceptAgain = new Set(); // "METHOD url" keys, cleared on service worker restart by design

function getPending(tabId) {
  if (!pendingByTab.has(tabId)) pendingByTab.set(tabId, new Map());
  return pendingByTab.get(tabId);
}

function matchKey(method, url) {
  return `${method} ${url}`;
}

export function requestActuallyChanged(original, edited) {
  if (!edited) return false;
  return (
    original.method !== edited.method ||
    original.url !== edited.url ||
    (original.body ?? "") !== (edited.body ?? "") ||
    !headersEqual(original.headers, edited.headers)
  );
}

function buildPendingItem(tabId, params) {
  const headers = Object.entries(params.request.headers || {}).map(([name, value]) => ({ name, value }));
  return {
    kind: "request",
    fetchRequestId: params.requestId,
    tabId,
    networkRequestId: params.networkId,
    resourceType: params.resourceType,
    pausedAt: Date.now(),
    request: {
      method: params.request.method,
      url: params.request.url,
      httpVersion: "HTTP/1.1",
      headers,
      body: params.request.postData ?? null,
    },
  };
}

/**
 * Called by background/interception.js for every request-stage pause.
 * `applyRules` is a (item) => item transform (content-engine match/replace).
 * Returns the (possibly rule-modified) item, and queues it for the UI unless
 * the URL is on the "don't intercept again" list, manual pause is disabled,
 * or `interceptRules` (see intercept-rules.js) says this particular request
 * doesn't need a human look.
 */
export async function handlePaused(tabId, params, { applyRules, manualPauseEnabled, interceptRules, emit }) {
  const original = buildPendingItem(tabId, params);
  let item = applyRules ? applyRules(original) : original;

  const key = matchKey(item.request.method, item.request.url);
  const shouldPause = manualPauseEnabled && !dontInterceptAgain.has(key) && shouldPauseForRules(item.request, interceptRules);

  if (!shouldPause) {
    // A content-engine rule silently rewrote this request — flag it in
    // History the same way a manual edit is (see response-interceptor.js
    // for the identical response-side case). Keyed by the ORIGINAL
    // method/URL — see the note on forwardEdited() below for why.
    if (requestActuallyChanged(original.request, item.request)) {
      // Best-effort — never let a History-bookkeeping failure block the
      // actual forward.
      await markEdited(original.request.method, original.request.url, original.pausedAt, {
        kind: "request",
        original: original.request,
        edited: item.request,
      }).catch(() => {});
    }
    await continueWithItem(tabId, params.requestId, item);
    return;
  }

  getPending(tabId).set(params.requestId, item);
  emit({ type: "request-paused", tabId, item });
}

async function continueWithItem(tabId, fetchRequestId, item) {
  // Same fix as the response side (response-interceptor.js): Content-Length
  // and friends describe wire framing, not content, and CDP rejects
  // Content-Length outright if set explicitly — always strip these rather
  // than trying to forward whatever the original request had.
  const headers = withCorrectedFramingHeaders(item.request.headers.map((h) => ({ name: h.name, value: h.value })));
  const cdpParams = { requestId: fetchRequestId, url: item.request.url, method: item.request.method, headers };
  if (typeof item.request.body === "string") cdpParams.postData = textToBase64(item.request.body);
  await chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", cdpParams);
}

export async function forward(tabId, fetchRequestId) {
  const item = getPending(tabId).get(fetchRequestId);
  getPending(tabId).delete(fetchRequestId);
  if (item) return continueWithItem(tabId, fetchRequestId, item);
  await chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: fetchRequestId });
}

export async function forwardEdited(tabId, fetchRequestId, editedRequest) {
  const original = getPending(tabId).get(fetchRequestId);
  getPending(tabId).delete(fetchRequestId);
  // Marks the eventual History entry as "edited" — see edited-tracker.js.
  // Keyed by the ORIGINAL method/URL, NOT the edited one — confirmed
  // empirically (a live console trace showed onCompleted reporting the
  // pre-edit URL, never the edited one, for the same transaction) and
  // consistent with Chromium's architecture: chrome.webRequest's
  // onBeforeRequest captures the URL/method before CDP's Fetch domain ever
  // gets a chance to intercept it, and nothing later in that request's
  // webRequest lifecycle (onSendHeaders, onCompleted, ...) updates it —
  // a Fetch.continueRequest URL/method override isn't a real HTTP redirect
  // (which DOES get a fresh onBeforeRequest-equivalent via onBeforeRedirect),
  // it's an in-flight substitution invisible to webRequest's bookkeeping.
  // So History's row for this transaction will always show the original
  // request's method/URL, however the actual bytes were edited — meaning
  // that's also the only key that can ever correlate with it.
  if (original && requestActuallyChanged(original.request, editedRequest)) {
    await markEdited(original.request.method, original.request.url, original.pausedAt, {
      kind: "request",
      original: original.request,
      edited: editedRequest,
    }).catch(() => {});
  }
  await continueWithItem(tabId, fetchRequestId, { request: editedRequest });
}

export async function drop(tabId, fetchRequestId, reason = "BlockedByClient") {
  getPending(tabId).delete(fetchRequestId);
  await chrome.debugger.sendCommand({ tabId }, "Fetch.failRequest", { requestId: fetchRequestId, errorReason: reason });
}

export async function forwardAndDontInterceptAgain(tabId, fetchRequestId, editedRequest) {
  // Bug this replaces: this used to call forward(tabId, fetchRequestId),
  // which re-fetches the ORIGINAL captured item from the pending map and
  // sends that — completely ignoring whatever the caller had just edited in
  // the inspector. The skip-rule key still needs the ORIGINAL method/URL
  // (that's what future real requests from the page will actually look
  // like — editing the URL here only affects this one forwarded instance),
  // so it's read from the pending map before deleting it, while what's
  // actually sent comes from `editedRequest`.
  const original = getPending(tabId).get(fetchRequestId);
  if (original) {
    dontInterceptAgain.add(matchKey(original.request.method, original.request.url));
    if (requestActuallyChanged(original.request, editedRequest)) {
      // Keyed by the ORIGINAL method/URL — see forwardEdited() above for why.
      await markEdited(original.request.method, original.request.url, original.pausedAt, {
        kind: "request",
        original: original.request,
        edited: editedRequest,
      }).catch(() => {});
    }
  }
  getPending(tabId).delete(fetchRequestId);
  return continueWithItem(tabId, fetchRequestId, { request: editedRequest });
}

export function clearDontInterceptAgain() {
  dontInterceptAgain.clear();
}

export function getPendingItems(tabId) {
  return [...getPending(tabId).values()];
}

export function clearTab(tabId) {
  pendingByTab.delete(tabId);
}
