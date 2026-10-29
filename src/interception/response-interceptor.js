// Response-stage handling for CDP Fetch.requestPaused (chrome.debugger backend).
// This is the only way an MV3 extension can read or rewrite a response body
// before it reaches the page — see docs/CAPABILITIES.md rows 9/10.
//
// Two copies of every body exist: the FULL body (kept here, in the service
// worker, and the only thing ever sent back to the page) and a display copy
// capped at MAX_INSPECT_BODY_BYTES (what the UI gets, so a huge response
// can't freeze it). Forwarding must never send the display copy — that would
// silently cut the response off at the cap. Likewise the body is decoded to
// text for display/rules, which is lossy for binary content (images, fonts,
// wasm), so an unchanged body is always forwarded from its original base64
// bytes, never re-encoded from the decoded text.
import { textToBase64, base64ToText } from "../utils/bytes.js";
import { withCorrectedFramingHeaders, headersEqual } from "../parsers/headers.js";
import { markEdited } from "../background/edited-tracker.js";
import { shouldPauseForRules } from "./intercept-rules.js";

const pendingByTab = new Map(); // tabId -> Map(fetchRequestId -> { item, original, rawBase64, display })
const MAX_INSPECT_BODY_BYTES = 500_000; // avoid freezing the UI on huge responses (perf requirement)

function getPending(tabId) {
  if (!pendingByTab.has(tabId)) pendingByTab.set(tabId, new Map());
  return pendingByTab.get(tabId);
}

async function fetchBody(tabId, fetchRequestId) {
  try {
    const result = await chrome.debugger.sendCommand({ tabId }, "Fetch.getResponseBody", { requestId: fetchRequestId });
    if (result.base64Encoded) return { text: base64ToText(result.body), rawBase64: result.body, available: true };
    return { text: result.body, rawBase64: null, available: true };
  } catch {
    // Not every paused response has a readable body (e.g. redirects, HEAD,
    // 304s, opaque cross-origin). This is expected, not an error state.
    return { text: null, rawBase64: null, available: false };
  }
}

function buildPendingItem(tabId, params, body) {
  const responseHeaders = (params.responseHeaders || []).map((h) => ({ name: h.name, value: h.value }));
  const contentType = (responseHeaders.find((h) => h.name.toLowerCase() === "content-type")?.value || "").split(";")[0];
  return {
    kind: "response",
    fetchRequestId: params.requestId,
    tabId,
    networkRequestId: params.networkId,
    pausedAt: Date.now(),
    request: {
      method: params.request.method,
      url: params.request.url,
      headers: Object.entries(params.request.headers || {}).map(([name, value]) => ({ name, value })),
      body: params.request.postData ?? null,
    },
    response: {
      statusCode: params.responseStatusCode,
      statusText: params.responseStatusText || "",
      headers: responseHeaders,
      body: body.text,
      bodyTruncated: false,
      bodyAvailable: body.available,
      mimeType: contentType,
    },
  };
}

/** The UI-bound copy of `item`, with the body capped at MAX_INSPECT_BODY_BYTES. */
function toDisplayItem(item) {
  const body = item.response.body;
  if (typeof body !== "string" || body.length <= MAX_INSPECT_BODY_BYTES) return item;
  return { ...item, response: { ...item.response, body: body.slice(0, MAX_INSPECT_BODY_BYTES), bodyTruncated: true } };
}

export function responseActuallyChanged(original, edited) {
  if (!edited) return false;
  return (
    String(original.statusCode) !== String(edited.statusCode) ||
    (original.statusText || "") !== (edited.statusText || "") ||
    (original.body ?? "") !== (edited.body ?? "") ||
    !headersEqual(original.headers, edited.headers)
  );
}

export async function handlePaused(tabId, params, { applyRules, manualPauseEnabled, interceptRules, emit }) {
  const body = await fetchBody(tabId, params.requestId);
  const original = buildPendingItem(tabId, params, body);
  const item = applyRules ? applyRules(original) : original;
  const record = { item, original, rawBase64: body.rawBase64 };

  const shouldPause = manualPauseEnabled && shouldPauseForRules(item.request, interceptRules);
  if (!shouldPause) {
    // Avoid a needless full fulfillRequest round-trip (re-encoding a
    // potentially large body) when the content-engine rules made no change.
    const unmodified = !responseActuallyChanged(original.response, item.response);
    if (unmodified) {
      await forwardUnmodified(tabId, params.requestId);
    } else {
      // A content-engine rule silently rewrote this response — that's an
      // edit just as much as a manual one, and arguably more important to
      // flag in History since it's otherwise completely invisible.
      await markEdited(original.request.method, original.request.url, original.pausedAt, {
        kind: "response",
        original: original.response,
        edited: item.response,
      }).catch(() => {});
      await fulfill(tabId, params.requestId, item.response, record);
    }
    return;
  }

  record.display = toDisplayItem(item);
  getPending(tabId).set(params.requestId, record);
  emit({ type: "response-paused", tabId, item: record.display });
}

function bodyAsBase64(response, record) {
  if (typeof response.body !== "string") return undefined;
  if (record?.rawBase64 && response.body === record.original.response.body) return record.rawBase64;
  return textToBase64(response.body);
}

async function fulfill(tabId, fetchRequestId, response, record) {
  const headers = withCorrectedFramingHeaders(response.headers.map((h) => ({ name: h.name, value: h.value })));
  try {
    await chrome.debugger.sendCommand({ tabId }, "Fetch.fulfillRequest", {
      requestId: fetchRequestId,
      responseCode: response.statusCode,
      responsePhrase: response.statusText || undefined,
      responseHeaders: headers,
      body: bodyAsBase64(response, record),
    });
  } catch (err) {
    throw new Error(`ZProxy could not fulfill the modified response: ${err.message}`);
  }
}

/** Forwards the response completely unmodified — prefers the response-stage-native command. */
export async function forwardUnmodified(tabId, fetchRequestId) {
  getPending(tabId).delete(fetchRequestId);
  try {
    await chrome.debugger.sendCommand({ tabId }, "Fetch.continueResponse", { requestId: fetchRequestId });
  } catch {
    // Fetch.continueResponse is Experimental in CDP; fall back for older Chrome builds.
    await chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: fetchRequestId });
  }
}

/**
 * Forward with no manual edit — but still WITH whatever content-engine rules
 * changed (shown to the user in the paused item), matching the request side.
 * Only a response no rule touched takes the native pass-through.
 */
export async function forward(tabId, fetchRequestId) {
  const record = getPending(tabId).get(fetchRequestId);
  if (!record || !responseActuallyChanged(record.original.response, record.item.response)) {
    return forwardUnmodified(tabId, fetchRequestId);
  }
  getPending(tabId).delete(fetchRequestId);
  await markEdited(record.original.request.method, record.original.request.url, record.original.pausedAt, {
    kind: "response",
    original: record.original.response,
    edited: record.item.response,
  }).catch(() => {});
  await fulfill(tabId, fetchRequestId, record.item.response, record);
}

export async function forwardEdited(tabId, fetchRequestId, editedResponse) {
  const record = getPending(tabId).get(fetchRequestId);
  let response = editedResponse;
  if (record) {
    const displayed = record.display.response;
    if ((editedResponse.body ?? null) === (displayed.body ?? null)) {
      // Body untouched in the inspector (only status/headers edited): send
      // the full body, not the possibly-truncated display copy.
      response = { ...editedResponse, body: record.item.response.body };
    } else if (displayed.bodyTruncated) {
      // Checked BEFORE removing it from the pending map, so the response
      // stays paused and can still be forwarded some other way.
      throw new Error(
        `This response body was truncated to ${MAX_INSPECT_BODY_BYTES.toLocaleString()} characters for display, so an edited body can't be forwarded without cutting off the rest. Edit only the status/headers, or use a content Match & Replace rule for the body.`
      );
    }
  }
  getPending(tabId).delete(fetchRequestId);
  // Marks the eventual History entry as "edited" — see edited-tracker.js.
  // Keyed by the REQUEST's method/URL (unaffected by a response edit):
  // that's the identity History entries are built around.
  if (record && responseActuallyChanged(record.original.response, response)) {
    await markEdited(record.original.request.method, record.original.request.url, record.original.pausedAt, {
      kind: "response",
      original: record.original.response,
      edited: response,
    }).catch(() => {});
  }
  await fulfill(tabId, fetchRequestId, response, record);
}

export async function drop(tabId, fetchRequestId, reason = "BlockedByClient") {
  getPending(tabId).delete(fetchRequestId);
  await chrome.debugger.sendCommand({ tabId }, "Fetch.failRequest", { requestId: fetchRequestId, errorReason: reason });
}

export function getPendingItems(tabId) {
  return [...getPending(tabId).values()].map((record) => record.display);
}

export function clearTab(tabId) {
  pendingByTab.delete(tabId);
}
