// Response-stage handling for CDP Fetch.requestPaused (chrome.debugger backend).
// This is the only way an MV3 extension can read or rewrite a response body
// before it reaches the page — see docs/CAPABILITIES.md rows 9/10.
import { textToBase64, base64ToText } from "../utils/bytes.js";
import { withCorrectedFramingHeaders, headersEqual } from "../parsers/headers.js";
import { markEdited } from "../background/edited-tracker.js";
import { shouldPauseForRules } from "./intercept-rules.js";

const pendingByTab = new Map();
const MAX_INSPECT_BODY_BYTES = 500_000; // avoid freezing the UI on huge responses (perf requirement)

function getPending(tabId) {
  if (!pendingByTab.has(tabId)) pendingByTab.set(tabId, new Map());
  return pendingByTab.get(tabId);
}

async function fetchBodyText(tabId, fetchRequestId) {
  try {
    const result = await chrome.debugger.sendCommand({ tabId }, "Fetch.getResponseBody", { requestId: fetchRequestId });
    let text = result.base64Encoded ? base64ToText(result.body) : result.body;
    let truncated = false;
    if (text && text.length > MAX_INSPECT_BODY_BYTES) {
      text = text.slice(0, MAX_INSPECT_BODY_BYTES);
      truncated = true;
    }
    return { text, truncated, available: true };
  } catch {
    // Not every paused response has a readable body (e.g. redirects, HEAD,
    // 304s, opaque cross-origin). This is expected, not an error state.
    return { text: null, truncated: false, available: false };
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
      bodyTruncated: body.truncated,
      bodyAvailable: body.available,
      mimeType: contentType,
    },
  };
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
  const body = await fetchBodyText(tabId, params.requestId);
  const original = buildPendingItem(tabId, params, body);
  const item = applyRules ? applyRules(original) : original;

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
      await continueWithItem(tabId, params.requestId, item);
    }
    return;
  }

  getPending(tabId).set(params.requestId, item);
  emit({ type: "response-paused", tabId, item });
}

async function continueWithItem(tabId, fetchRequestId, item) {
  const headers = withCorrectedFramingHeaders(item.response.headers.map((h) => ({ name: h.name, value: h.value })));
  try {
    await chrome.debugger.sendCommand({ tabId }, "Fetch.fulfillRequest", {
      requestId: fetchRequestId,
      responseCode: item.response.statusCode,
      responsePhrase: item.response.statusText || undefined,
      responseHeaders: headers,
      body: typeof item.response.body === "string" ? textToBase64(item.response.body) : undefined,
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

export async function forwardEdited(tabId, fetchRequestId, editedResponse) {
  const original = getPending(tabId).get(fetchRequestId);
  getPending(tabId).delete(fetchRequestId);
  // Marks the eventual History entry as "edited" — see edited-tracker.js.
  // Keyed by the REQUEST's method/URL (unaffected by a response edit):
  // that's the identity History entries are built around.
  if (original && responseActuallyChanged(original.response, editedResponse)) {
    await markEdited(original.request.method, original.request.url, original.pausedAt, {
      kind: "response",
      original: original.response,
      edited: editedResponse,
    }).catch(() => {});
  }
  await continueWithItem(tabId, fetchRequestId, { response: editedResponse });
}

export async function drop(tabId, fetchRequestId, reason = "BlockedByClient") {
  getPending(tabId).delete(fetchRequestId);
  await chrome.debugger.sendCommand({ tabId }, "Fetch.failRequest", { requestId: fetchRequestId, errorReason: reason });
}

export function getPendingItems(tabId) {
  return [...getPending(tabId).values()];
}

export function clearTab(tabId) {
  pendingByTab.delete(tabId);
}
