// Reads response bodies via CDP's Network domain for History (see
// background/body-tracker.js). Pure observation: Network.enable is already
// on for every attached tab (interception.js), and nothing here pauses or
// alters a request — unlike the Fetch domain the interceptors use.
import { attachResponseBody } from "../background/body-tracker.js";
import { base64ToText } from "../utils/bytes.js";

const requestsByTab = new Map(); // tabId -> Map(networkRequestId -> { method, url, type, mimeType })

// Binary bodies would just be lossy text in History and dead weight for the
// passive checks, which only look for text patterns.
const SKIPPED_TYPES = new Set(["Image", "Media", "Font"]);
const TEXT_MIME = /^(text\/|application\/([\w.+-]*\+)?(json|xml|javascript|ecmascript|x-www-form-urlencoded|graphql)\b)/i;

/** Pure — whether a finished response's body is worth reading for History. */
export function shouldCaptureBody(type, mimeType) {
  if (SKIPPED_TYPES.has(type)) return false;
  return TEXT_MIME.test(mimeType || "");
}

function requestsFor(tabId) {
  if (!requestsByTab.has(tabId)) requestsByTab.set(tabId, new Map());
  return requestsByTab.get(tabId);
}

/**
 * Handles one Network.* CDP event. `getContext()` resolves to
 * { isInScope(url), maxBodyBytes } — only read once a body is actually
 * wanted, so the common path stays synchronous.
 */
export function handleNetworkEvent(tabId, method, params, getContext) {
  const requests = requestsFor(tabId);
  if (method === "Network.requestWillBeSent") {
    // A redirect re-uses the requestId; the newest hop is the one whose body arrives.
    requests.set(params.requestId, { method: params.request.method, url: params.request.url, type: params.type, mimeType: null });
  } else if (method === "Network.responseReceived") {
    const req = requests.get(params.requestId);
    if (req) {
      req.type = params.type || req.type;
      req.mimeType = params.response?.mimeType || null;
    }
  } else if (method === "Network.loadingFailed") {
    requests.delete(params.requestId);
  } else if (method === "Network.loadingFinished") {
    const req = requests.get(params.requestId);
    requests.delete(params.requestId);
    if (req && shouldCaptureBody(req.type, req.mimeType)) {
      captureBody(tabId, params.requestId, req, Date.now(), getContext).catch(() => {
        // Best-effort: the body may already be evicted, or the tab gone.
      });
    }
  }
}

async function captureBody(tabId, networkRequestId, req, finishedAt, getContext) {
  const { isInScope, maxBodyBytes } = await getContext();
  if (!isInScope(req.url)) return;
  const result = await chrome.debugger.sendCommand({ tabId }, "Network.getResponseBody", { requestId: networkRequestId });
  let body = result.base64Encoded ? base64ToText(result.body) : result.body;
  if (typeof body !== "string") return;
  // One char over the cap, so history.js's own truncateBodies() still
  // notices and sets bodyTruncated, while a huge body isn't held in full.
  if (body.length > maxBodyBytes + 1) body = body.slice(0, maxBodyBytes + 1);
  await attachResponseBody(req.method, req.url, finishedAt, body);
}

export function clearTab(tabId) {
  requestsByTab.delete(tabId);
}
