// Owns the chrome.debugger lifecycle. Attaching is explicit and per-tab (the
// user turns Intercept on for the tab they're testing) — see
// docs/CAPABILITIES.md "Debugger caveats" for why this is never automatic or
// global.
import { getScope, getRules, getInterceptRules } from "../storage/rules.js";
import { isInScope } from "./scope.js";
import { getSettings } from "../storage/settings.js";
import * as RequestInterceptor from "../interception/request-interceptor.js";
import * as ResponseInterceptor from "../interception/response-interceptor.js";
import * as WebSocketInterceptor from "../interception/websocket-interceptor.js";
import * as NetworkBodyCapture from "../interception/network-body-capture.js";
import { applyRulesToUrl, applyRulesToHeaders, applyRulesToBody } from "../interception/match-replace.js";

const attachedTabs = new Set();
const listeners = new Set();
// Per-tab counters so the UI can tell "nothing paused because Intercept
// isn't seeing any of your traffic" apart from "nothing paused because
// everything so far has been out of Scope" — the latter looks identical to
// a broken extension if it's silent. See getStats()/intercept.js.
const tabStats = new Map(); // tabId -> { seen, outOfScope }

function statsFor(tabId) {
  if (!tabStats.has(tabId)) tabStats.set(tabId, { seen: 0, outOfScope: 0 });
  return tabStats.get(tabId);
}

export function getStats(tabId) {
  return tabStats.get(tabId) || { seen: 0, outOfScope: 0 };
}

export function onInterceptionEvent(cb) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function emit(event) {
  for (const cb of listeners) cb(event);
}

export function isAttached(tabId) {
  return attachedTabs.has(tabId);
}

export function getAttachedTabs() {
  return [...attachedTabs];
}

// Resource-type strings Fetch.RequestPattern.resourceType actually accepts.
// This is NOT the full Network.ResourceType enum from the protocol docs —
// confirmed at runtime ({"code":-32602,"message":"Unknown resource type in
// fetch filter: 'TextTrack'"}) and against Chromium's own implementation
// (content/browser/devtools/protocol/fetch_handler.cc,
// AddInterceptedResourceType()): Fetch's filter only recognizes these 12
// strings, mapping each to one or more internal resource-type buckets
// (e.g. "Other" covers kSubResource/kObject/kWorker/kSharedWorker/
// kFavicon/kServiceWorker/kPluginResource). TextTrack, Preflight, WebSocket,
// Manifest, SignedExchange, and FedCM are valid Network.ResourceType values
// used elsewhere in CDP but are NOT valid here and are rejected outright.
// (WebSocket traffic was never routed through Fetch.requestPaused anyway —
// see websocket-interceptor.js, which uses Network.webSocketFrame* events
// instead — so its absence here costs nothing.) NOT the same
// strings/casing as declarativeNetRequest's resourceTypes in dnr-rules.js
// (lowercase, a different set) — unrelated vocabularies that happen to
// both describe "kinds of request".
const ALL_RESOURCE_TYPES = [
  "Document",
  "Stylesheet",
  "Image",
  "Media",
  "Font",
  "Script",
  "XHR",
  "Fetch",
  "EventSource",
  "CSPViolationReport",
  "Ping",
  "Other",
];

/**
 * Which Fetch.requestPaused patterns to register, per settings.interceptStage
 * and settings.excludedResourceTypes.
 *
 * A stage left out of `patterns` entirely never pauses at all for that
 * stage — cheaper than pausing-then-immediately-continuing, and it also
 * means content-engine rules scoped to the excluded stage simply never get
 * a chance to run (there's nothing paused for them to act on). The same
 * logic applies per resource type: Fetch.enable's patterns are an allow-list
 * of what TO intercept, not a block-list, so excluding a type (e.g. CSS)
 * means enumerating every OTHER type explicitly instead of a single
 * catch-all "*" pattern.
 */
export function buildFetchPatterns(interceptStage, excludedResourceTypes = []) {
  const stages = [];
  if (interceptStage !== "response") stages.push("Request");
  if (interceptStage !== "request") stages.push("Response");

  const excluded = new Set(excludedResourceTypes);
  if (excluded.size === 0) {
    return stages.map((requestStage) => ({ urlPattern: "*", requestStage }));
  }

  const includedTypes = ALL_RESOURCE_TYPES.filter((t) => !excluded.has(t));
  const patterns = [];
  for (const requestStage of stages) {
    for (const resourceType of includedTypes) {
      patterns.push({ urlPattern: "*", resourceType, requestStage });
    }
  }
  return patterns;
}

/** Re-applies the current interceptStage/excludedResourceTypes settings to every already-attached tab, so changing either takes effect immediately rather than only on the next attach. */
export async function refreshFetchPatternsForAttachedTabs() {
  if (attachedTabs.size === 0) return;
  const settings = await getSettings();
  const patterns = buildFetchPatterns(settings.interceptStage, settings.excludedResourceTypes);
  await Promise.all(
    [...attachedTabs].map((tabId) => chrome.debugger.sendCommand({ tabId }, "Fetch.enable", { patterns }).catch(() => {}))
  );
}

export async function attachTab(tabId) {
  if (attachedTabs.has(tabId)) return { ok: true };
  if (!chrome.debugger) return { ok: false, error: "The debugger permission has not been granted yet." };
  registerDebuggerListeners();
  tabStats.set(tabId, { seen: 0, outOfScope: 0 });
  try {
    await chrome.debugger.attach({ tabId }, "1.3");
  } catch (err) {
    return { ok: false, error: err.message };
  }
  attachedTabs.add(tabId);
  try {
    const settings = await getSettings();
    await chrome.debugger.sendCommand({ tabId }, "Fetch.enable", {
      patterns: buildFetchPatterns(settings.interceptStage, settings.excludedResourceTypes),
    });
    await chrome.debugger.sendCommand({ tabId }, "Network.enable", {});
  } catch (err) {
    attachedTabs.delete(tabId);
    try {
      await chrome.debugger.detach({ tabId });
    } catch {
      /* already gone */
    }
    return { ok: false, error: err.message };
  }
  emit({ type: "attached", tabId });
  return { ok: true };
}

export async function detachTab(tabId) {
  if (!attachedTabs.has(tabId)) return;
  // Detaching does NOT resolve any request still paused via Fetch — Chrome's
  // network stack just keeps waiting for a decision (continue/fulfill/fail)
  // that can now never come, since the only thing that could send it was
  // this debugger session. Any request left paused when the debugger goes
  // away hangs indefinitely — which, given a page load almost always leaves
  // *something* paused (sub-resources, or the response-stage pause that
  // follows forwarding a request), is exactly why turning Intercept off
  // used to look like it "got stuck" rather than releasing the page.
  // clearTab() below only drops our own bookkeeping — it was never enough
  // on its own. So: forward everything still pending, unmodified, first.
  const pendingRequests = RequestInterceptor.getPendingItems(tabId);
  const pendingResponses = ResponseInterceptor.getPendingItems(tabId);
  await Promise.all([
    ...pendingRequests.map((item) => RequestInterceptor.forward(tabId, item.fetchRequestId).catch(() => {})),
    ...pendingResponses.map((item) => ResponseInterceptor.forward(tabId, item.fetchRequestId).catch(() => {})),
  ]);
  clearTabState(tabId);
  try {
    await chrome.debugger.detach({ tabId });
  } catch {
    /* tab may already be closed */
  }
  emit({ type: "detached", tabId });
}

// `debugger` is a required permission (manifest.json — Chrome refuses to let
// it be optional at all: "Permission 'debugger' cannot be listed as
// optional"), so `chrome.debugger` is defined from the moment the service
// worker starts. This guard is defensive leftover from when `debugger` was
// briefly (incorrectly) declared optional, during which `chrome.debugger`
// was `undefined` until granted and calling `.onEvent` on it at module
// top-level crashed the whole service worker ("Cannot read properties of
// undefined (reading 'onEvent')" -> "Service worker registration failed").
// Kept as a no-cost safety net rather than assuming the manifest can never
// regress.
let debuggerListenersRegistered = false;

async function bodyCaptureContext() {
  const [scope, settings] = await Promise.all([getScope(), getSettings()]);
  return { isInScope: (url) => isInScope(url, scope), maxBodyBytes: settings.maxBodyBytesStored };
}

function clearTabState(tabId) {
  attachedTabs.delete(tabId);
  tabStats.delete(tabId);
  RequestInterceptor.clearTab(tabId);
  ResponseInterceptor.clearTab(tabId);
  WebSocketInterceptor.clearTab(tabId);
  NetworkBodyCapture.clearTab(tabId);
}

function registerDebuggerListeners() {
  if (debuggerListenersRegistered || !chrome.debugger) return;
  debuggerListenersRegistered = true;

  chrome.debugger.onEvent.addListener((source, method, params) => {
    const tabId = source.tabId;
    if (tabId == null || !attachedTabs.has(tabId)) return;

    if (method === "Fetch.requestPaused") {
      handleFetchPaused(tabId, params).catch((err) => {
        emit({ type: "error", tabId, error: `Interception error: ${err.message}` });
      });
    } else if (
      method === "Network.webSocketFrameSent" ||
      method === "Network.webSocketFrameReceived" ||
      method === "Network.webSocketCreated"
    ) {
      WebSocketInterceptor.handleEvent(tabId, method, params, emit);
    } else if (
      method === "Network.requestWillBeSent" ||
      method === "Network.responseReceived" ||
      method === "Network.loadingFinished" ||
      method === "Network.loadingFailed"
    ) {
      NetworkBodyCapture.handleNetworkEvent(tabId, method, params, bodyCaptureContext);
    }
  });

  chrome.debugger.onDetach.addListener((source, reason) => {
    if (source.tabId == null) return;
    clearTabState(source.tabId);
    emit({ type: "detached", tabId: source.tabId, reason });
  });
}

// Guarded on `chrome` existing at all (not just chrome.debugger) so this
// module can be imported from a plain Node test runner for its pure helpers
// (buildFetchPatterns) without a chrome global present — these listeners
// are meaningless outside a real extension context anyway.
if (typeof chrome !== "undefined") {
  registerDebuggerListeners();
  chrome.permissions.onAdded.addListener((permissions) => {
    if (permissions.permissions?.includes("debugger")) registerDebuggerListeners();
  });

  chrome.tabs.onRemoved.addListener((tabId) => clearTabState(tabId));
}

function makeRequestRulesApplier(rules) {
  return (item) => {
    const url = applyRulesToUrl(rules, item.request.url, "request");
    const headers = applyRulesToHeaders(rules, item.request.headers, "request");
    const body = applyRulesToBody(rules, item.request.body, "request");
    return { ...item, request: { ...item.request, url, headers, body } };
  };
}

function makeResponseRulesApplier(rules) {
  return (item) => {
    const headers = applyRulesToHeaders(rules, item.response.headers, "response");
    const body = applyRulesToBody(rules, item.response.body, "response");
    return { ...item, response: { ...item.response, headers, body } };
  };
}

async function handleFetchPaused(tabId, params) {
  const scope = await getScope();
  const url = params.request.url;
  const stats = statsFor(tabId);
  stats.seen++;

  if (!isInScope(url, scope)) {
    stats.outOfScope++;
    // Out of scope: never pause it, never even run rules against it.
    try {
      if (params.responseStatusCode !== undefined || params.responseErrorReason) {
        await chrome.debugger.sendCommand({ tabId }, "Fetch.continueResponse", { requestId: params.requestId }).catch(() =>
          chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: params.requestId })
        );
      } else {
        await chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: params.requestId });
      }
    } catch {
      /* the tab/request may already be gone */
    }
    return;
  }

  const [rules, settings, interceptRules] = await Promise.all([getRules(), getSettings(), getInterceptRules()]);
  const contentRules = rules.filter((r) => r.engine === "content");
  const isResponseStage = params.responseStatusCode !== undefined || params.responseErrorReason;

  if (isResponseStage) {
    await ResponseInterceptor.handlePaused(tabId, params, {
      applyRules: makeResponseRulesApplier(contentRules),
      manualPauseEnabled: settings.manualPauseEnabled,
      interceptRules,
      emit,
    });
  } else {
    await RequestInterceptor.handlePaused(tabId, params, {
      applyRules: makeRequestRulesApplier(contentRules),
      manualPauseEnabled: settings.manualPauseEnabled,
      interceptRules,
      emit,
    });
  }
}
