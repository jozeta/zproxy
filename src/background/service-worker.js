// ZProxy service worker — the single source of truth for traffic capture,
// DNR rule sync, and debugger-based interception. See docs/ARCHITECTURE.md.
import { registerTrafficListeners, onTrafficEntry } from "./traffic-manager.js";
import { syncDnrRules } from "./dnr-rules.js";
import * as Interception from "./interception.js";
import * as RequestInterceptor from "../interception/request-interceptor.js";
import * as ResponseInterceptor from "../interception/response-interceptor.js";
import * as WebSocketInterceptor from "../interception/websocket-interceptor.js";
import * as Permissions from "./permissions.js";
import { getSettings, updateSettings } from "../storage/settings.js";
import { getRules, saveRules, getScope, saveScope, getInterceptRules, saveInterceptRules } from "../storage/rules.js";
import { getHistory, clearHistory, loadHistory, updateHistoryEntry } from "../storage/history.js";
import { addHostToScope } from "./scope.js";

registerTrafficListeners();
loadHistory();
syncDnrRules().catch((err) => console.error("[ZProxy] initial DNR sync failed:", err.message));

chrome.runtime.onInstalled.addListener(() => {
  syncDnrRules().catch((err) => console.error("[ZProxy] DNR sync failed:", err.message));
});

function broadcast(event) {
  chrome.runtime.sendMessage({ type: "push", event }).catch(() => {
    // No listeners open (popup/side panel closed) — nothing to do.
  });
}

onTrafficEntry((entry) => broadcast({ type: "history:new-entry", entry }));
Interception.onInterceptionEvent((event) => broadcast({ type: "intercept:event", event }));

const handlers = {
  "settings:get": () => getSettings(),
  "settings:update": async ({ patch }) => {
    const next = await updateSettings(patch);
    if ("interceptStage" in patch || "excludedResourceTypes" in patch) {
      await Interception.refreshFetchPatternsForAttachedTabs();
    }
    return next;
  },

  "scope:get": () => getScope(),
  "scope:save": ({ scope }) => saveScope(scope),

  "rules:get": () => getRules(),
  "rules:save": async ({ rules }) => {
    await saveRules(rules);
    await syncDnrRules();
    return rules;
  },

  "interceptRules:get": () => getInterceptRules(),
  "interceptRules:save": ({ interceptRules }) => saveInterceptRules(interceptRules),

  "history:get": () => getHistory(),
  "history:clear": () => clearHistory(),
  // Tag/comment triage metadata only — see history.js's tag-dot click
  // handler and saveComment(). Not a general-purpose entry editor: nothing
  // else in the UI patches a History entry after capture.
  "history:update": ({ id, patch }) => updateHistoryEntry(id, patch),

  "permissions:hasHostAccess": () => Permissions.hasHostAccess(),
  "permissions:requestHostAccess": () => Permissions.requestHostAccess(),
  "permissions:hasDebugger": () => Permissions.hasDebuggerPermission(),

  "intercept:status": ({ tabId }) => ({ attached: Interception.isAttached(tabId), stats: Interception.getStats(tabId) }),
  // {id, title, url} per attached tab, not just ids — the Intercept view's
  // "Managing tab" picker needs something human-readable to list. A tab
  // that's been attached but then closed (chrome.tabs.get throws) still
  // shows up with null title/url rather than being silently dropped, since
  // Intercept's own bookkeeping (attachedTabs) hasn't been told it's gone
  // yet either — see interception.js's chrome.tabs.onRemoved listener.
  "intercept:attachedTabs": async () => {
    const ids = Interception.getAttachedTabs();
    return Promise.all(
      ids.map(async (id) => {
        try {
          const tab = await chrome.tabs.get(id);
          return { id, title: tab.title || null, url: tab.url || null };
        } catch {
          return { id, title: null, url: null };
        }
      })
    );
  },
  "intercept:attach": async ({ tabId, host }) => {
    // Attaching Intercept to a tab should mean "this tab's traffic is in
    // scope" — not silently pause nothing until the user separately finds
    // and configures Scope. `host` is the tab's hostname, resolved by the
    // caller (side panel/popup) since only they know which tab was clicked.
    if (host) {
      const current = await getScope();
      await saveScope(addHostToScope(current, host));
    }
    return Interception.attachTab(tabId);
  },
  "intercept:detach": ({ tabId }) => Interception.detachTab(tabId).then(() => ({ ok: true })),
  "intercept:pending": ({ tabId }) => ({
    requests: RequestInterceptor.getPendingItems(tabId),
    responses: ResponseInterceptor.getPendingItems(tabId),
  }),
  "intercept:forward": ({ tabId, kind, fetchRequestId }) =>
    (kind === "response" ? ResponseInterceptor.forwardUnmodified : RequestInterceptor.forward)(tabId, fetchRequestId).then(
      () => ({ ok: true })
    ),
  "intercept:forwardEdited": ({ tabId, kind, fetchRequestId, edited }) =>
    (kind === "response"
      ? ResponseInterceptor.forwardEdited(tabId, fetchRequestId, edited)
      : RequestInterceptor.forwardEdited(tabId, fetchRequestId, edited)
    ).then(() => ({ ok: true })),
  "intercept:drop": ({ tabId, kind, fetchRequestId }) =>
    (kind === "response" ? ResponseInterceptor.drop : RequestInterceptor.drop)(tabId, fetchRequestId).then(() => ({
      ok: true,
    })),
  "intercept:forwardAndDontInterceptAgain": ({ tabId, fetchRequestId, edited }) =>
    RequestInterceptor.forwardAndDontInterceptAgain(tabId, fetchRequestId, edited).then(() => ({ ok: true })),

  "websocket:list": ({ tabId }) => WebSocketInterceptor.getSockets(tabId),
  "websocket:frames": ({ tabId, requestId }) => WebSocketInterceptor.getFrames(tabId, requestId),

  "cookies:getAll": (filter) => chrome.cookies.getAll(filter || {}),
  "cookies:set": (details) => chrome.cookies.set(details),
  "cookies:remove": ({ url, name }) => chrome.cookies.remove({ url, name }),

  "tabs:current": async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab ? { id: tab.id, url: tab.url, title: tab.title } : null;
  },
};

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const handler = handlers[message?.type];
  if (!handler) return false;
  Promise.resolve(handler(message.payload || {}))
    .then((result) => sendResponse({ ok: true, result }))
    .catch((err) => sendResponse({ ok: false, error: err.message }));
  return true; // keep the message channel open for the async response
});
