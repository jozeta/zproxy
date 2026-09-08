import { call, onPush, getCurrentTab } from "../components/api.js";
import { infoIcon, hideActiveTooltip } from "../components/tooltip.js";
import { matchesShortcut } from "../../utils/shortcuts.js";
import { renderDashboard } from "./views/dashboard.js";
import { renderHistory } from "./views/history.js";
import { renderFindings } from "./views/findings.js";
import { renderIntercept } from "./views/intercept.js";
import { renderRepeater } from "./views/repeater.js";
import { renderIntruder } from "./views/intruder.js";
import { renderCookies } from "./views/cookies.js";
import { renderMatchReplace } from "./views/match-replace.js";
import { renderScope } from "./views/scope.js";
import { renderSettings } from "./views/settings.js";
import { renderDecoder } from "./views/decoder.js";
import { renderComparer } from "./views/comparer.js";

const VIEWS = [
  { id: "dashboard", label: "Dashboard", render: renderDashboard },
  { id: "history", label: "History", render: renderHistory },
  { id: "findings", label: "Findings", render: renderFindings },
  { id: "intercept", label: "Intercept", render: renderIntercept },
  { id: "repeater", label: "Repeater", render: renderRepeater },
  { id: "intruder", label: "Intruder", render: renderIntruder },
  { id: "cookies", label: "Cookies", render: renderCookies },
  { id: "decoder", label: "Decoder", render: renderDecoder },
  { id: "comparer", label: "Comparer", render: renderComparer },
  { id: "match-replace", label: "Match/Replace", render: renderMatchReplace },
  { id: "scope", label: "Scope", render: renderScope },
  { id: "settings", label: "Settings", render: renderSettings },
];

const nav = document.getElementById("nav");
const main = document.getElementById("main");
const interceptToggle = document.getElementById("intercept-toggle");
const interceptLabel = document.getElementById("intercept-toggle-label");
const scopeBadge = document.getElementById("scope-badge");

scopeBadge.after(
  infoIcon(
    "Which hosts ZProxy is allowed to see. Traffic for hosts outside Scope is never captured or intercepted — configure it in the Scope tab.",
    { label: "About Scope" }
  )
);
interceptToggle.after(
  infoIcon(
    "Attaches ZProxy's debugger to the active tab so its requests/responses can be paused, inspected, and edited before they go out. Also adds the tab's host to Scope automatically.",
    { label: "About Intercept" }
  )
);

let activeView = "dashboard";
let currentTab = null;
let currentViewCleanup = null;
let interceptNavBtn = null;
let interceptAttachedForBadge = false;
let interceptPendingCount = 0;

// Repeater/Intruder state is shared across view switches so "Send to
// Repeater"/"Send to Intruder" from History/Intercept can hand off a
// request without losing anything. shortcutHandlers is populated by
// whichever view currently supports a given action (see the global keydown
// listener below) — each view claims/releases its own entries on
// mount/unmount, following the same ownership-check pattern Intruder uses
// for state.notify (see views/intruder.js).
const sharedState = { repeaterQueue: [], intruderQueue: [], comparerQueue: [], shortcutHandlers: {} };
let shortcuts = {};

async function refreshShortcuts() {
  try {
    const settings = await call("settings:get");
    shortcuts = settings.shortcuts || {};
  } catch {
    /* background not ready yet */
  }
}

// Global, not per-view: toggleIntercept always works (it's the header
// toggle); forward/sendToRepeater/search/clearHistory only do anything when
// the currently mounted view has registered a handler for them in
// sharedState.shortcutHandlers — a shortcut for an action the active view
// doesn't support is silently a no-op rather than an error.
document.addEventListener("keydown", (event) => {
  if (matchesShortcut(event, shortcuts.toggleIntercept)) {
    event.preventDefault();
    interceptToggle.click();
    return;
  }
  for (const name of ["forward", "sendToRepeater", "search", "clearHistory"]) {
    if (matchesShortcut(event, shortcuts[name]) && sharedState.shortcutHandlers[name]) {
      event.preventDefault();
      sharedState.shortcutHandlers[name]();
      return;
    }
  }
});

function makeCtx() {
  return {
    api: call,
    onPush,
    getTab: () => currentTab,
    navigateTo,
    sharedState,
    // Forwarding/dropping a pending item doesn't broadcast its own push
    // event, so the nav badge's count can't otherwise learn a decrease
    // happened until the next 5s poll. The Intercept view is the only place
    // that changes it, so it calls this directly for an immediate update.
    refreshInterceptBadge: refreshInterceptPendingCount,
  };
}

/**
 * chrome.debugger.attach() refuses to touch a `chrome://`, `chrome-extension://`
 * (including this one's own pages), `devtools://`, or Chrome Web Store page —
 * these are all outside what an extension is allowed to debug, for the exact
 * same security-boundary reason as "Cannot access a chrome-extension:// URL
 * of different extension" (a real error this surfaced with once). Checked
 * up front so the user gets one clear sentence instead of that raw Chrome
 * error after already going through a permission prompt.
 */
function isDebuggableUrl(url) {
  if (!url) return false;
  try {
    return ["http:", "https:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}

function renderNav() {
  nav.textContent = "";
  interceptNavBtn = null;
  for (const view of VIEWS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "zp-nav-item" + (view.id === activeView ? " active" : "");
    const labelSpan = document.createElement("span");
    labelSpan.textContent = view.label;
    btn.appendChild(labelSpan);
    btn.addEventListener("click", () => navigateTo(view.id));
    nav.appendChild(btn);
    if (view.id === "intercept") interceptNavBtn = btn;
  }
  updateInterceptNavBadge();
}

function updateInterceptNavBadge() {
  if (!interceptNavBtn) return;
  interceptNavBtn.querySelector(".zp-nav-count")?.remove();
  if (interceptAttachedForBadge && interceptPendingCount > 0) {
    const count = document.createElement("span");
    count.className = "zp-nav-count";
    count.textContent = String(interceptPendingCount);
    interceptNavBtn.appendChild(count);
  }
}

/** Pending count shown in the nav badge — needs its own fetch since it must
 * stay current even while a different view (not Intercept) is on screen. */
async function refreshInterceptPendingCount() {
  if (!currentTab || !interceptAttachedForBadge) {
    interceptPendingCount = 0;
    updateInterceptNavBadge();
    return;
  }
  try {
    const pending = await call("intercept:pending", { tabId: currentTab.id });
    interceptPendingCount = (pending.requests?.length || 0) + (pending.responses?.length || 0);
  } catch {
    interceptPendingCount = 0;
  }
  updateInterceptNavBadge();
}

function navigateTo(viewId) {
  hideActiveTooltip();
  activeView = viewId;
  renderNav();
  main.textContent = "";
  currentViewCleanup?.();
  currentViewCleanup = null;
  const view = VIEWS.find((v) => v.id === viewId) || VIEWS[0];
  const result = view.render(main, makeCtx());
  if (typeof result === "function") currentViewCleanup = result;
}

async function refreshInterceptState() {
  if (!currentTab) return;
  try {
    const { attached } = await call("intercept:status", { tabId: currentTab.id });
    interceptToggle.classList.toggle("on", attached);
    interceptLabel.textContent = attached ? "Intercept: ON (this tab)" : "Intercept: OFF";
    interceptAttachedForBadge = attached;
  } catch {
    interceptLabel.textContent = "Intercept: OFF";
    interceptAttachedForBadge = false;
  }
  await refreshInterceptPendingCount();
}

async function refreshScopeBadge() {
  try {
    const scope = await call("scope:get");
    const count = scope.enabled ? (scope.include || []).length : 0;
    scopeBadge.textContent = scope.enabled ? `Scope: ${count} pattern${count === 1 ? "" : "s"}` : "Scope: off";
    scopeBadge.classList.toggle("on", scope.enabled && count > 0);
  } catch {
    /* background not ready yet */
  }
}

interceptToggle.addEventListener("click", async () => {
  if (!currentTab) return;
  const { attached } = await call("intercept:status", { tabId: currentTab.id });
  if (attached) {
    await call("intercept:detach", { tabId: currentTab.id });
  } else {
    if (!isDebuggableUrl(currentTab.url)) {
      window.alert(
        "ZProxy can't attach to this tab — it's a browser-internal or extension page, not a regular website. Switch to the site you want to test, then click Intercept again."
      );
      return;
    }
    const hasHosts = await call("permissions:hasHostAccess");
    if (!hasHosts) {
      const granted = await call("permissions:requestHostAccess");
      if (!granted) return;
    }
    let host = null;
    try {
      host = new URL(currentTab.url).hostname;
    } catch {
      /* chrome:// or similar — nothing to add to Scope */
    }
    const result = await call("intercept:attach", { tabId: currentTab.id, host });
    if (!result.ok) {
      const friendly = /chrome-extension:\/\/ URL of different extension/i.test(result.error)
        ? "this tab is showing another extension's page, which ZProxy isn't allowed to debug. Switch to the site you want to test and try again."
        : result.error;
      window.alert(`ZProxy could not attach the debugger: ${friendly}`);
    }
    refreshScopeBadge();
  }
  refreshInterceptState();
});

onPush((event) => {
  if (event.type !== "intercept:event" || event.event.tabId !== currentTab?.id) return;
  if (event.event.type === "attached" || event.event.type === "detached") {
    refreshInterceptState();
  } else {
    // request-paused/response-paused (a new item just queued) — the nav
    // badge needs to know immediately. Forwarding/dropping an item doesn't
    // broadcast an event of its own, so the badge count going back down
    // relies on the polling interval below instead.
    refreshInterceptPendingCount();
  }
});

async function init() {
  currentTab = await getCurrentTab();
  chrome.tabs.onActivated.addListener(async () => {
    currentTab = await getCurrentTab();
    refreshInterceptState();
  });
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (tabId === currentTab?.id && changeInfo.url) {
      currentTab.url = changeInfo.url;
    }
  });
  renderNav();
  navigateTo(activeView);
  refreshInterceptState();
  refreshScopeBadge();
  refreshShortcuts();
  setInterval(() => {
    refreshScopeBadge();
    refreshInterceptPendingCount();
    refreshShortcuts();
  }, 5000);
}

init();
