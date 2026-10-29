// Passive body capture: whenever a Scope is defined, attach Chrome's
// debugger in observe-only mode (interception.js observeTab — Network
// domain only, nothing is ever paused) to every tab showing an in-scope
// page, so History and Findings get response bodies without Intercept.
//
// The cost, stated plainly in Settings and the README: Chrome shows its own
// "ZProxy started debugging this browser" banner while any tab is observed.
// Dismissing it ("Cancel") ends observation for that tab until it closes
// (interception.js optedOutTabs). Settings → "Capture response bodies
// without Intercept" turns the whole feature off.
import { isInScope } from "./scope.js";
import { scopeIsDefined } from "./findings-monitor.js";

/** Pure — should a tab at `url` be observed? */
export function shouldObserve(url, scope, settings) {
  if (!settings?.captureBodiesWithoutIntercept) return false;
  if (!scopeIsDefined(scope) || !scope.enabled) return false;
  if (!/^https?:\/\//i.test(url || "")) return false;
  return isInScope(url, scope);
}

/**
 * Starts watching tabs. `deps`: Interception (observeTab/stopObserving/
 * isAttached/isObserved/setKeepObservingPolicy), getScope(), getSettings(),
 * hasHostAccess().
 */
export function startPassiveObserver({ Interception, getScope, getSettings, hasHostAccess }) {
  async function wanted(url) {
    const [scope, settings, hosts] = await Promise.all([getScope(), getSettings(), hasHostAccess()]);
    return hosts && shouldObserve(url, scope, settings);
  }

  async function evaluate(tabId, url) {
    if (Interception.isAttached(tabId)) return; // Intercept owns the session
    if (await wanted(url)) await Interception.observeTab(tabId);
    else if (Interception.isObserved(tabId)) await Interception.stopObserving(tabId);
  }

  /** Re-checks every open tab — after Scope or the setting changes. */
  async function reevaluateAll() {
    const tabs = await chrome.tabs.query({});
    await Promise.all(tabs.map((t) => (t.id != null ? evaluate(t.id, t.url).catch(() => {}) : null)));
  }

  // After Intercept is switched off on a tab, keep observing it if it would be observed anyway.
  Interception.setKeepObservingPolicy(async (tabId) => {
    const tab = await chrome.tabs.get(tabId);
    return wanted(tab.url);
  });

  // "loading" fires as a navigation starts — early enough to catch most of
  // the page's own requests (a document fetched before the attach completes
  // is missed; it's picked up on the next load).
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "loading" || changeInfo.url) evaluate(tabId, changeInfo.url || tab.url).catch(() => {});
  });

  // Nothing can be observed before host access is granted — re-check once it is.
  chrome.permissions.onAdded.addListener(() => reevaluateAll().catch(() => {}));

  reevaluateAll().catch(() => {});
  return { reevaluateAll };
}
