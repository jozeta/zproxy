import { DEFAULT_SCOPE } from "../background/scope.js";

// In-memory cache: getRules()/getScope() are on the hot path of every CDP
// Fetch.requestPaused pause (background/interception.js's handleFetchPaused
// runs isInScope() per pause, and per-request-in-scope rule application) —
// the pause holds up the actual network request until we act on it, so an
// uncached chrome.storage.local.get() there adds visible latency to every
// subresource on the page under test. Kept in sync by save*() below and by
// chrome.storage.onChanged for changes from another extension context.
let cachedRules = null;
let cachedScope = null;
let cachedInterceptRules = null;

if (typeof chrome !== "undefined" && chrome.storage?.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") return;
    if ("rules" in changes) cachedRules = null;
    if ("scope" in changes) cachedScope = null;
    if ("interceptRules" in changes) cachedInterceptRules = null;
  });
}

export async function getRules() {
  if (cachedRules) return cachedRules;
  const { rules } = await chrome.storage.local.get("rules");
  cachedRules = rules || [];
  return cachedRules;
}

export async function saveRules(rules) {
  cachedRules = rules;
  await chrome.storage.local.set({ rules });
  return rules;
}

export async function getScope() {
  if (cachedScope) return cachedScope;
  const { scope } = await chrome.storage.local.get("scope");
  cachedScope = scope || { ...DEFAULT_SCOPE };
  return cachedScope;
}

export async function saveScope(scope) {
  cachedScope = scope;
  await chrome.storage.local.set({ scope });
  return scope;
}

// Same hot-path caching rationale as getRules()/getScope() above — read on
// every CDP Fetch.requestPaused pause (background/interception.js).
export async function getInterceptRules() {
  if (cachedInterceptRules) return cachedInterceptRules;
  const { interceptRules } = await chrome.storage.local.get("interceptRules");
  cachedInterceptRules = interceptRules || [];
  return cachedInterceptRules;
}

export async function saveInterceptRules(interceptRules) {
  cachedInterceptRules = interceptRules;
  await chrome.storage.local.set({ interceptRules });
  return interceptRules;
}
