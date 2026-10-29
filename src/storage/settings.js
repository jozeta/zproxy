export const SETTINGS_DEFAULTS = Object.freeze({
  maxHistoryEntries: 1000,
  persistHistoryToDisk: false, // see docs/SECURITY.md — session-only by default
  manualPauseEnabled: true, // whether Fetch pauses are shown to the user, vs auto-continued after rules apply
  interceptStage: "request", // "both" | "request" | "response" — which stage(s) Fetch.enable actually pauses at all
  // CDP Fetch resource types that never pause at all. Static assets are
  // skipped by default so Intercept shows the app's own traffic (documents,
  // XHR/fetch, form posts) instead of a wall of CSS/image/font/script pauses.
  excludedResourceTypes: ["Stylesheet", "Image", "Font", "Media", "Script"],
  // Side-panel views left out of the navigation (see src/utils/nav-visibility.js).
  // The specialist tools start hidden so the nav opens on the core workflow.
  hiddenViews: ["websockets", "access-control", "decoder", "comparer", "match-replace", "scope"],
  // Attach the debugger in observe-only mode to in-scope tabs so History and
  // Findings get response bodies without Intercept (background/passive-observer.js).
  captureBodiesWithoutIntercept: true,
  autoForwardTimeoutMs: 30000,
  maxBodyBytesStored: 200000,
  theme: "dark",
  shortcuts: {
    forward: "Ctrl+Enter",
    // Not "Ctrl+R": Chrome reserves that for page reload at the browser-chrome
    // level, so it never reaches this extension page's keydown listener no
    // matter what — see src/utils/shortcuts.js's doc comment.
    sendToRepeater: "Ctrl+Shift+E",
    search: "Ctrl+F",
    clearHistory: "Ctrl+K",
    toggleIntercept: "Ctrl+I",
  },
});

// In-memory cache: getSettings() is called on the hot path of every CDP
// Fetch.requestPaused pause (see background/interception.js) — a debugger
// pause holds up the actual network request until we decide what to do with
// it, so an uncached chrome.storage.local.get() there (an IPC round-trip to
// the browser process) adds real, visible latency to every single
// subresource on the page being tested. Settings only ever change via
// updateSettings() (which keeps the cache in sync) or, rarely, another
// extension context — chrome.storage.onChanged covers that case too.
let cachedSettings = null;

if (typeof chrome !== "undefined" && chrome.storage?.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local" && "settings" in changes) cachedSettings = null;
  });
}

export async function getSettings() {
  if (cachedSettings) return cachedSettings;
  const { settings } = await chrome.storage.local.get("settings");
  cachedSettings = { ...SETTINGS_DEFAULTS, ...(settings || {}) };
  return cachedSettings;
}

export async function updateSettings(patch) {
  const current = await getSettings();
  const next = { ...current, ...patch };
  cachedSettings = next;
  await chrome.storage.local.set({ settings: next });
  return next;
}

/**
 * Restores SETTINGS_DEFAULTS by deleting the stored settings rather than
 * writing the defaults into storage — so a later change to the defaults
 * reaches this install too, instead of being shadowed by a frozen copy.
 * Returns {previous, next} so the caller can react to what changed.
 */
export async function resetSettings() {
  const previous = await getSettings();
  await chrome.storage.local.remove("settings");
  // structuredClone: SETTINGS_DEFAULTS is frozen but its nested arrays/objects aren't.
  cachedSettings = structuredClone({ ...SETTINGS_DEFAULTS });
  return { previous, next: cachedSettings };
}
