// A capped ring buffer of captured traffic. Backed by chrome.storage.session
// by default (in-memory, cleared on browser restart — see docs/SECURITY.md)
// and optionally chrome.storage.local if the user opts into persistence.
import { getSettings } from "./settings.js";

let memoryHistory = [];
let loaded = false;
let loadPromise = null;
let persistTimer = null;

function storageAreaFor(settings) {
  return settings.persistHistoryToDisk ? chrome.storage.local : chrome.storage.session;
}

// Memoized: the service worker calls this at startup without awaiting, and
// the first addHistoryEntry() (often the very request that woke it) calls it
// again — two independent loads could resolve out of order and replace
// memoryHistory after an entry had already been pushed onto it.
export function loadHistory() {
  if (!loadPromise) {
    loadPromise = (async () => {
      const settings = await getSettings();
      const { history } = await storageAreaFor(settings).get("history");
      memoryHistory = history || [];
      loaded = true;
      return memoryHistory;
    })();
    loadPromise.catch(() => {
      loadPromise = null; // let the next caller retry
    });
  }
  return loadPromise;
}

export async function getHistory() {
  if (!loaded) await loadHistory();
  return memoryHistory;
}

function truncateBodies(entry, maxBodyBytes) {
  // entry.editDiff.{original,edited} (the before/after snapshots kept for
  // edited entries so the UI can show a comparison) are exactly as
  // body-heavy as entry.request/response and need the same cap.
  const sides = [entry.request, entry.response, entry.editDiff?.original, entry.editDiff?.edited];
  for (const side of sides) {
    if (side && typeof side.body === "string" && side.body.length > maxBodyBytes) {
      side.body = side.body.slice(0, maxBodyBytes);
      side.bodyTruncated = true;
    }
  }
  return entry;
}

export async function addHistoryEntry(entry) {
  if (!loaded) await loadHistory();
  const settings = await getSettings();
  memoryHistory.push(truncateBodies(entry, settings.maxBodyBytesStored));
  while (memoryHistory.length > settings.maxHistoryEntries) {
    memoryHistory.shift();
  }
  schedulePersist();
  return entry;
}

export async function updateHistoryEntry(id, patch) {
  if (!loaded) await loadHistory();
  const idx = memoryHistory.findIndex((e) => e.id === id);
  if (idx === -1) return null;
  const settings = await getSettings();
  memoryHistory[idx] = truncateBodies({ ...memoryHistory[idx], ...patch }, settings.maxBodyBytesStored);
  schedulePersist();
  return memoryHistory[idx];
}

// Clears both areas, not just the current one: history persisted to disk
// before the user switched persistence off must not survive a "Clear".
export async function clearHistory() {
  memoryHistory = [];
  await Promise.all([chrome.storage.local.remove("history"), chrome.storage.session.remove("history")]);
}

/**
 * Call after settings.persistHistoryToDisk changes: moves the in-memory
 * history to the newly selected area and deletes it from the other one.
 * Turning persistence off must actually take captured Authorization headers
 * and session cookies back off disk (docs/SECURITY.md), not just stop
 * writing new ones there.
 */
export async function applyHistoryPersistence(settings) {
  if (!loaded) await loadHistory();
  const other = settings.persistHistoryToDisk ? chrome.storage.session : chrome.storage.local;
  await persistNow(settings);
  await other.remove("history");
}

function schedulePersist() {
  if (persistTimer) return;
  persistTimer = setTimeout(async () => {
    persistTimer = null;
    // Settings are read when the timer fires, not when it was scheduled —
    // otherwise a write queued just before persistence was switched off
    // would put history back on disk after applyHistoryPersistence() removed it.
    try {
      await persistNow(await getSettings());
    } catch (err) {
      // Most likely chrome.storage.session's quota — history stays in
      // memory, but won't survive a service worker restart.
      console.warn("[ZProxy] could not persist history:", err.message);
    }
  }, 400);
}

async function persistNow(settings) {
  const area = storageAreaFor(settings);
  await area.set({ history: memoryHistory });
}
