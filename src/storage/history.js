// A capped ring buffer of captured traffic. Backed by chrome.storage.session
// by default (in-memory, cleared on browser restart — see docs/SECURITY.md)
// and optionally chrome.storage.local if the user opts into persistence.
import { getSettings } from "./settings.js";

let memoryHistory = [];
let loaded = false;
let persistTimer = null;

function storageAreaFor(settings) {
  return settings.persistHistoryToDisk ? chrome.storage.local : chrome.storage.session;
}

export async function loadHistory() {
  const settings = await getSettings();
  const area = storageAreaFor(settings);
  const { history } = await area.get("history");
  memoryHistory = history || [];
  loaded = true;
  return memoryHistory;
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
  schedulePersist(settings);
  return entry;
}

export async function updateHistoryEntry(id, patch) {
  if (!loaded) await loadHistory();
  const idx = memoryHistory.findIndex((e) => e.id === id);
  if (idx === -1) return null;
  const settings = await getSettings();
  memoryHistory[idx] = truncateBodies({ ...memoryHistory[idx], ...patch }, settings.maxBodyBytesStored);
  schedulePersist(settings);
  return memoryHistory[idx];
}

export async function clearHistory() {
  memoryHistory = [];
  const settings = await getSettings();
  await persistNow(settings);
}

function schedulePersist(settings) {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    persistNow(settings).catch(() => {});
  }, 400);
}

async function persistNow(settings) {
  const area = storageAreaFor(settings);
  await area.set({ history: memoryHistory });
}
