// Gives History entries response bodies, which chrome.webRequest never
// exposes (docs/CAPABILITIES.md row 9). While Intercept's debugger is
// attached, network-body-capture.js reads each finished response's body
// through CDP's Network domain — observation only, nothing is paused, so
// this works whatever Intercept's stage/resource-type settings are — and
// hands it here to be joined onto the matching History entry.
//
// Same correlation problem as edited-tracker.js: CDP's Network requestId
// isn't chrome.webRequest's requestId, so the join is on method + URL
// (fragment stripped) + time. The two capture paths finish in either order:
//  - webRequest's onCompleted first: the entry is already in History, so
//    it's patched in place (attachResponseBody -> updateHistoryEntry);
//  - CDP's body first: it's parked here until traffic-manager.js finalizes
//    the entry and picks it up (consumeResponseBody).
import { getHistory, updateHistoryEntry } from "../storage/history.js";
import { key, stripFragment } from "./edited-tracker.js";

const parked = new Map(); // "METHOD url" -> { body, finishedAt }
// webRequest's onCompleted and CDP's loadingFinished describe the same
// moment from two processes; they land within a few hundred ms of each other.
const MATCH_WINDOW_MS = 5_000;

function purgeStale(now) {
  for (const [k, v] of parked) {
    if (now - v.finishedAt > MATCH_WINDOW_MS) parked.delete(k);
  }
}

/**
 * Pure — index of the newest History entry (oldest-first array) for
 * method+url that has a response but no body yet, and completed within
 * MATCH_WINDOW_MS of `finishedAt`; -1 if none.
 */
export function findEntryForBody(history, method, url, finishedAt) {
  const targetUrl = stripFragment(url);
  for (let i = history.length - 1; i >= 0; i--) {
    const entry = history[i];
    const completedAt = (entry.startedAt || 0) + (entry.durationMs || 0);
    if (completedAt < finishedAt - MATCH_WINDOW_MS) break; // completion-ordered — nothing earlier qualifies
    if (completedAt > finishedAt + MATCH_WINDOW_MS) continue;
    if (!entry.response || typeof entry.response.body === "string") continue;
    if (entry.request?.method !== method || stripFragment(entry.request?.url || "") !== targetUrl) continue;
    return i;
  }
  return -1;
}

let onPatchedCallback = null;
/** `cb(entry)` runs when a body is joined onto an already-saved entry (no new-entry push covers that). */
export function onBodyPatched(cb) {
  onPatchedCallback = cb;
}

/** Called with a body read from CDP once its request finished loading. */
export async function attachResponseBody(method, url, finishedAt, body) {
  const history = await getHistory();
  const idx = findEntryForBody(history, method, url, finishedAt);
  if (idx !== -1) {
    const entry = history[idx];
    const updated = await updateHistoryEntry(entry.id, { response: { ...entry.response, body } });
    if (updated) onPatchedCallback?.(updated);
    return true;
  }
  purgeStale(finishedAt);
  parked.set(key(method, url), { body, finishedAt });
  return false;
}

/** Called by traffic-manager.js when finalizing a new entry; returns a parked body for it, or null. */
export function consumeResponseBody(method, url, completedAt) {
  const k = key(method, url);
  const hit = parked.get(k);
  if (!hit) return null;
  parked.delete(k);
  return Math.abs(completedAt - hit.finishedAt) <= MATCH_WINDOW_MS ? hit.body : null;
}
