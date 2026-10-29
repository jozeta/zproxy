// Shared by the views that re-derive state from the full History list on
// every history:new-entry push (History, Dashboard, Findings). A page load
// can complete dozens of requests in a burst, and each push used to trigger
// a full history:get round-trip plus a passive-check scan of every entry.
import { checkResponse } from "../../parsers/passive-checks.js";

// Keyed by id+startedAt rather than the entry object: history:get returns
// fresh copies every time, so object identity never survives a refresh.
// A captured request/response only ever changes in one way after capture —
// its response body arriving late from CDP (background/body-tracker.js) —
// so the body's length is part of the key; tag/comment edits don't matter.
const findingsCache = new Map();
const MAX_CACHED = 5000;

/** checkResponse(entry.request, entry.response), memoized per History entry. */
export function findingsFor(entry) {
  const key = `${entry.id}|${entry.startedAt}|${entry.response?.body?.length ?? -1}`;
  let findings = findingsCache.get(key);
  if (!findings) {
    if (findingsCache.size >= MAX_CACHED) findingsCache.clear();
    findings = checkResponse(entry.request, entry.response);
    findingsCache.set(key, findings);
  }
  return findings;
}

/**
 * Wraps `fn` so a burst of calls runs it once, `delayMs` after the first —
 * every call within the window is covered by that one trailing run.
 * `.cancel()` drops a pending run (call it on view teardown).
 */
export function coalesced(fn, delayMs = 250) {
  let timer = null;
  const wrapped = () => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      fn();
    }, delayMs);
  };
  wrapped.cancel = () => {
    clearTimeout(timer);
    timer = null;
  };
  return wrapped;
}
