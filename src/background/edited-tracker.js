// Correlates an Intercept edit with the passive History entry
// traffic-manager.js builds for the same request. History (via
// chrome.webRequest) and Intercept (via CDP Fetch) are two independent
// capture paths with no shared request ID guaranteed by either API — CDP's
// Fetch.requestPaused.networkId correlates with CDP's own Network domain
// requestId, not chrome.webRequest's requestId (confirmed against the
// official Fetch.requestPaused docs) — so correlation is done the same way
// request-interceptor.js's "don't intercept again" already does: method+URL
// matching.
//
// CRITICAL, confirmed via a live console trace: callers must always pass
// the ORIGINAL (pre-edit) method/URL here, never the edited one, even when
// the edit changes the URL itself. chrome.webRequest's onBeforeRequest
// captures a request's URL/method before CDP's Fetch domain ever gets a
// chance to intercept it, and nothing later in that request's webRequest
// lifecycle (onSendHeaders, onCompleted, ...) updates it — a
// Fetch.continueRequest URL/method override is an in-flight substitution
// invisible to webRequest's own bookkeeping (unlike a real HTTP redirect,
// which DOES get a fresh onBeforeRequest-equivalent via onBeforeRedirect).
// So the History row for an edited request will always show its ORIGINAL
// method/URL, however the bytes actually sent were changed — meaning that's
// also the only key any caller here can ever correlate against.
//
// This can't just register a marker for a FUTURE History entry to consume:
// for a RESPONSE edit specifically, the underlying network transaction (and
// so its History entry, via webRequest's onCompleted) has almost certainly
// already completed and saved — unmarked — by the time a human has read the
// paused response, edited it, and clicked Forward. CDP's Fetch only pauses
// delivery to the renderer; it doesn't hold up chrome.webRequest's view of
// the already-finished network fetch. So markEdited() also tries to
// retroactively patch an existing entry.
//
// The real timeline for any edit looks like:
//   pausedAt ---[human reads/edits — UNBOUNDED]---> markEdited() called ---[network latency — bounded]---> entry completes
//
// Two anchors, two different jobs:
//  - `pausedAt`: only used as a LOWER bound, to reject an entry that
//    finished BEFORE the pause happened — e.g. an unrelated earlier request
//    to the same URL (a normal page load hitting the same endpoint before
//    Intercept was ever attached). There is no upper bound tied to
//    `pausedAt`: human edit time is unbounded, so any cutoff measured from
//    the pause moment eventually rejects a real match once editing takes
//    more than a few seconds — this was the actual bug here.
//  - `markedAt` (when markEdited() itself runs, i.e. AFTER the unbounded
//    human delay has already elapsed): the anchor for the one remaining
//    bounded interval — ordinary network completion/failure latency — used
//    to expire a marker whose request never actually completed.
import { getHistory, updateHistoryEntry } from "../storage/history.js";

const pendingMarks = new Map(); // "METHOD url" -> { pausedAt, markedAt }
const PAUSE_JITTER_MS = 2_000; // CDP Fetch-pause vs. webRequest.onCompleted can fire a moment apart for the same real transaction
const NETWORK_COMPLETION_MAX_MS = 30_000; // how long a just-forwarded request may reasonably take to complete/fail

// Confirmed via a live console trace: CDP's Fetch.requestPaused reports a
// request's URL exactly as it goes over the wire — fragments are never
// transmitted to a server, so CDP correctly omits them — while
// chrome.webRequest's details.url reports the full browser-side URL,
// fragment included, even though the fragment never affects the actual HTTP
// request. Same transaction, two different string representations
// ("…/xss_r/?name=h" vs. "…/xss_r/?name=h#"). Stripped before ever using a
// URL as a correlation key so this class of mismatch can't recur.
export function stripFragment(url) {
  const i = url.indexOf("#");
  return i === -1 ? url : url.slice(0, i);
}

export function key(method, url) {
  return `${method} ${stripFragment(url)}`;
}

/**
 * Pure — given a chronological-by-completion (oldest-first) history array,
 * finds the index of the most recent not-yet-marked entry matching
 * method+url that finished at or after `pausedAt` (within a small jitter
 * allowance). No upper bound: anything that already exists in history
 * finished at or before "now" by definition, however long the edit took.
 * Extracted from markEdited() so it's testable without a chrome.storage
 * dependency.
 */
export function findEntryToPatch(history, method, url, pausedAt) {
  const targetUrl = stripFragment(url);
  const minCompletedAt = pausedAt - PAUSE_JITTER_MS;
  for (let i = history.length - 1; i >= 0; i--) {
    const entry = history[i];
    const completedAt = (entry.startedAt || 0) + (entry.durationMs || 0);
    if (completedAt < minCompletedAt) break; // completion-ordered array — nothing earlier will qualify either
    if (entry.edited) continue;
    if (entry.request?.method !== method || stripFragment(entry.request?.url || "") !== targetUrl) continue;
    return i;
  }
  return -1;
}

/**
 * Call when Intercept forwards a genuinely edited request/response.
 * `pausedAt` is the original pending item's own pausedAt (when CDP paused
 * this exact transaction) — see the module comment for why that's the right
 * anchor and why there's no equivalent upper-bound parameter.
 *
 * `diff` is `{ kind: "request" | "response", original, edited }` — both
 * snapshots captured directly from the interceptor at edit time, NOT read
 * back from the eventual History entry. That distinction matters: History's
 * own request/response fields come from chrome.webRequest, which (per the
 * module comment above) never reflects a CDP-level edit for the request
 * side, and never carries a response BODY at all, edited or not (documented
 * webRequest limitation — see docs/CAPABILITIES.md row 9). So History's own
 * fields can't be trusted to show "what was actually sent"; `diff.edited` is
 * the only reliable record of it, which is why it's captured and stored
 * explicitly here instead of just flagging `edited: true` and pointing back
 * at the entry's own data.
 */
export async function markEdited(method, url, pausedAt, diff) {
  const history = await getHistory();
  const idx = findEntryToPatch(history, method, url, pausedAt);
  if (idx !== -1) {
    await updateHistoryEntry(history[idx].id, { edited: true, editDiff: diff });
    return;
  }
  // Not saved yet (the request-edit case: the network transaction hasn't
  // happened yet) — leave a marker for traffic-manager.js to pick up once
  // it does complete. markedAt (not pausedAt) anchors how long that marker
  // stays valid, since only network latency remains unbounded-human-delay-free
  // from this point on.
  pendingMarks.set(key(method, url), { pausedAt, markedAt: Date.now(), diff });
}

/**
 * Call once, when finalizing a NEW History entry, with that entry's own
 * method+URL and its completion time (startedAt + durationMs). Returns the
 * `diff` object passed to the matching markEdited() call (store it as
 * entry.editDiff) if this corresponds to a recent edit that hadn't been
 * retroactively patched yet, otherwise null.
 */
export function consumeEdited(method, url, completedAt = Date.now()) {
  const k = key(method, url);
  const mark = pendingMarks.get(k);
  if (mark === undefined) return null;
  pendingMarks.delete(k);
  if (completedAt < mark.pausedAt - PAUSE_JITTER_MS) return null; // shouldn't happen, but reject defensively
  return completedAt - mark.markedAt <= NETWORK_COMPLETION_MAX_MS ? mark.diff : null;
}
