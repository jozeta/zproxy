// Pure state helpers behind Repeater's per-tab send history (back/forward
// through previous sends) and "send group" result summary. DOM-free so
// they're unit-testable; views/repeater.js owns rendering.
export const MAX_HISTORY_PER_TAB = 50;

/**
 * Records one send on `tab` and makes it the current entry. Sending from an
 * older entry (after going back) keeps everything — the new send is
 * appended at the end, like a terminal's history, rather than discarding
 * the "forward" entries the way a browser would.
 */
export function recordSend(tab, { request, response, error }) {
  if (!tab.history) tab.history = [];
  tab.history.push({ request, response, error, sentAt: Date.now() });
  if (tab.history.length > MAX_HISTORY_PER_TAB) tab.history.shift();
  tab.historyIndex = tab.history.length - 1;
  tab.request = request;
  tab.response = response;
  tab.error = error;
}

/** Moves `delta` entries back (-1) or forward (+1); returns false at either end. */
export function stepHistory(tab, delta) {
  const next = (tab.historyIndex ?? -1) + delta;
  if (!tab.history || next < 0 || next >= tab.history.length) return false;
  const entry = tab.history[next];
  tab.historyIndex = next;
  tab.request = entry.request;
  tab.response = entry.response;
  tab.error = entry.error;
  return true;
}

/** The response sent just before the current history entry, for diffing — null if none. */
export function previousResponse(tab) {
  for (let i = (tab.historyIndex ?? -1) - 1; i >= 0; i--) {
    if (tab.history[i].response) return tab.history[i].response;
  }
  return null;
}

/**
 * Marks which results of a parallel group differ from the majority
 * (status code + body length) — in a race-condition test, the interesting
 * result is usually the one request that behaved differently. Errors always
 * count as different. Returns one boolean per result.
 */
export function groupOutliers(results) {
  const signature = (r) => (r.ok ? `${r.response.statusCode}|${r.response.body.length}` : null);
  const counts = new Map();
  for (const r of results) {
    const s = signature(r);
    if (s) counts.set(s, (counts.get(s) || 0) + 1);
  }
  let majority = null;
  let best = 0;
  for (const [s, n] of counts) {
    if (n > best) {
      best = n;
      majority = s;
    }
  }
  return results.map((r) => signature(r) !== majority);
}
