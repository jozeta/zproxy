// Pure post-processing over an Intruder run's results — no network calls,
// no state, just numbers already collected. Two things Burp users do by
// hand today in ZProxy: sort the results table to find the outlier, and
// eyeball which response looks different from the rest. This gives both a
// real implementation instead of leaving them manual.

/** The most common value in `values` (first-seen wins on a count tie), or null for an empty array. */
function mode(values) {
  if (values.length === 0) return null;
  const counts = new Map();
  for (const v of values) counts.set(v, (counts.get(v) || 0) + 1);
  let best = values[0];
  let bestCount = 0;
  for (const [v, c] of counts) {
    if (c > bestCount) {
      best = v;
      bestCount = c;
    }
  }
  return best;
}

/**
 * Returns a Set of result `index` values whose status code or response
 * length differs from the majority (mode) among rows that actually got a
 * response — the classic "which one is different" signal for spotting a
 * successful attack in a big result set (e.g. every response is 200/1487
 * bytes except one 200/612-byte outlier). Rows with no response (network
 * error, aborted, macro failure) are never themselves flagged — they're
 * already visibly distinct via the Error column — and don't count toward
 * computing the majority either. Returns an empty Set for fewer than 2
 * successful results: no meaningful "majority" to compare against yet.
 */
export function findAnomalies(results) {
  const withResponse = (results || []).filter((r) => r.response);
  if (withResponse.length < 2) return new Set();
  const modalStatus = mode(withResponse.map((r) => r.status));
  const modalLength = mode(withResponse.map((r) => r.length));
  const anomalies = new Set();
  for (const r of withResponse) {
    if (r.status !== modalStatus || r.length !== modalLength) anomalies.add(r.index);
  }
  return anomalies;
}

const NULLS_LAST = (dir) => (a, b) => {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  if (a < b) return dir === "asc" ? -1 : 1;
  if (a > b) return dir === "asc" ? 1 : -1;
  return 0;
};

const SORT_VALUE = {
  index: (r) => r.index,
  status: (r) => r.status,
  length: (r) => r.length,
  timeMs: (r) => r.timeMs,
};

/** Sortable columns for the Intruder results table — only the numeric ones (payload/grep/search columns are per-query computed values, not stable sort keys). */
export const SORTABLE_RESULT_KEYS = Object.keys(SORT_VALUE);

/** Sorted copy of `results` by `sortKey` (one of SORTABLE_RESULT_KEYS)/`sortDir` ("asc"|"desc"). Missing values (null, e.g. an errored request's status) always sort last regardless of direction. Falls back to natural `index` order for an unrecognized key. */
export function sortResults(results, sortKey, sortDir = "asc") {
  const valueOf = SORT_VALUE[sortKey] || SORT_VALUE.index;
  const cmp = NULLS_LAST(sortDir);
  return [...(results || [])].sort((a, b) => cmp(valueOf(a), valueOf(b)));
}
