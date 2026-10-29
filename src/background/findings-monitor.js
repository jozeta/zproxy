// Keeps Findings running in the background whenever a Scope is defined:
// re-summarizes the passive checks over History after every change and
// shows the count of high/medium kinds of finding as a badge on ZProxy's
// toolbar icon — visible even with the side panel closed. The side panel's
// Findings nav badge reads the same summary (findings:summary / the
// findings:summary-changed push), so the two always agree.
import { checkResponse, SEVERITY_ORDER } from "../parsers/passive-checks.js";

/** True when Scope has at least one Include pattern — "a scope is defined". */
export function scopeIsDefined(scope) {
  return (scope?.include || []).some((p) => (p || "").trim());
}

/**
 * Pure — counts distinct kinds of finding (grouped by finding id, each at
 * its worst severity seen — the same grouping as the Findings view) per
 * severity. `findingsFor(entry)` returns that entry's findings.
 */
export function summarizeFindings(entries, findingsFor) {
  const worst = new Map(); // finding id -> severity index
  for (const entry of entries) {
    for (const f of findingsFor(entry)) {
      const rank = SEVERITY_ORDER.indexOf(f.severity);
      if (rank > (worst.get(f.id) ?? -1)) worst.set(f.id, rank);
    }
  }
  const summary = { high: 0, medium: 0, low: 0, info: 0 };
  for (const rank of worst.values()) summary[SEVERITY_ORDER[rank]]++;
  return summary;
}

/** Pure — the toolbar badge for a summary: {text, color, title}. */
export function badgeFor(summary, active) {
  const urgent = active ? summary.high + summary.medium : 0;
  return {
    text: urgent > 0 ? String(urgent > 99 ? "99+" : urgent) : "",
    color: summary.high > 0 ? "#bf616a" : "#d08770",
    title: active
      ? `ZProxy — ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.info} info kinds of passive finding`
      : "ZProxy — Inspect. Intercept. Modify.",
  };
}

// Per-entry results, keyed like the UI's history-feed.js cache (a captured
// exchange only changes when its response body arrives late).
const cache = new Map();
const MAX_CACHED = 5000;

function cachedFindings(entry) {
  const key = `${entry.id}|${entry.startedAt}|${entry.response?.body?.length ?? -1}`;
  let findings = cache.get(key);
  if (!findings) {
    if (cache.size >= MAX_CACHED) cache.clear();
    findings = checkResponse(entry.request, entry.response);
    cache.set(key, findings);
  }
  return findings;
}

let current = { high: 0, medium: 0, low: 0, info: 0, active: false };
let timer = null;

/**
 * Wires the monitor up. `deps`: getHistory(), getScope(), onChange(summary)
 * (the service worker broadcasts it to open panels).
 */
export function createFindingsMonitor({ getHistory, getScope, onChange }) {
  async function recompute() {
    timer = null;
    const [history, scope] = await Promise.all([getHistory(), getScope()]);
    const active = scopeIsDefined(scope);
    const summary = { ...(active ? summarizeFindings(history, cachedFindings) : { high: 0, medium: 0, low: 0, info: 0 }), active };
    const changed = JSON.stringify(summary) !== JSON.stringify(current);
    current = summary;
    if (typeof chrome !== "undefined" && chrome.action) {
      const badge = badgeFor(summary, active);
      await chrome.action.setBadgeText({ text: badge.text });
      await chrome.action.setBadgeBackgroundColor({ color: badge.color });
      await chrome.action.setTitle({ title: badge.title });
    }
    if (changed) onChange?.(summary);
  }

  return {
    /** Recompute soon — bursts of new History entries collapse into one pass. */
    schedule(delayMs = 1000) {
      if (timer) return;
      timer = setTimeout(() => recompute().catch((err) => console.warn("[ZProxy] findings summary failed:", err.message)), delayMs);
    },
    summary: () => current,
  };
}
