// Pure logic behind the Access Control view (Autorize/AuthMatrix-style
// testing): replay requests captured as one user with another identity's
// credentials and compare the responses, to find endpoints that don't
// enforce authorization (OWASP A01: Broken Access Control). DOM- and
// network-free so it's unit-testable; views/access-control.js does the
// sending, via the same http-send.js path Repeater uses — which is what
// lets an identity's Cookie actually replace the browser's own.
import { parseHeaderLines } from "../parsers/headers.js";
import { stripFragment } from "../background/edited-tracker.js";
import { DNR_OVERRIDABLE_HEADERS } from "../ui/components/http-send.js";

export const UNAUTHENTICATED_IDENTITY = Object.freeze({
  id: "unauthenticated",
  name: "Unauthenticated",
  // Empty values strip the header — for Cookie, http-send.js removes it via a DNR rule.
  headersText: "Cookie:\nAuthorization:",
});

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// webRequest resource types (History's entry.type) that are static assets —
// they're rarely access-controlled and would only drown out the results.
const STATIC_TYPES = new Set(["image", "stylesheet", "font", "script", "media"]);

export function isSafeMethod(method) {
  return SAFE_METHODS.has((method || "").toUpperCase());
}

/**
 * Applies an identity ({headersText: "Name: value" lines}) to `request`:
 * every header the identity names replaces all same-named headers on the
 * request. An empty value means "send without it": dropped outright for
 * ordinary headers, kept as an empty Cookie/Origin/Referer line for the
 * forbidden ones (http-send.js turns that into a DNR remove — otherwise the
 * browser would attach its own cookies). Headers the identity doesn't name
 * pass through unchanged.
 */
export function applyIdentity(request, identity) {
  const overrides = parseHeaderLines(identity.headersText || "").map((h) => ({ name: h.name.trim(), value: h.value.trim() }));
  const named = new Set(overrides.map((h) => h.name.toLowerCase()));
  const headers = request.headers.filter((h) => !named.has(h.name.toLowerCase()));
  for (const h of overrides) {
    if (h.value !== "" || DNR_OVERRIDABLE_HEADERS.has(h.name.toLowerCase())) headers.push(h);
  }
  return { ...request, headers };
}

/**
 * History entries worth an access-control check: completed, not a static
 * asset, safe methods only unless `includeUnsafe`, optionally narrowed to
 * URLs containing `urlContains`, and de-duplicated by method + URL (newest
 * capture wins) so a page polling one endpoint isn't tested 40 times.
 */
export function selectCandidates(history, { includeUnsafe = false, urlContains = "" } = {}) {
  const needle = urlContains.trim().toLowerCase();
  const byKey = new Map();
  for (const entry of history) {
    if (entry.status !== "completed" || !entry.response) continue;
    if (STATIC_TYPES.has(entry.type)) continue;
    if (!includeUnsafe && !isSafeMethod(entry.request.method)) continue;
    if (needle && !entry.request.url.toLowerCase().includes(needle)) continue;
    byKey.set(`${entry.request.method} ${stripFragment(entry.request.url)}`, entry);
  }
  return [...byKey.values()];
}

/**
 * Decides what one replay says about authorization, comparing the response
 * the ORIGINAL user got (`original`) with what another identity got for the
 * same request (`replay`). Both are {statusCode, headers, body} — or null if
 * that send failed outright (network error).
 *
 * Returns one of:
 *   "enforced"  — the identity was clearly refused
 *   "bypassed"  — the identity got what the original user got: likely a finding
 *   "different" — neither: a human needs to look (e.g. a 200 with other content)
 *   "error"     — a send failed, so nothing can be concluded
 *
 * TODO(you): implement — see the request in the chat for the trade-offs.
 */
export function judgeReplay(original, replay) {
  return null;
}
