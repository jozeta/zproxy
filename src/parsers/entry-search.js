// Pure text-match logic behind History's search box. Two modes: plain
// substring (default, case-insensitive) or regex (also case-insensitive —
// add (?-i) inline if a case-sensitive match is ever needed). Checked
// against everything a History entry actually carries text in: URL, method,
// status, every request/response header, and every body ZProxy actually has
// bytes for — a plain (non-edited) entry's response.body is always null
// (chrome.webRequest never exposes response bytes, see
// docs/CAPABILITIES.md row 9), but an edited entry's editDiff carries real
// captured bodies, so those are searched too.

/** A query compiled into a `{test(text)}` matcher, or null for an empty query / an invalid regex (treated as "no filter" rather than crashing the view). */
export function compileEntryQuery(query, useRegex) {
  if (!query) return null;
  if (useRegex) {
    try {
      return new RegExp(query, "i");
    } catch {
      return null;
    }
  }
  const needle = query.toLowerCase();
  return { test: (text) => text.toLowerCase().includes(needle) };
}

function headerTexts(headers) {
  return (headers || []).map((h) => `${h.name}: ${h.value}`);
}

/** Every string a History entry's search can match against, in a stable order. */
export function searchableTexts(entry) {
  const status = String(entry.response?.statusCode ?? "");
  return [
    entry.request?.url || "",
    entry.request?.method || "",
    status,
    ...headerTexts(entry.request?.headers),
    ...headerTexts(entry.response?.headers),
    entry.request?.body || "",
    entry.response?.body || "",
    entry.editDiff?.original?.body || "",
    entry.editDiff?.edited?.body || "",
    entry.comment || "",
  ];
}

export function matchesEntryQuery(entry, query, useRegex) {
  const matcher = compileEntryQuery(query, useRegex);
  if (!matcher) return true;
  return searchableTexts(entry).some((text) => text && matcher.test(text));
}
