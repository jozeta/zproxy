// Pure, DOM-free logic for Intruder "attack positions" — Burp's §payload§
// marker convention, applied across three independently-edited text fields
// (URL, a "Name: value" headers block, and the body) rather than one single
// raw-HTTP text blob. Canonical position order used everywhere (the numbers
// shown in the UI, and the index into a payload-set/tuple array) is always:
// every marker in the URL, in appearance order; then every marker in the
// headers block, in appearance order; then every marker in the body, in
// appearance order.
export const MARKER = "§";
const MARKER_RE = /§([^§]*)§/g;

const FIELD_ORDER = ["url", "headersText", "body"];

/** Every §...§ occurrence across the three fields, in canonical order. `originalValue` is the text that was between the markers — substituted back in for any position a given attack request doesn't target (e.g. Sniper's non-active positions). */
export function findPositions(fields) {
  const positions = [];
  for (const field of FIELD_ORDER) {
    const text = fields[field] || "";
    for (const match of text.matchAll(MARKER_RE)) {
      positions.push({ field, originalValue: match[1] });
    }
  }
  return positions;
}

export function countPositions(fields) {
  return findPositions(fields).length;
}

export function clearMarkers(text) {
  return (text || "").split(MARKER).join("");
}

export function clearAllMarkers(fields) {
  return { url: clearMarkers(fields.url), headersText: clearMarkers(fields.headersText), body: clearMarkers(fields.body) };
}

/** Replaces every §...§ in `fieldText`, in order, with the corresponding entry of `values` (one per marker occurrence). */
function replaceMarkersInField(fieldText, values) {
  let i = 0;
  return (fieldText || "").replace(MARKER_RE, () => values[i++]);
}

/**
 * Builds the concrete request fields for one attack request. `tuple` is an
 * array the same length as findPositions(fields), one entry per position in
 * canonical order — a string payload to substitute, or null/undefined to
 * fall back to that position's original (pre-marker) value.
 */
export function applyPayloads(fields, tuple) {
  const positions = findPositions(fields);
  const substitutions = positions.map((p, idx) => (tuple[idx] ?? p.originalValue));
  let cursor = 0;
  const result = {};
  for (const field of FIELD_ORDER) {
    const countInField = positions.filter((p) => p.field === field).length;
    result[field] = replaceMarkersInField(fields[field], substitutions.slice(cursor, cursor + countInField));
    cursor += countInField;
  }
  return result;
}

/** One flat list of {field, start, end, text, isMarker} segments per field, in field order — used to render a highlighted, numbered read-only preview without ever using innerHTML. `index` (1-based) is only set on marker segments. */
export function buildPreviewSegments(fields) {
  const segments = [];
  let positionNumber = 0;
  for (const field of FIELD_ORDER) {
    const text = fields[field] || "";
    let lastEnd = 0;
    for (const match of text.matchAll(MARKER_RE)) {
      const start = match.index;
      const end = start + match[0].length;
      if (start > lastEnd) segments.push({ field, text: text.slice(lastEnd, start), isMarker: false });
      positionNumber += 1;
      segments.push({ field, text: match[1], isMarker: true, index: positionNumber });
      lastEnd = end;
    }
    if (lastEnd < text.length) segments.push({ field, text: text.slice(lastEnd), isMarker: false });
    segments.push({ field, text: "\n", isMarker: false, isFieldBreak: true });
  }
  return segments;
}

const DEFAULT_SKIP_HEADERS = new Set([
  "host",
  "content-length",
  "connection",
  "accept-encoding",
  "origin",
  "referer",
  "transfer-encoding",
  "upgrade",
  "keep-alive",
  "te",
]);

/** Wraps every "key=value" value in a query-string-shaped chunk of text (URL query string, or a form-urlencoded body) in §...§. Never touches keys, "?"/"&" separators, or the rest of the string. */
function markQueryLikeValues(text) {
  return text.replace(/([^&=?#]+)=([^&#]*)/g, (whole, key, value) => `${key}=${MARKER}${value}${MARKER}`);
}

/** Auto-detects likely payload positions in a URL: every query-parameter value. Leaves the path and an unmarked URL (no "?") untouched. */
export function autoMarkUrl(url) {
  const text = url || "";
  const qIdx = text.indexOf("?");
  if (qIdx === -1) return text;
  return text.slice(0, qIdx + 1) + markQueryLikeValues(text.slice(qIdx + 1));
}

/** Auto-detects likely payload positions in a "Name: value" headers block: the full value of every header not in a fixed skip-list (hop-by-hop headers, and ones a script can never actually set — see http-send.js). */
export function autoMarkHeaders(headersText, skip = DEFAULT_SKIP_HEADERS) {
  const lines = (headersText || "").split("\n");
  return lines
    .map((line) => {
      const idx = line.indexOf(":");
      if (idx === -1) return line;
      const name = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      if (!name || !value || skip.has(name.toLowerCase())) return line;
      return `${name}: ${MARKER}${value}${MARKER}`;
    })
    .join("\n");
}

/** Auto-detects likely payload positions in a request body: form-urlencoded parameter values, or JSON string values. Anything else (plain text, XML, multipart, ...) is left untouched — mark those manually. */
export function autoMarkBody(body, contentType = "") {
  const text = body || "";
  if (!text.trim()) return text;
  const ct = contentType.toLowerCase();
  const looksJson = ct.includes("json") || /^\s*[[{]/.test(text);
  if (looksJson) {
    // Only string values (":  "quoted text"") — numeric/boolean JSON values
    // are left for manual marking, since re-scanning already-substituted
    // text for a second numeric pass risks marking inside a marker.
    return text.replace(/:(\s*)"((?:[^"\\]|\\.)*)"/g, (whole, space, value) => `:${space}"${MARKER}${value}${MARKER}"`);
  }
  const looksFormEncoded = /^[^\s=&]+=[^&\s]*(&[^\s=&]+=[^&\s]*)*$/.test(text.trim());
  if (looksFormEncoded) return markQueryLikeValues(text);
  return text;
}
