// Header list <-> map helpers. Canonical shape used everywhere: an array of
// { name, value } pairs (preserves order and duplicate header names, unlike a
// plain object).

export function toHeaderList(headersLike) {
  if (Array.isArray(headersLike)) {
    return headersLike.map((h) => ({ name: h.name, value: h.value ?? "" }));
  }
  if (headersLike && typeof headersLike === "object") {
    return Object.entries(headersLike).map(([name, value]) => ({ name, value: String(value) }));
  }
  return [];
}

export function toHeaderMap(headerList) {
  const map = {};
  for (const { name, value } of headerList) map[name] = value;
  return map;
}

/** Parses a "Name: value" per-line block — the free-text headers textarea format Repeater/Intruder/session-handling macros all edit — into the canonical header list. Blank lines and lines with no colon are skipped. */
export function parseHeaderLines(text) {
  return (text || "")
    .split("\n")
    .map((line) => {
      const idx = line.indexOf(":");
      if (idx === -1) return null;
      return { name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() };
    })
    .filter((h) => h && h.name);
}

export function findHeader(headerList, name) {
  const lower = name.toLowerCase();
  return headerList.find((h) => h.name.toLowerCase() === lower);
}

export function getHeaderValue(headerList, name) {
  return findHeader(headerList, name)?.value;
}

export function setHeader(headerList, name, value) {
  const lower = name.toLowerCase();
  const idx = headerList.findIndex((h) => h.name.toLowerCase() === lower);
  if (idx === -1) return [...headerList, { name, value }];
  const copy = headerList.slice();
  copy[idx] = { name, value };
  return copy;
}

export function removeHeader(headerList, name) {
  const lower = name.toLowerCase();
  return headerList.filter((h) => h.name.toLowerCase() !== lower);
}

export function dedupeHeaders(headerList) {
  const byLowerName = new Map();
  for (const header of headerList) {
    byLowerName.set(header.name.toLowerCase(), header);
  }
  return Array.from(byLowerName.values());
}

/** Order-insensitive equality — re-rendering a header table (which doesn't reorder rows on its own) must never register as a change. */
export function headersEqual(a, b) {
  const key = (list) =>
    (list || [])
      .map((h) => `${h.name.toLowerCase()}:${h.value}`)
      .sort()
      .join("\n");
  return key(a) === key(b);
}

// Headers that describe wire-level framing/connection-handling rather than
// content, which must never be forwarded on a synthesized request/response
// sent over CDP (Fetch.fulfillRequest / Fetch.continueRequest):
//  - Content-Length: Chrome's own CDP implementation actively REJECTS this
//    one if supplied explicitly — confirmed at runtime: sendCommand rejects
//    with {"code":-32602,"message":"Unsafe header: Content-Length"}. There
//    is no "correct value" to set; Chrome computes it itself from the
//    actual body bytes being sent, and won't accept an override at all —
//    so this must be stripped outright, never re-added.
//  - Content-Encoding: CDP's Fetch.getResponseBody already hands ZProxy the
//    DECODED body (gzip/br/deflate all undone by Chrome), but the header
//    naming that encoding was left untouched in the captured headers.
//    Sending the now-plaintext body back with e.g. "Content-Encoding: gzip"
//    still attached tells the receiver to gzip-decode plain text, which
//    fails silently at the network layer — no exception to catch, just a
//    request that never completes. This is why editing a response on a
//    real, compressed website (unlike an uncompressed local test server)
//    hung with no error anywhere.
//  - The rest are the standard HTTP hop-by-hop headers (RFC 7230 §6.1):
//    connection-management details for the original TCP/TLS connection
//    that make no sense to replay on a synthesized message, and that CDP
//    may equally reject given it already rejects Content-Length for the
//    same class of reason.
const UNSAFE_FRAMING_HEADERS = [
  "content-length",
  "content-encoding",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "upgrade",
];

/** Strips every header that describes wire framing rather than content — see UNSAFE_FRAMING_HEADERS above. */
export function withCorrectedFramingHeaders(headerList) {
  return UNSAFE_FRAMING_HEADERS.reduce((acc, name) => removeHeader(acc, name), headerList);
}
