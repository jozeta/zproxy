// Used everywhere ZProxy logs a request/response to the console, so captured
// secrets never end up in chrome://extensions service worker logs.
const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "x-api-key",
]);

export function redactHeadersForLog(headerList) {
  if (!Array.isArray(headerList)) return headerList;
  return headerList.map((h) =>
    SENSITIVE_HEADER_NAMES.has(h.name.toLowerCase()) ? { name: h.name, value: "[redacted]" } : h
  );
}

export function redactEntryForLog(entry) {
  return {
    ...entry,
    request: entry.request && { ...entry.request, headers: redactHeadersForLog(entry.request.headers) },
    response: entry.response && { ...entry.response, headers: redactHeadersForLog(entry.response.headers) },
  };
}
