// Shared by Repeater and Intruder: both send a request "for real" via fetch()
// from this extension page. With the <all_urls> optional host permission
// granted, extension-page fetches are exempt from CORS (a documented Chrome
// extension capability) so cross-origin responses come back readable — but
// the Fetch spec still forbids scripts from setting a handful of headers
// (Host, Origin, Cookie, Content-Length, ...) on any request, extension or
// not. Those are dropped before sending. See docs/CAPABILITIES.md.
export const FORBIDDEN_REQUEST_HEADERS = new Set([
  "host",
  "origin",
  "cookie",
  "cookie2",
  "date",
  "dnt",
  "connection",
  "content-length",
  "expect",
  "keep-alive",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "via",
  "referer",
]);

/**
 * Sends `request` ({method, url, headers, body}) via fetch() and returns
 * either {ok: true, response: {statusCode, statusText, headers, body, durationMs}}
 * or {ok: false, error} — never throws, so callers (esp. a loop sending many
 * requests in a row) don't need their own try/catch around every call.
 */
export async function sendRequest(request, { signal } = {}) {
  const startedAt = Date.now();
  try {
    const headers = new Headers();
    for (const h of request.headers) {
      if (FORBIDDEN_REQUEST_HEADERS.has(h.name.toLowerCase())) continue;
      try {
        headers.append(h.name, h.value);
      } catch {
        /* invalid header name/value — skip rather than fail the whole send */
      }
    }
    const hasBody = !["GET", "HEAD"].includes(request.method.toUpperCase()) && request.body;
    const res = await fetch(request.url, {
      method: request.method,
      headers,
      body: hasBody ? request.body : undefined,
      credentials: "include",
      signal,
    });
    const body = await res.text();
    return {
      ok: true,
      response: {
        statusCode: res.status,
        statusText: res.statusText,
        headers: [...res.headers.entries()].map(([name, value]) => ({ name, value })),
        body,
        durationMs: Date.now() - startedAt,
      },
    };
  } catch (err) {
    if (err?.name === "AbortError") return { ok: false, aborted: true, error: "Aborted" };
    return { ok: false, error: `Request failed: ${err.message} (network error, blocked by CORS/CSP, or an invalid URL)` };
  }
}
