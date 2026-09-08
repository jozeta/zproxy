import { getHeaderValue } from "./headers.js";

export function parseQueryParams(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.entries()].map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

/** {host, path} for display in a table row — falls back to {host: "", path: url} for an unparseable URL rather than throwing. */
export function hostAndPath(url) {
  try {
    const u = new URL(url);
    return { host: u.host, path: u.pathname + u.search };
  } catch {
    return { host: "", path: url || "" };
  }
}

/** Marks a History entry's response as {bodyAvailable: false} before handing it to the shared inspector — chrome.webRequest (History's data source) never exposes response bytes, only the debugger-backed interceptors can, so the inspector should say that explicitly instead of silently showing an empty body. See docs/CAPABILITIES.md row 9. A no-op for an entry with no response at all. */
export function withBodyUnavailable(entry) {
  if (!entry.response) return entry;
  return { ...entry, response: { ...entry.response, bodyAvailable: false } };
}

export function requestToRawHttp(req) {
  let path = req.url;
  let host = getHeaderValue(req.headers, "host");
  try {
    const u = new URL(req.url);
    path = u.pathname + u.search;
    host = host || u.host;
  } catch {
    // Not a fully-qualified URL (unusual, but don't fail rendering over it).
  }
  const lines = [`${req.method} ${path} ${req.httpVersion || "HTTP/1.1"}`];
  const hasHost = req.headers.some((h) => h.name.toLowerCase() === "host");
  const headers = hasHost ? req.headers : [{ name: "Host", value: host || "" }, ...req.headers];
  for (const h of headers) lines.push(`${h.name}: ${h.value}`);
  lines.push("");
  if (req.body) lines.push(req.body);
  return lines.join("\r\n");
}

export function responseToRawHttp(res) {
  const lines = [`HTTP/1.1 ${res.statusCode} ${res.statusText || ""}`.trimEnd()];
  for (const h of res.headers) lines.push(`${h.name}: ${h.value}`);
  lines.push("");
  if (res.body) lines.push(res.body);
  return lines.join("\r\n");
}

function quoteShellArg(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

export function requestToCurl(req) {
  const parts = ["curl", quoteShellArg(req.url), "-X", req.method];
  for (const h of req.headers) {
    if (h.name.toLowerCase() === "content-length") continue;
    parts.push("-H", quoteShellArg(`${h.name}: ${h.value}`));
  }
  if (req.body) parts.push("--data-raw", quoteShellArg(req.body));
  return parts.join(" \\\n  ");
}

export function requestResponseToHarEntry(entry) {
  const { request, response, startedAt, durationMs } = entry;
  return {
    startedDateTime: new Date(startedAt || Date.now()).toISOString(),
    time: durationMs ?? 0,
    request: {
      method: request.method,
      url: request.url,
      httpVersion: request.httpVersion || "HTTP/1.1",
      headers: request.headers,
      queryString: parseQueryParams(request.url),
      cookies: [],
      headersSize: -1,
      bodySize: request.body ? request.body.length : 0,
      ...(request.body
        ? { postData: { mimeType: getHeaderValue(request.headers, "content-type") || "text/plain", text: request.body } }
        : {}),
    },
    response: response
      ? {
          status: response.statusCode,
          statusText: response.statusText || "",
          httpVersion: "HTTP/1.1",
          headers: response.headers,
          cookies: [],
          content: {
            size: response.body ? response.body.length : 0,
            mimeType: response.mimeType || getHeaderValue(response.headers, "content-type") || "application/octet-stream",
            text: response.body || "",
          },
          redirectURL: "",
          headersSize: -1,
          bodySize: response.body ? response.body.length : 0,
        }
      : {
          status: 0,
          statusText: "",
          httpVersion: "HTTP/1.1",
          headers: [],
          cookies: [],
          content: { size: 0, mimeType: "", text: "" },
          redirectURL: "",
          headersSize: -1,
          bodySize: -1,
        },
    cache: {},
    timings: { send: 0, wait: durationMs ?? 0, receive: 0 },
  };
}

export function buildHar(entries) {
  return {
    log: {
      version: "1.2",
      creator: { name: "ZProxy", version: "0.1.0" },
      entries: entries.map(requestResponseToHarEntry),
    },
  };
}

/** One Postman Collection v2.1 request item. `url` is left as a plain string — Postman's own schema accepts either a string or a broken-out object, and re-parses a string on import, so there's no need to hand-split it into protocol/host/path/query ourselves. */
export function requestToPostmanItem(req) {
  const item = {
    name: `${req.method} ${req.url}`,
    request: {
      method: req.method,
      header: (req.headers || []).map((h) => ({ key: h.name, value: h.value })),
      url: req.url,
    },
  };
  if (req.body) item.request.body = { mode: "raw", raw: req.body };
  return item;
}

export function buildPostmanCollection(entries, name = "ZProxy export") {
  return {
    info: { name, schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
    item: entries.map((e) => requestToPostmanItem(e.request)),
  };
}
