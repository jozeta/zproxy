// Pure, DOM-free "Search - Extract" logic for Intruder attack results.
// Compiles a user-entered search query (literal text plus `*`/`?` wildcards,
// Burp Suite Extractor-style) into a regex, then extracts matched text/data
// from a response's body and headers. A run of wildcard characters becomes
// one capturing group; literal text outside wildcards is escaped and used
// as an anchor a match must contain verbatim. A query with no wildcards is
// a plain substring search whose "extracted" value is the substring itself.
//
// Note on cookies: a Set-Cookie response header is a forbidden header the
// Fetch API never exposes to page JS (see FORBIDDEN_REQUEST_HEADERS in
// http-send.js for the request-side equivalent restriction) — this is a
// browser security limitation ZProxy can't work around from an extension
// page. Searching `headersAsText` still covers every header the fetch layer
// *can* see, cookie-named or not.

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Compiles a wildcard search query into a global RegExp plus metadata.
 * A run of consecutive identical wildcard characters collapses into a
 * single capturing group: `*` matches any run of characters (incl. zero),
 * non-greedy; `?` matches exactly that many characters. Literal runs are
 * regex-escaped. Returns null for an empty/whitespace query or a pattern
 * that fails to compile.
 */
export function compileSearchQuery(query) {
  const q = query || "";
  if (!q.trim()) return null;
  let source = "";
  let groupCount = 0;
  let i = 0;
  while (i < q.length) {
    const ch = q[i];
    if (ch === "*" || ch === "?") {
      let j = i;
      while (j < q.length && q[j] === ch) j++;
      source += ch === "*" ? "([\\s\\S]*?)" : `([\\s\\S]{${j - i}})`;
      groupCount++;
      i = j;
    } else {
      let j = i;
      while (j < q.length && q[j] !== "*" && q[j] !== "?") j++;
      source += escapeRegExp(q.slice(i, j));
      i = j;
    }
  }
  let regex;
  try {
    regex = new RegExp(source, "g");
  } catch {
    return null;
  }
  return { query: q, regex, groupCount, hasWildcard: groupCount > 0 };
}

/**
 * Every match of `compiled` in `text`, in order: the wildcard-captured
 * groups joined with " | " (a query with more than one wildcard run
 * extracts more than one span per match), or the whole matched substring
 * for a plain literal query with no wildcards.
 */
export function extractMatches(text, compiled) {
  if (!compiled || !text) return [];
  const { regex, groupCount } = compiled;
  regex.lastIndex = 0;
  const out = [];
  let match;
  while ((match = regex.exec(text))) {
    out.push(groupCount > 0 ? match.slice(1).join(" | ") : match[0]);
    // A pattern that can match the empty string (e.g. bare "*") would
    // otherwise pin lastIndex and loop forever.
    if (match[0].length === 0) regex.lastIndex++;
  }
  return out;
}

/** {name, value} header list rendered as one "Name: value" line per header — what a search scans headers/cookies through, so an anchor either side of a header's value (e.g. around a Set-Cookie pair) still extracts just that value. */
export function headersAsText(headers) {
  return (headers || []).map((h) => `${h.name}: ${h.value}`).join("\n");
}

/**
 * Runs `compiled` over a response's body then headers (in that order), and
 * returns every extracted value ("all" mode) or just the first one found
 * ("first" mode, the default — stops scanning as soon as one turns up).
 * Returns [] for a missing response/compiled query.
 */
export function searchResponse(response, compiled, mode = "first") {
  if (!compiled || !response) return [];
  const sources = [response.body || "", headersAsText(response.headers)];
  const all = [];
  for (const text of sources) {
    const matches = extractMatches(text, compiled);
    if (!matches.length) continue;
    if (mode === "first") return [matches[0]];
    all.push(...matches);
  }
  return all;
}
