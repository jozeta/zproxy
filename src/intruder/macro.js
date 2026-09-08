// Session-handling macro: pure logic for "send this request first, extract
// a value from its response, substitute that value into the real request
// wherever {{macro}} appears." Solves the common case Repeater/Intruder
// otherwise can't handle at all: a server that rotates a CSRF/session token
// on every response, which makes a single captured request go stale after
// the very first resend (Repeater) or after request #1 of an attack
// (Intruder). Extraction reuses the exact same wildcard-anchor search
// engine as Intruder's Search - Extract column (src/intruder/search.js) —
// same query syntax, same semantics, one thing to learn.
import { compileSearchQuery, searchResponse } from "./search.js";

export const MACRO_TOKEN = "{{macro}}";

export function containsMacroToken(text) {
  return (text || "").includes(MACRO_TOKEN);
}

/** True if the token appears in any of a request's editable text fields — used to decide whether running the macro is even necessary before a given send. */
export function usesMacroToken(fields) {
  return containsMacroToken(fields.url) || containsMacroToken(fields.headersText) || containsMacroToken(fields.body);
}

/** Replaces every {{macro}} occurrence in url/headersText/body with `value` (missing/null value substitutes as ""). Same {url, headersText, body} shape Intruder's applyPayloads() returns, so callers can treat the two the same way. */
export function applyMacroValue(fields, value) {
  const sub = (text) => (text || "").split(MACRO_TOKEN).join(value ?? "");
  return { url: sub(fields.url), headersText: sub(fields.headersText), body: sub(fields.body) };
}

/** Extracts the macro's value from its response via a Search - Extract-style wildcard query, always taking the first match (a macro needs exactly one token, not a list). Returns null if the query is empty/invalid or nothing matched — callers should treat that as "macro failed" rather than substituting the literal string "null". */
export function extractMacroValue(response, query) {
  const compiled = compileSearchQuery(query);
  if (!compiled) return null;
  const matches = searchResponse(response, compiled, "first");
  return matches.length ? matches[0] : null;
}

export function defaultMacro() {
  return { enabled: false, method: "GET", url: "", headersText: "", body: "", extractQuery: "" };
}
