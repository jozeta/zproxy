// Pure encode/decode transforms behind the Decoder view — Burp/ZAP-style
// scratch encoding utility. Every decode returns {ok, value|error} instead
// of throwing, since the whole point of this tool is pasting in arbitrary,
// possibly-malformed text and seeing what happens rather than crashing the
// view.
import { textToBase64, base64ToText } from "../utils/bytes.js";

export function encodeBase64(text) {
  return textToBase64(text || "");
}

export function decodeBase64(text) {
  try {
    return { ok: true, value: base64ToText(text || "") };
  } catch {
    return { ok: false, error: "Invalid base64 input." };
  }
}

export function encodeUrl(text) {
  return encodeURIComponent(text || "");
}

export function decodeUrl(text) {
  try {
    return { ok: true, value: decodeURIComponent(text || "") };
  } catch {
    return { ok: false, error: "Invalid percent-encoding." };
  }
}

const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

export function encodeHtmlEntities(text) {
  return (text || "").replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

// A deliberately small table (the entities ZProxy's own captured-response
// bodies actually turn up) rather than the full HTML5 named-entity list —
// and never routed through the DOM (e.g. a detached element's innerHTML)
// to decode, since that's exactly the kind of sink docs/SECURITY.md bans
// for anything that touched captured traffic.
const NAMED_ENTITIES = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  copy: "©",
  reg: "®",
  trade: "™",
  hellip: "…",
  mdash: "—",
  ndash: "–",
  ldquo: "“",
  rdquo: "”",
  lsquo: "‘",
  rsquo: "’",
};

export function decodeHtmlEntities(text) {
  const value = (text || "").replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body) => {
    if (body[0] === "#") {
      const codePoint = body[1] === "x" || body[1] === "X" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      if (!Number.isFinite(codePoint)) return whole;
      try {
        return String.fromCodePoint(codePoint);
      } catch {
        return whole;
      }
    }
    return NAMED_ENTITIES[body] ?? whole;
  });
  return { ok: true, value };
}

export function encodeHex(text) {
  const bytes = new TextEncoder().encode(text || "");
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function decodeHex(text) {
  const clean = (text || "").replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    return { ok: false, error: "Invalid hex input (must be an even number of hex digits)." };
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return { ok: true, value: new TextDecoder("utf-8", { fatal: false }).decode(bytes) };
}

/** Percent-encodes every byte, not just reserved characters — bypasses filters that only look for a literal "<" or "'". */
export function encodeUrlAll(text) {
  return [...new TextEncoder().encode(text || "")].map((b) => `%${b.toString(16).toUpperCase().padStart(2, "0")}`).join("");
}

export function encodeBase64Url(text) {
  return encodeBase64(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64Url(text) {
  const b64 = (text || "").trim().replace(/-/g, "+").replace(/_/g, "/");
  return decodeBase64(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

/** \uXXXX for every non-printable-ASCII character (surrogate pairs as two escapes, as JS/JSON expect). */
export function encodeUnicodeEscape(text) {
  return (text || "").replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/** Decodes \uXXXX, \u{X…}, and \xXX escapes; anything else is left as-is. */
export function decodeUnicodeEscape(text) {
  try {
    const value = (text || "").replace(/\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g, (_, cp, u, x) =>
      cp ? String.fromCodePoint(parseInt(cp, 16)) : String.fromCharCode(parseInt(u || x, 16))
    );
    return { ok: true, value };
  } catch {
    return { ok: false, error: "Invalid \\u{…} code point." };
  }
}

export function encodeBinary(text) {
  return [...new TextEncoder().encode(text || "")].map((b) => b.toString(2).padStart(8, "0")).join(" ");
}

export function decodeBinary(text) {
  const groups = (text || "").trim().split(/\s+/).filter(Boolean);
  if (!groups.every((g) => /^[01]{1,8}$/.test(g))) return { ok: false, error: "Expected space-separated groups of up to 8 bits." };
  return { ok: true, value: new TextDecoder("utf-8", { fatal: false }).decode(Uint8Array.from(groups, (g) => parseInt(g, 2))) };
}

/** Comma-separated Unicode code points, e.g. for String.fromCharCode() / CHAR() payloads. */
export function encodeCharCodes(text) {
  return [...(text || "")].map((c) => c.codePointAt(0)).join(",");
}

export function decodeCharCodes(text) {
  const parts = (text || "").split(/[\s,]+/).filter(Boolean);
  if (!parts.every((p) => /^\d+$/.test(p))) return { ok: false, error: "Expected comma- or space-separated decimal numbers." };
  try {
    return { ok: true, value: String.fromCodePoint(...parts.map(Number)) };
  } catch {
    return { ok: false, error: "A number is outside the Unicode range." };
  }
}

/** ROT13 — its own inverse. */
export function rot13(text) {
  return (text || "").replace(/[a-zA-Z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

async function pipeThrough(bytes, stream) {
  const out = new Response(new Blob([bytes]).stream().pipeThrough(stream));
  return new Uint8Array(await out.arrayBuffer());
}

/** Gzip-compresses text and returns it as base64 (CompressionStream). */
export async function encodeGzip(text) {
  const bytes = await pipeThrough(new TextEncoder().encode(text || ""), new CompressionStream("gzip"));
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Base64 of gzip (or zlib/raw deflate) data → the decompressed text. Tries each format in turn. */
export async function decodeGzip(text) {
  let bytes;
  try {
    bytes = Uint8Array.from(atob((text || "").trim()), (c) => c.charCodeAt(0));
  } catch {
    return { ok: false, error: "Expected base64-encoded compressed data." };
  }
  for (const format of ["gzip", "deflate", "deflate-raw"]) {
    try {
      const out = await pipeThrough(bytes, new DecompressionStream(format));
      return { ok: true, value: new TextDecoder("utf-8", { fatal: false }).decode(out) };
    } catch {
      /* not this format — try the next */
    }
  }
  return { ok: false, error: "Not valid gzip, zlib, or raw deflate data." };
}

/** One entry per Decoder view mode. `decode` is only present for a mode that has a real inverse. Either side may be async. */
export const DECODER_MODES = [
  { id: "base64", label: "Base64", encode: encodeBase64, decode: decodeBase64 },
  { id: "base64url", label: "Base64url", encode: encodeBase64Url, decode: decodeBase64Url },
  { id: "url", label: "URL", encode: encodeUrl, decode: decodeUrl },
  { id: "urlAll", label: "URL (all chars)", encode: encodeUrlAll, decode: decodeUrl },
  { id: "html", label: "HTML entities", encode: encodeHtmlEntities, decode: decodeHtmlEntities },
  { id: "unicode", label: "Unicode escape", encode: encodeUnicodeEscape, decode: decodeUnicodeEscape },
  { id: "hex", label: "Hex", encode: encodeHex, decode: decodeHex },
  { id: "binary", label: "Binary", encode: encodeBinary, decode: decodeBinary },
  { id: "charCodes", label: "Char codes", encode: encodeCharCodes, decode: decodeCharCodes },
  { id: "rot13", label: "ROT13", encode: rot13, decode: (t) => ({ ok: true, value: rot13(t) }) },
  { id: "gzip", label: "Gzip (base64)", encode: encodeGzip, decode: decodeGzip },
];

/**
 * "Smart decode": repeatedly applies whichever single decoding clearly
 * applies (URL, Base64/Base64url, hex, HTML entities, Unicode escapes)
 * until none does or `maxSteps` is reached — for unwrapping layered
 * encodings like a URL-encoded Base64 cookie. Returns the steps taken.
 */
export function smartDecode(text, maxSteps = 6) {
  const steps = [];
  let current = (text || "").trim();
  const printable = (s) => s.length > 0 && !/[\u0000-\u0008\u000e-\u001f�]/.test(s);
  const candidates = [
    ["URL", (s) => /%[0-9a-fA-F]{2}/.test(s) && decodeUrl(s)],
    ["HTML entities", (s) => /&(#x?[0-9a-fA-F]+|[a-z]+);/i.test(s) && decodeHtmlEntities(s)],
    ["Unicode escape", (s) => /\\(u[0-9a-fA-F]{4}|u\{|x[0-9a-fA-F]{2})/.test(s) && decodeUnicodeEscape(s)],
    ["Hex", (s) => /^([0-9a-fA-F]{2}){2,}$/.test(s) && decodeHex(s)],
    ["Base64", (s) => s.length >= 8 && /^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0 && decodeBase64(s)],
    ["Base64url", (s) => s.length >= 8 && /^[A-Za-z0-9_-]+$/.test(s) && /[-_]/.test(s) && decodeBase64Url(s)],
  ];
  for (let i = 0; i < maxSteps; i++) {
    let applied = false;
    for (const [label, attempt] of candidates) {
      const result = attempt(current);
      if (result?.ok && result.value !== current && printable(result.value)) {
        steps.push({ label, value: result.value });
        current = result.value;
        applied = true;
        break;
      }
    }
    if (!applied) break;
  }
  return steps;
}

/**
 * If `text` is a Unix timestamp (10-digit seconds or 13-digit milliseconds)
 * or a date string Date.parse() understands, returns both representations;
 * otherwise null. Powers the Decoder's "Inspect" panel.
 */
export function describeTimestamp(text) {
  const t = (text || "").trim();
  let ms = null;
  if (/^\d{10}$/.test(t)) ms = Number(t) * 1000;
  else if (/^\d{13}$/.test(t)) ms = Number(t);
  else if (/\d{4}-\d{2}-\d{2}|[A-Za-z]{3},? \d{1,2} [A-Za-z]{3} \d{4}/.test(t) && t.length <= 64) {
    const parsed = Date.parse(t);
    if (Number.isFinite(parsed)) ms = parsed;
  }
  if (ms == null || !Number.isFinite(ms)) return null;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  return { unixSeconds: Math.floor(ms / 1000), unixMs: ms, iso: d.toISOString() };
}
