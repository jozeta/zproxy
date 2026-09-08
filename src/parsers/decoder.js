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

/** One entry per Decoder view tab. `decode` is only present for a mode that has a real inverse (JWT-style base64url isn't offered here since src/parsers/jwt.js already owns JWT decoding end to end). */
export const DECODER_MODES = [
  { id: "base64", label: "Base64", encode: encodeBase64, decode: decodeBase64 },
  { id: "url", label: "URL", encode: encodeUrl, decode: decodeUrl },
  { id: "html", label: "HTML entities", encode: encodeHtmlEntities, decode: decodeHtmlEntities },
  { id: "hex", label: "Hex", encode: encodeHex, decode: decodeHex },
];
