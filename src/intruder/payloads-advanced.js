// More Intruder payload generators, chosen by comparing ZProxy against Burp
// Intruder's documented payload types, ZAP's fuzzer, and ffuf/wfuzz (see
// CHANGELOG 0.4.0): Custom iterator, Illegal Unicode, Character frobber,
// Bit flipper, ECB block shuffler (Burp); Regex generator (ZAP); IP ranges,
// Random strings, UUIDs, Encoding variants (ffuf/wfuzz). Every generator is
// a lazy iterator — payloads.js caps how many are materialized.
import { encodeUrlAll, encodeHtmlEntities, encodeUnicodeEscape, encodeBase64 } from "../parsers/decoder.js";

function lines(text) {
  return (text || "").split("\n").map((l) => l.replace(/\r$/, "")).filter((l) => l.length > 0);
}

// ------------------------------------------------------- Custom iterator --

/** Every combination of one item per slot, joined with each slot's separator — Burp's Custom iterator. */
export function* customIteratorIter({ slots = [] }) {
  const lists = slots.map((s) => ({ items: lines(s.text), separator: s.separator ?? "" })).filter((s) => s.items.length > 0);
  if (lists.length === 0) return;
  const idx = new Array(lists.length).fill(0);
  while (true) {
    yield lists.map((l, i) => l.items[idx[i]] + (i < lists.length - 1 ? l.separator : "")).join("");
    let p = lists.length - 1;
    for (; p >= 0; p--) {
      idx[p]++;
      if (idx[p] < lists[p].items.length) break;
      idx[p] = 0;
    }
    if (p < 0) return;
  }
}

export function countCustomIterator({ slots = [] }) {
  const sizes = slots.map((s) => lines(s.text).length).filter((n) => n > 0);
  return sizes.length ? sizes.reduce((a, b) => a * b, 1) : 0;
}

// ------------------------------------------------------- Illegal Unicode --

const pct = (bytes) => bytes.map((b) => `%${b.toString(16).toUpperCase().padStart(2, "0")}`).join("");

/**
 * Non-standard encodings of an ASCII character that lenient decoders turn
 * back into it, but filters looking for the literal character miss:
 * overlong 2/3/4-byte UTF-8 (the classic %C0%AF for "/"), %u-encoding,
 * double percent-encoding, and the full-width Unicode form that NFKC
 * normalization folds back to ASCII.
 */
export function illegalUnicodeForms(char) {
  const c = char.charCodeAt(0);
  if (c > 0x7f) return [];
  const forms = [
    pct([0xc0 | (c >> 6), 0x80 | (c & 0x3f)]),
    pct([0xe0, 0x80 | (c >> 6), 0x80 | (c & 0x3f)]),
    pct([0xf0, 0x80, 0x80 | (c >> 6), 0x80 | (c & 0x3f)]),
    `%u${c.toString(16).toUpperCase().padStart(4, "0")}`,
    `%25${c.toString(16).toUpperCase().padStart(2, "0")}`,
  ];
  if (c >= 0x21 && c <= 0x7e) forms.push(String.fromCharCode(0xff00 + (c - 0x20)));
  return forms;
}

/**
 * For each input line, one payload per encoding form, with every
 * occurrence of the target characters (default: the whole line's
 * non-alphanumerics) replaced by that form.
 */
export function* illegalUnicodeIter({ text, targets }) {
  const targetSet = targets ? new Set([...targets]) : null;
  for (const line of lines(text)) {
    const isTarget = (ch) => (targetSet ? targetSet.has(ch) : /[^A-Za-z0-9]/.test(ch));
    for (let form = 0; form < 6; form++) {
      let changed = false;
      const out = [...line]
        .map((ch) => {
          if (!isTarget(ch)) return ch;
          const f = illegalUnicodeForms(ch)[form];
          if (f === undefined) return ch;
          changed = true;
          return f;
        })
        .join("");
      if (changed) yield out;
    }
  }
}

// ------------------------------------------------ Frobber / bit flipping --

/** Each position's character code incremented by one, one position at a time — Burp's Character frobber. */
export function* characterFrobberIter({ text }) {
  for (const base of lines(text)) {
    for (let i = 0; i < base.length; i++) yield base.slice(0, i) + String.fromCharCode(base.charCodeAt(i) + 1) + base.slice(i + 1);
  }
}

/** Every single-bit flip of each byte (literal text, or hex when format is "hex") — Burp's Bit flipper. */
export function* bitFlipperIter({ text, format = "text", bits = [0, 1, 2, 3, 4, 5, 6, 7] }) {
  for (const base of lines(text)) {
    if (format === "hex") {
      const clean = base.replace(/\s+/g, "");
      if (!/^([0-9a-f]{2})+$/i.test(clean)) continue;
      const bytes = clean.match(/../g).map((h) => parseInt(h, 16));
      for (let i = 0; i < bytes.length; i++) {
        for (const bit of bits) {
          const copy = bytes.slice();
          copy[i] ^= 1 << bit;
          yield copy.map((b) => b.toString(16).padStart(2, "0")).join("");
        }
      }
    } else {
      for (let i = 0; i < base.length; i++) {
        for (const bit of bits) yield base.slice(0, i) + String.fromCharCode(base.charCodeAt(i) ^ (1 << bit)) + base.slice(i + 1);
      }
    }
  }
}

// ----------------------------------------------------- ECB block shuffler --

function decodeCipher(text, format) {
  const t = text.trim();
  if (format === "hex") return /^([0-9a-f]{2})+$/i.test(t) ? t.match(/../g).map((h) => parseInt(h, 16)) : null;
  try {
    const b64 = t.replace(/-/g, "+").replace(/_/g, "/");
    return [...atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4))].map((c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function encodeCipher(bytes, format) {
  if (format === "hex") return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  return btoa(String.fromCharCode(...bytes));
}

/**
 * ECB encrypts each block independently, so blocks can be rearranged and
 * still decrypt — e.g. moving an "admin" block into the role position.
 * Yields every ciphertext where block i is replaced by block j (i ≠ j),
 * in the input's format (hex or base64).
 */
export function* ecbShufflerIter({ text, format = "base64", blockSize = 16 }) {
  const size = Number(blockSize) || 16;
  for (const line of lines(text)) {
    const bytes = decodeCipher(line, format);
    if (!bytes || bytes.length < size * 2 || bytes.length % size !== 0) continue;
    const blocks = [];
    for (let i = 0; i < bytes.length; i += size) blocks.push(bytes.slice(i, i + size));
    for (let i = 0; i < blocks.length; i++) {
      for (let j = 0; j < blocks.length; j++) {
        if (i === j) continue;
        const shuffled = blocks.map((b, k) => (k === i ? blocks[j] : b)).flat();
        yield encodeCipher(shuffled, format);
      }
    }
  }
}

// ----------------------------------------------------------- IP ranges --

function ipToInt(ip) {
  const parts = ip.trim().split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null;
  return parts.reduce((n, p) => n * 256 + Number(p), 0);
}

function intToIp(n) {
  return [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join(".");
}

/** Start/end (inclusive) for a CIDR ("10.0.0.0/30"), a range ("10.0.0.1-10.0.0.9"), or a single IP; null if invalid. */
export function parseIpRange(spec) {
  const s = spec.trim();
  const cidr = s.match(/^([\d.]+)\/(\d{1,2})$/);
  if (cidr) {
    const base = ipToInt(cidr[1]);
    const bits = Number(cidr[2]);
    if (base === null || bits > 32) return null;
    const size = 2 ** (32 - bits);
    const start = Math.floor(base / size) * size;
    return { start, end: start + size - 1 };
  }
  const range = s.match(/^([\d.]+)\s*-\s*([\d.]+)$/);
  if (range) {
    const start = ipToInt(range[1]);
    const end = ipToInt(range[2]);
    return start !== null && end !== null && end >= start ? { start, end } : null;
  }
  const single = ipToInt(s);
  return single === null ? null : { start: single, end: single };
}

export function* ipRangeIter({ text }) {
  for (const spec of lines(text)) {
    const r = parseIpRange(spec);
    if (r) for (let n = r.start; n <= r.end; n++) yield intToIp(n);
  }
}

export function countIpRange({ text }) {
  return lines(text).reduce((sum, spec) => {
    const r = parseIpRange(spec);
    return sum + (r ? r.end - r.start + 1 : 0);
  }, 0);
}

// ------------------------------------------------- Random strings / UUIDs --

export const RANDOM_CHARSETS = {
  hex: "0123456789abcdef",
  alphanumeric: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  digits: "0123456789",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
};

/** `count` random strings (crypto-grade randomness) of `length` from a named or custom charset. New values on every generation. */
export function* randomStringsIter({ count, length, charset = "hex", custom = "" }) {
  const chars = charset === "custom" ? [...new Set(custom)] : [...(RANDOM_CHARSETS[charset] || RANDOM_CHARSETS.hex)];
  const len = Math.max(1, Math.min(4096, Math.trunc(Number(length)) || 1));
  if (chars.length === 0) return;
  for (let i = 0; i < Math.max(0, Math.trunc(Number(count)) || 0); i++) {
    const rnd = crypto.getRandomValues(new Uint32Array(len));
    yield [...rnd].map((r) => chars[r % chars.length]).join("");
  }
}

/** `count` random (v4) UUIDs — for IDOR checks against UUID-keyed objects and cache busting. */
export function* uuidIter({ count, uppercase = false }) {
  for (let i = 0; i < Math.max(0, Math.trunc(Number(count)) || 0); i++) {
    const id = crypto.randomUUID();
    yield uppercase ? id.toUpperCase() : id;
  }
}

// ------------------------------------------------------ Encoding variants --

/** The same payload in the encodings WAFs and filters most often fail to normalize. */
export function encodingVariants(value) {
  const codes = [...value];
  return [
    value,
    encodeURIComponent(value),
    encodeURIComponent(encodeURIComponent(value)),
    encodeUrlAll(value),
    encodeHtmlEntities(value),
    codes.map((c) => `&#x${c.codePointAt(0).toString(16)};`).join(""),
    codes.map((c) => `&#${c.codePointAt(0)};`).join(""),
    codes.map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join(""),
    encodeUnicodeEscape(value),
    codes.map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""),
    encodeBase64(value),
  ].filter((v, i, all) => all.indexOf(v) === i);
}

export function* encodingVariantsIter({ text }) {
  for (const line of lines(text)) yield* encodingVariants(line);
}

// ------------------------------------------------------- Regex generator --

const PRINTABLE = Array.from({ length: 95 }, (_, i) => String.fromCharCode(0x20 + i));
const CLASS_ESCAPES = {
  d: "0123456789".split(""),
  w: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_".split(""),
  s: [" "],
};

/**
 * Parses the subset of regex syntax a payload template needs: literals and
 * escapes, character classes with ranges and negation, ".", \d \w \s,
 * groups with "|", and the quantifiers ? * + {n} {n,m} ("*" and "+" are
 * capped at `maxRepeat`, since they're unbounded). Anchors are ignored.
 * Throws a readable Error on anything else.
 */
export function parseRegexTemplate(source, { maxRepeat = 3 } = {}) {
  let i = 0;
  const peek = () => source[i];
  const fail = (msg) => {
    throw new Error(`${msg} at position ${i + 1}`);
  };

  function parseAlternation() {
    const options = [parseSequence()];
    while (peek() === "|") {
      i++;
      options.push(parseSequence());
    }
    return options.length === 1 ? options[0] : { type: "alt", options };
  }

  function parseSequence() {
    const items = [];
    while (i < source.length && peek() !== "|" && peek() !== ")") {
      let atom = parseAtom();
      if (atom === null) continue;
      atom = parseQuantifier(atom);
      items.push(atom);
    }
    return { type: "seq", items };
  }

  function parseAtom() {
    const ch = source[i++];
    if (ch === "^" || ch === "$") return null;
    if (ch === "(") {
      if (source.startsWith("?:", i)) i += 2;
      const inner = parseAlternation();
      if (source[i++] !== ")") fail("Missing )");
      return inner;
    }
    if (ch === "[") return parseClass();
    if (ch === ".") return { type: "set", chars: PRINTABLE };
    if (ch === "\\") {
      const e = source[i++];
      if (e === undefined) fail("Dangling \\");
      if (CLASS_ESCAPES[e]) return { type: "set", chars: CLASS_ESCAPES[e] };
      if (/[DWSbB]/.test(e)) fail(`\\${e} isn't supported`);
      return { type: "set", chars: [{ n: "\n", t: "\t", r: "\r" }[e] ?? e] };
    }
    if ("*+?{".includes(ch)) fail(`Nothing to repeat before "${ch}"`);
    if (ch === ")") fail("Unmatched )");
    return { type: "set", chars: [ch] };
  }

  function parseClass() {
    let negate = false;
    if (peek() === "^") {
      negate = true;
      i++;
    }
    const chars = new Set();
    let first = true;
    while (i < source.length && (peek() !== "]" || first)) {
      first = false;
      let c = source[i++];
      if (c === "\\") {
        const e = source[i++];
        if (CLASS_ESCAPES[e]) {
          CLASS_ESCAPES[e].forEach((x) => chars.add(x));
          continue;
        }
        c = e;
      }
      if (peek() === "-" && source[i + 1] !== "]" && source[i + 1] !== undefined) {
        i++;
        let end = source[i++];
        if (end === "\\") end = source[i++];
        if (end.charCodeAt(0) < c.charCodeAt(0)) fail(`Range ${c}-${end} is backwards`);
        for (let code = c.charCodeAt(0); code <= end.charCodeAt(0); code++) chars.add(String.fromCharCode(code));
      } else {
        chars.add(c);
      }
    }
    if (source[i++] !== "]") fail("Missing ]");
    const list = negate ? PRINTABLE.filter((c) => !chars.has(c)) : [...chars];
    if (list.length === 0) fail("Empty character class");
    return { type: "set", chars: list };
  }

  function parseQuantifier(node) {
    const q = peek();
    if (q === "?") return (i++, { type: "repeat", node, min: 0, max: 1 });
    if (q === "*") return (i++, { type: "repeat", node, min: 0, max: maxRepeat });
    if (q === "+") return (i++, { type: "repeat", node, min: 1, max: maxRepeat });
    if (q === "{") {
      const m = source.slice(i).match(/^\{(\d+)(,(\d*))?\}/);
      if (!m) fail("Malformed {n,m}");
      i += m[0].length;
      const min = Number(m[1]);
      const max = m[2] ? (m[3] === "" ? min + maxRepeat : Number(m[3])) : min;
      if (max < min) fail("{n,m} with m < n");
      return { type: "repeat", node, min, max };
    }
    return node;
  }

  const tree = parseAlternation();
  if (i < source.length) fail("Unmatched )");
  return tree;
}

function* expand(node) {
  switch (node.type) {
    case "set":
      yield* node.chars;
      return;
    case "alt":
      for (const o of node.options) yield* expand(o);
      return;
    case "seq":
      yield* expandSeq(node.items, 0);
      return;
    case "repeat":
      for (let k = node.min; k <= node.max; k++) yield* expandSeq(new Array(k).fill(node.node), 0);
      return;
    default:
  }
}

function* expandSeq(items, index) {
  if (index >= items.length) {
    yield "";
    return;
  }
  for (const head of expand(items[index])) {
    for (const rest of expandSeq(items, index + 1)) yield head + rest;
  }
}

/** Every string matching the template (lazily; payloads.js caps it). An invalid template generates nothing. */
export function* regexGeneratorIter({ pattern, maxRepeat = 3 }) {
  let tree;
  try {
    tree = parseRegexTemplate(pattern || "", { maxRepeat: Math.max(0, Math.min(8, Number(maxRepeat) || 3)) });
  } catch {
    return;
  }
  if (!pattern) return;
  yield* expand(tree);
}
