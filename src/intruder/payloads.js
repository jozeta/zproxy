// Pure, DOM-free payload generators — Burp Intruder's most-used payload
// types: Simple list, built-in Fuzz lists, Numbers, Dates, Brute forcer,
// Case modification, Character substitution, Username generator, Character
// blocks, and Null payloads. Every generator is capped so a misconfigured
// attack (e.g. a wide brute-force range) can't freeze the tab
// materializing millions of strings.
import { WORDLISTS } from "./wordlists.js";
import * as Adv from "./payloads-advanced.js";

export const DEFAULT_GENERATION_CAP = 20000;

/** The payload types, in the order the UI lists them. */
export const PAYLOAD_TYPES = [
  { value: "simpleList", label: "Simple list" },
  { value: "wordlist", label: "Fuzz list (built-in)" },
  { value: "numbers", label: "Numbers" },
  { value: "dates", label: "Dates" },
  { value: "bruteForce", label: "Brute forcer" },
  { value: "caseModification", label: "Case modification" },
  { value: "charSubstitution", label: "Character substitution" },
  { value: "usernames", label: "Username generator" },
  { value: "charBlocks", label: "Character blocks" },
  { value: "nullPayloads", label: "Null payloads" },
  { value: "customIterator", label: "Custom iterator" },
  { value: "regexGenerator", label: "Regex generator" },
  { value: "encodingVariants", label: "Encoding variants" },
  { value: "illegalUnicode", label: "Illegal Unicode" },
  { value: "characterFrobber", label: "Character frobber" },
  { value: "bitFlipper", label: "Bit flipper" },
  { value: "ecbShuffler", label: "ECB block shuffler" },
  { value: "ipRange", label: "IP ranges" },
  { value: "randomStrings", label: "Random strings" },
  { value: "uuids", label: "UUIDs" },
];

export const DATE_FORMATS = ["YYYY-MM-DD", "DD/MM/YYYY", "MM/DD/YYYY", "YYYYMMDD", "DD-MM-YYYY", "unix", "unixMs", "iso"];
export const DEFAULT_SUBSTITUTIONS = "a=4 e=3 i=1 o=0 s=5 t=7";

export function defaultConfig(type) {
  switch (type) {
    case "numbers":
      return { type: "numbers", from: "1", to: "10", step: "1", format: "decimal", padLength: 0 };
    case "bruteForce":
      return { type: "bruteForce", charset: "abcdefghijklmnopqrstuvwxyz0123456789", minLength: 1, maxLength: 3 };
    case "wordlist":
      return { type: "wordlist", list: "sqli" };
    case "dates":
      return { type: "dates", from: "2024-01-01", to: "2024-01-31", stepDays: 1, format: "YYYY-MM-DD" };
    case "caseModification":
      return { type: "caseModification", text: "" };
    case "charSubstitution":
      return { type: "charSubstitution", text: "", substitutions: DEFAULT_SUBSTITUTIONS };
    case "usernames":
      return { type: "usernames", text: "" };
    case "charBlocks":
      return { type: "charBlocks", base: "A", minLength: 100, maxLength: 1000, step: 100 };
    case "nullPayloads":
      return { type: "nullPayloads", count: 10 };
    case "customIterator":
      return { type: "customIterator", slots: [{ text: "", separator: "" }, { text: "", separator: "" }] };
    case "regexGenerator":
      return { type: "regexGenerator", pattern: "", maxRepeat: 3 };
    case "encodingVariants":
    case "characterFrobber":
      return { type, text: "" };
    case "illegalUnicode":
      return { type: "illegalUnicode", text: "../", targets: "" };
    case "bitFlipper":
      return { type: "bitFlipper", text: "", format: "text" };
    case "ecbShuffler":
      return { type: "ecbShuffler", text: "", format: "base64", blockSize: 16 };
    case "ipRange":
      return { type: "ipRange", text: "127.0.0.1\n10.0.0.0/30" };
    case "randomStrings":
      return { type: "randomStrings", count: 20, length: 16, charset: "hex", custom: "" };
    case "uuids":
      return { type: "uuids", count: 20, uppercase: false };
    case "simpleList":
    default:
      return { type: "simpleList", text: "" };
  }
}

// --- Dates ---

const DAY_MS = 86_400_000;

function parseIsoDate(text) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec((text || "").trim());
  if (!m) return null;
  const t = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return Number.isFinite(t) ? t : null;
}

/** Formats a UTC timestamp (ms) per one of DATE_FORMATS. */
export function formatDate(ms, format) {
  const d = new Date(ms);
  const Y = String(d.getUTCFullYear());
  const M = String(d.getUTCMonth() + 1).padStart(2, "0");
  const D = String(d.getUTCDate()).padStart(2, "0");
  switch (format) {
    case "DD/MM/YYYY":
      return `${D}/${M}/${Y}`;
    case "MM/DD/YYYY":
      return `${M}/${D}/${Y}`;
    case "YYYYMMDD":
      return `${Y}${M}${D}`;
    case "DD-MM-YYYY":
      return `${D}-${M}-${Y}`;
    case "unix":
      return String(Math.floor(ms / 1000));
    case "unixMs":
      return String(ms);
    case "iso":
      return d.toISOString();
    case "YYYY-MM-DD":
    default:
      return `${Y}-${M}-${D}`;
  }
}

function dateRange({ from, to, stepDays }) {
  const f = parseIsoDate(from);
  const t = parseIsoDate(to);
  const step = Math.trunc(Number(stepDays));
  if (f == null || t == null || !step) return null;
  return { f, t, stepMs: step * DAY_MS };
}

function* datesIter(config) {
  const r = dateRange(config);
  if (!r) return;
  for (let ms = r.f; r.stepMs > 0 ? ms <= r.t : ms >= r.t; ms += r.stepMs) yield formatDate(ms, config.format);
}

function countDates(config) {
  const r = dateRange(config);
  if (!r || (r.stepMs > 0 && r.f > r.t) || (r.stepMs < 0 && r.f < r.t)) return 0;
  return Math.floor((r.t - r.f) / r.stepMs) + 1;
}

// --- Word-based variants ---

/** Case variants of one word, de-duplicated, original first. */
export function caseVariants(word) {
  const variants = [
    word,
    word.toLowerCase(),
    word.toUpperCase(),
    word.charAt(0).toUpperCase() + word.slice(1).toLowerCase(),
    [...word].map((c) => (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase())).join(""),
    [...word].map((c, i) => (i % 2 ? c.toLowerCase() : c.toUpperCase())).join(""),
  ];
  return [...new Set(variants)];
}

/** "a=4 e=3,@" → Map(a → ["4"], e → ["3", "@"]). Keys are lower-cased; one character per key. */
export function parseSubstitutions(spec) {
  const map = new Map();
  for (const pair of (spec || "").split(/\s+/).filter(Boolean)) {
    const eq = pair.indexOf("=");
    if (eq !== 1) continue;
    const from = pair[0].toLowerCase();
    const tos = pair.slice(2).split(",").filter(Boolean);
    if (tos.length) map.set(from, [...new Set([...(map.get(from) || []), ...tos])]);
  }
  return map;
}

/** Every combination of substituting (or not) each substitutable character of `word`. */
export function* substitutionVariants(word, map) {
  const options = [...word].map((c) => [c, ...(map.get(c.toLowerCase()) || [])]);
  const idx = new Array(options.length).fill(0);
  while (true) {
    yield idx.map((j, i) => options[i][j]).join("");
    let p = options.length - 1;
    for (; p >= 0; p--) {
      idx[p]++;
      if (idx[p] < options[p].length) break;
      idx[p] = 0;
    }
    if (p < 0) return;
  }
}

/** Likely usernames for a "First Last" (or single) name. */
export function usernameVariants(fullName) {
  const parts = fullName.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return [];
  if (parts.length === 1) return [parts[0]];
  const first = parts[0];
  const last = parts[parts.length - 1];
  const f = first[0];
  const l = last[0];
  return [...new Set([`${first}.${last}`, `${first}${last}`, `${f}${last}`, `${f}.${last}`, `${first}_${last}`, `${first}-${last}`, `${last}${first}`, `${last}.${first}`, `${last}${f}`, `${first}${l}`, first, last])];
}

function* perLine(text, expand) {
  for (const line of parseSimpleList(text)) yield* expand(line);
}

// --- Blocks / nulls ---

function* charBlocksIter({ base, minLength, maxLength, step }) {
  const unit = base || "A";
  const min = Math.max(0, Math.trunc(Number(minLength)) || 0);
  const max = Math.max(min, Math.trunc(Number(maxLength)) || min);
  const s = Math.max(1, Math.trunc(Number(step)) || 1);
  for (let len = min; len <= max; len += s) yield unit.repeat(Math.ceil(len / unit.length)).slice(0, len);
}

function countCharBlocks({ minLength, maxLength, step }) {
  const min = Math.max(0, Math.trunc(Number(minLength)) || 0);
  const max = Math.max(min, Math.trunc(Number(maxLength)) || min);
  const s = Math.max(1, Math.trunc(Number(step)) || 1);
  return Math.floor((max - min) / s) + 1;
}

function nullCount({ count }) {
  return Math.max(0, Math.trunc(Number(count)) || 0);
}

function parseSimpleList(text) {
  return (text || "").split("\n").map((l) => l.replace(/\r$/, "")).filter((l) => l.length > 0);
}

function* generateNumbersIter({ from, to, step, format = "decimal", padLength = 0 }) {
  const f = Number(from);
  const t = Number(to);
  const s = Number(step);
  if (!Number.isFinite(f) || !Number.isFinite(t) || !Number.isFinite(s) || s === 0) return;
  const ascending = s > 0;
  const pad = Math.max(0, Number(padLength) || 0);
  // A small epsilon guards against float step-accumulation (e.g. step 0.1)
  // stopping one iteration short of an endpoint it should actually reach.
  for (let n = f; ascending ? n <= t + 1e-9 : n >= t - 1e-9; n += s) {
    const rounded = Math.round(n * 1e6) / 1e6;
    let str;
    if (format === "hex") {
      str = Math.trunc(rounded).toString(16);
      if (pad) str = str.padStart(pad, "0");
    } else {
      str = String(rounded);
      if (pad && Number.isInteger(rounded)) {
        const neg = rounded < 0;
        str = (neg ? "-" : "") + Math.abs(rounded).toString().padStart(pad, "0");
      }
    }
    yield str;
  }
}

export function countNumbers({ from, to, step }) {
  const f = Number(from);
  const t = Number(to);
  const s = Number(step);
  if (!Number.isFinite(f) || !Number.isFinite(t) || !Number.isFinite(s) || s === 0) return 0;
  if (s > 0 && f > t) return 0;
  if (s < 0 && f < t) return 0;
  return Math.floor(Math.abs((t - f) / s) + 1e-9) + 1;
}

function uniqueChars(charset) {
  return [...new Set((charset || "").split(""))];
}

function* combosOfLength(chars, len) {
  const n = chars.length;
  const idx = new Array(len).fill(0);
  const total = Math.pow(n, len);
  for (let i = 0; i < total; i++) {
    yield idx.map((j) => chars[j]).join("");
    for (let p = len - 1; p >= 0; p--) {
      idx[p]++;
      if (idx[p] < n) break;
      idx[p] = 0;
    }
  }
}

function* bruteForceIter({ charset, minLength, maxLength }) {
  const chars = uniqueChars(charset);
  if (chars.length === 0) return;
  const min = Math.max(1, Number(minLength) || 1);
  const max = Math.max(min, Number(maxLength) || min);
  for (let len = min; len <= max; len++) yield* combosOfLength(chars, len);
}

export function countBruteForce({ charset, minLength, maxLength }) {
  const n = uniqueChars(charset).length;
  if (n === 0) return 0;
  const min = Math.max(1, Number(minLength) || 1);
  const max = Math.max(min, Number(maxLength) || min);
  let total = 0;
  for (let len = min; len <= max; len++) {
    total += Math.pow(n, len);
    if (total > Number.MAX_SAFE_INTEGER / 2) return Infinity;
  }
  return total;
}

/** Cheap payload-count estimate for a config, without materializing anything — used for "this will generate N payloads" previews/warnings. */
export function estimateCount(config) {
  switch (config?.type) {
    case "simpleList":
      return parseSimpleList(config.text).length;
    case "wordlist":
      return WORDLISTS[config.list]?.items.length ?? 0;
    case "numbers":
      return countNumbers(config);
    case "dates":
      return countDates(config);
    case "bruteForce":
      return countBruteForce(config);
    case "charBlocks":
      return countCharBlocks(config);
    case "nullPayloads":
      return nullCount(config);
    case "customIterator":
      return Adv.countCustomIterator(config);
    case "ipRange":
      return Adv.countIpRange(config);
    case "randomStrings":
    case "uuids":
      return nullCount(config);
    case "regexGenerator":
    case "encodingVariants":
    case "illegalUnicode":
    case "characterFrobber":
    case "bitFlipper":
    case "ecbShuffler":
    case "caseModification":
    case "charSubstitution":
    case "usernames":
      // Variant counts depend on each word's content — generate (capped) and count.
      return generatePayloads(config).payloads.length;
    default:
      return 0;
  }
}

function iteratorFor(config) {
  switch (config?.type) {
    case "simpleList":
      return parseSimpleList(config.text)[Symbol.iterator]();
    case "wordlist":
      return (WORDLISTS[config.list]?.items ?? [])[Symbol.iterator]();
    case "numbers":
      return generateNumbersIter(config);
    case "dates":
      return datesIter(config);
    case "bruteForce":
      return bruteForceIter(config);
    case "caseModification":
      return perLine(config.text, caseVariants);
    case "charSubstitution": {
      const map = parseSubstitutions(config.substitutions ?? DEFAULT_SUBSTITUTIONS);
      return perLine(config.text, (word) => substitutionVariants(word, map));
    }
    case "usernames":
      return perLine(config.text, usernameVariants);
    case "charBlocks":
      return charBlocksIter(config);
    case "nullPayloads":
      return (function* () {
        for (let i = 0; i < nullCount(config); i++) yield "";
      })();
    case "customIterator":
      return Adv.customIteratorIter(config);
    case "regexGenerator":
      return Adv.regexGeneratorIter(config);
    case "encodingVariants":
      return Adv.encodingVariantsIter(config);
    case "illegalUnicode":
      return Adv.illegalUnicodeIter(config);
    case "characterFrobber":
      return Adv.characterFrobberIter(config);
    case "bitFlipper":
      return Adv.bitFlipperIter(config);
    case "ecbShuffler":
      return Adv.ecbShufflerIter(config);
    case "ipRange":
      return Adv.ipRangeIter(config);
    case "randomStrings":
      return Adv.randomStringsIter(config);
    case "uuids":
      return Adv.uuidIter(config);
    default:
      return [][Symbol.iterator]();
  }
}

/**
 * Materializes payloads for `config`, stopping at `limit` entries (default
 * DEFAULT_GENERATION_CAP). Returns {payloads, truncated} — `truncated` is
 * true when the generator had more to give than `limit` allowed.
 */
export function generatePayloads(config, { limit = DEFAULT_GENERATION_CAP } = {}) {
  const iter = iteratorFor(config);
  const payloads = [];
  let truncated = false;
  for (const p of iter) {
    if (payloads.length >= limit) {
      truncated = true;
      break;
    }
    payloads.push(p);
  }
  return { payloads, truncated };
}
