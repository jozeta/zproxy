// Pure, DOM-free payload generators. Kept deliberately small compared to
// Burp's full payload-type list (no dates/bit-flipper/username-generator/
// payload-processing-rules) — Simple list, Numbers, and Brute forcer cover
// the large majority of real Intruder usage, and every generator here is
// capped so a misconfigured attack (e.g. a wide brute-force range) can't
// freeze the tab materializing millions of strings.
export const DEFAULT_GENERATION_CAP = 20000;

export function defaultConfig(type) {
  switch (type) {
    case "numbers":
      return { type: "numbers", from: "1", to: "10", step: "1", format: "decimal", padLength: 0 };
    case "bruteForce":
      return { type: "bruteForce", charset: "abcdefghijklmnopqrstuvwxyz0123456789", minLength: 1, maxLength: 3 };
    case "simpleList":
    default:
      return { type: "simpleList", text: "" };
  }
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
    case "numbers":
      return countNumbers(config);
    case "bruteForce":
      return countBruteForce(config);
    default:
      return 0;
  }
}

/**
 * Materializes payloads for `config`, stopping at `limit` entries (default
 * DEFAULT_GENERATION_CAP). Returns {payloads, truncated} — `truncated` is
 * true when the generator had more to give than `limit` allowed.
 */
export function generatePayloads(config, { limit = DEFAULT_GENERATION_CAP } = {}) {
  let iter;
  switch (config?.type) {
    case "simpleList":
      iter = parseSimpleList(config.text)[Symbol.iterator]();
      break;
    case "numbers":
      iter = generateNumbersIter(config);
      break;
    case "bruteForce":
      iter = bruteForceIter(config);
      break;
    default:
      iter = [][Symbol.iterator]();
  }
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
