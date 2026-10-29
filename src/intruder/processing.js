// Payload processing rules: an optional, ordered chain of transforms applied
// to every generated payload right before substitution — Burp's Intruder
// "payload processing" feature. Lets a Simple list/Numbers/Brute forcer
// payload set carry, say, "prepend admin_" then "Base64-encode" without the
// user hand-encoding every line of a wordlist themselves. Async because the
// hash rule goes through Web Crypto (see src/utils/hash.js) — every rule
// runs through the same async pipeline for one uniform code path rather
// than a sync/async split.
import { textToBase64, base64ToText } from "../utils/bytes.js";
import { sha1Hex, sha256Hex, md5Hex } from "../utils/hash.js";
import { encodeUrlAll, encodeBase64Url, encodeUnicodeEscape, encodeHtmlEntities, encodeHex } from "../parsers/decoder.js";

export const PROCESSING_RULE_TYPES = [
  { value: "prefix", label: "Add prefix" },
  { value: "suffix", label: "Add suffix" },
  { value: "replace", label: "Find & replace" },
  { value: "skipIfMatches", label: "Skip if matches (regex)" },
  { value: "urlEncode", label: "URL-encode" },
  { value: "urlEncodeAll", label: "URL-encode all characters" },
  { value: "doubleUrlEncode", label: "Double URL-encode" },
  { value: "urlDecode", label: "URL-decode" },
  { value: "htmlEncode", label: "HTML-encode" },
  { value: "base64Encode", label: "Base64-encode" },
  { value: "base64UrlEncode", label: "Base64url-encode" },
  { value: "base64Decode", label: "Base64-decode" },
  { value: "hexEncode", label: "Hex-encode" },
  { value: "unicodeEscape", label: "Unicode-escape (\\uXXXX)" },
  { value: "upper", label: "To uppercase" },
  { value: "lower", label: "To lowercase" },
  { value: "reverse", label: "Reverse" },
  { value: "trim", label: "Trim whitespace" },
  { value: "md5", label: "MD5 hash (hex)" },
  { value: "sha1", label: "SHA-1 hash (hex)" },
  { value: "sha256", label: "SHA-256 hash (hex)" },
];

// Rules with a text value; "replace" also has `match` (the text to find).
const TAKES_VALUE = new Set(["prefix", "suffix", "replace", "skipIfMatches"]);

export function ruleTakesValue(type) {
  return TAKES_VALUE.has(type);
}

export function ruleTakesMatch(type) {
  return type === "replace";
}

export function defaultProcessingRule(type) {
  if (type === "replace") return { type, match: "", value: "" };
  return TAKES_VALUE.has(type) ? { type, value: "" } : { type };
}

/** Returned by a rule to drop the payload from the attack entirely. */
export const SKIP = Symbol("skip payload");

async function applyRule(payload, rule) {
  switch (rule.type) {
    case "prefix":
      return `${rule.value ?? ""}${payload}`;
    case "suffix":
      return `${payload}${rule.value ?? ""}`;
    case "urlEncode":
      return encodeURIComponent(payload);
    case "urlDecode":
      try {
        return decodeURIComponent(payload);
      } catch {
        return payload; // malformed percent-encoding — pass through unchanged rather than abort the whole attack
      }
    case "base64Encode":
      return textToBase64(payload);
    case "base64Decode":
      try {
        return base64ToText(payload);
      } catch {
        return payload;
      }
    case "replace":
      return rule.match ? payload.split(rule.match).join(rule.value ?? "") : payload;
    case "skipIfMatches":
      try {
        return rule.value && new RegExp(rule.value).test(payload) ? SKIP : payload;
      } catch {
        return payload; // invalid regex — never skips, rather than aborting the attack
      }
    case "urlEncodeAll":
      return encodeUrlAll(payload);
    case "doubleUrlEncode":
      return encodeURIComponent(encodeURIComponent(payload));
    case "htmlEncode":
      return encodeHtmlEntities(payload);
    case "base64UrlEncode":
      return encodeBase64Url(payload);
    case "hexEncode":
      return encodeHex(payload);
    case "unicodeEscape":
      return encodeUnicodeEscape(payload);
    case "reverse":
      return [...payload].reverse().join("");
    case "trim":
      return payload.trim();
    case "md5":
      return md5Hex(payload);
    case "upper":
      return payload.toUpperCase();
    case "lower":
      return payload.toLowerCase();
    case "sha1":
      return sha1Hex(payload);
    case "sha256":
      return sha256Hex(payload);
    default:
      return payload;
  }
}

/** Runs `rules` over `payload` in order, each rule's output feeding the next. Returns SKIP if a "Skip if matches" rule dropped it. */
export async function applyProcessingRules(payload, rules) {
  let value = payload;
  for (const rule of rules || []) {
    value = await applyRule(value, rule);
    if (value === SKIP) return SKIP;
  }
  return value;
}

/** Runs applyProcessingRules over every entry of `payloads` (order preserved, skipped payloads removed). */
export async function applyProcessingRulesToAll(payloads, rules) {
  if (!rules || rules.length === 0) return payloads;
  const out = [];
  for (const p of payloads) {
    const v = await applyProcessingRules(p, rules);
    if (v !== SKIP) out.push(v);
  }
  return out;
}
