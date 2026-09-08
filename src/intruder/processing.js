// Payload processing rules: an optional, ordered chain of transforms applied
// to every generated payload right before substitution — Burp's Intruder
// "payload processing" feature. Lets a Simple list/Numbers/Brute forcer
// payload set carry, say, "prepend admin_" then "Base64-encode" without the
// user hand-encoding every line of a wordlist themselves. Async because the
// hash rule goes through Web Crypto (see src/utils/hash.js) — every rule
// runs through the same async pipeline for one uniform code path rather
// than a sync/async split.
import { textToBase64, base64ToText } from "../utils/bytes.js";
import { sha1Hex, sha256Hex } from "../utils/hash.js";

export const PROCESSING_RULE_TYPES = [
  { value: "prefix", label: "Add prefix" },
  { value: "suffix", label: "Add suffix" },
  { value: "urlEncode", label: "URL-encode" },
  { value: "urlDecode", label: "URL-decode" },
  { value: "base64Encode", label: "Base64-encode" },
  { value: "base64Decode", label: "Base64-decode" },
  { value: "upper", label: "To uppercase" },
  { value: "lower", label: "To lowercase" },
  { value: "sha1", label: "SHA-1 hash (hex)" },
  { value: "sha256", label: "SHA-256 hash (hex)" },
];

const TAKES_VALUE = new Set(["prefix", "suffix"]);

export function ruleTakesValue(type) {
  return TAKES_VALUE.has(type);
}

export function defaultProcessingRule(type) {
  return TAKES_VALUE.has(type) ? { type, value: "" } : { type };
}

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

/** Runs `rules` over `payload` in order, each rule's output feeding the next. */
export async function applyProcessingRules(payload, rules) {
  let value = payload;
  for (const rule of rules || []) {
    value = await applyRule(value, rule);
  }
  return value;
}

/** Runs applyProcessingRules over every entry of `payloads` (order preserved). */
export async function applyProcessingRulesToAll(payloads, rules) {
  if (!rules || rules.length === 0) return payloads;
  const out = new Array(payloads.length);
  for (let i = 0; i < payloads.length; i++) out[i] = await applyProcessingRules(payloads[i], rules);
  return out;
}
