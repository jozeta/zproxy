// Config fields for Intruder's newer payload types (Fuzz list, Dates, Case
// modification, Character substitution, Username generator, Character
// blocks, Null payloads). The original three types keep their fields in
// views/intruder.js. `update(patch)` merges into the active payload set's
// config and refreshes the payload count.
import { WORDLISTS, WORDLIST_IDS } from "../../intruder/wordlists.js";
import { DATE_FORMATS, DEFAULT_SUBSTITUTIONS, generatePayloads } from "../../intruder/payloads.js";
import { parseRegexTemplate } from "../../intruder/payloads-advanced.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function row(host, label, control) {
  const r = el("div", "zp-form-row");
  r.appendChild(el("label", "", label));
  r.appendChild(control);
  host.appendChild(r);
  return control;
}

function input(type, value, onInput) {
  const i = document.createElement("input");
  i.type = type;
  i.value = value ?? "";
  i.addEventListener("input", () => onInput(i.value));
  return i;
}

function select(options, value, onChange) {
  const s = document.createElement("select");
  for (const [v, label] of options) {
    const o = document.createElement("option");
    o.value = v;
    o.textContent = label;
    s.appendChild(o);
  }
  s.value = value;
  s.addEventListener("change", () => onChange(s.value));
  return s;
}

function wordsArea(host, cfg, update, placeholder) {
  const area = document.createElement("textarea");
  area.style.minHeight = "90px";
  area.placeholder = placeholder;
  area.value = cfg.text || "";
  area.addEventListener("input", () => update({ text: area.value }));
  host.appendChild(area);
}

/** A live sample of what the current config generates. */
function samplePreview(host, getConfig) {
  const pre = el("pre", "zp-raw-view zp-intruder-preview");
  host.appendChild(pre);
  const refresh = () => {
    const { payloads, truncated } = generatePayloads(getConfig(), { limit: 12 });
    pre.textContent = payloads.length ? payloads.map((p) => (p === "" ? "(empty)" : p)).join("\n") + (truncated ? "\n…" : "") : "(nothing generated yet)";
  };
  refresh();
  return refresh;
}

const DATE_FORMAT_LABELS = {
  "YYYY-MM-DD": "2024-01-31",
  "DD/MM/YYYY": "31/01/2024",
  "MM/DD/YYYY": "01/31/2024",
  YYYYMMDD: "20240131",
  "DD-MM-YYYY": "31-01-2024",
  unix: "Unix seconds",
  unixMs: "Unix milliseconds",
  iso: "ISO 8601 (UTC)",
};

/** Renders fields for `cfg.type` into `host`; returns false for a type this module doesn't own. */
export function renderExtraPayloadFields(cfg, host, update, getConfig) {
  let refreshSample = () => {};
  const changed = (patch) => {
    update(patch);
    refreshSample();
  };
  switch (cfg.type) {
    case "wordlist":
      row(host, "List", select(WORDLIST_IDS.map((id) => [id, `${WORDLISTS[id].label} (${WORDLISTS[id].items.length})`]), cfg.list, (v) => changed({ list: v })));
      host.appendChild(el("p", "zp-hint", "Curated starting points for each injection class — not exhaustive. For a full dictionary, load a file with Simple list. Only use against applications you're authorized to test."));
      break;
    case "dates":
      row(host, "From", input("date", cfg.from, (v) => changed({ from: v })));
      row(host, "To", input("date", cfg.to, (v) => changed({ to: v })));
      row(host, "Step (days)", input("number", String(cfg.stepDays), (v) => changed({ stepDays: Number(v) })));
      row(host, "Format", select(DATE_FORMATS.map((f) => [f, DATE_FORMAT_LABELS[f] || f]), cfg.format, (v) => changed({ format: v })));
      break;
    case "caseModification":
      wordsArea(host, cfg, changed, "One word per line — each becomes: as-is, lower, UPPER, Capitalized, iNVERTED, AlTeRnAtInG");
      break;
    case "charSubstitution":
      wordsArea(host, cfg, changed, "One word per line — every combination of substitutions is generated");
      row(host, "Substitutions", input("text", cfg.substitutions ?? DEFAULT_SUBSTITUTIONS, (v) => changed({ substitutions: v })));
      host.appendChild(el("p", "zp-hint", 'Space-separated "char=replacement" pairs; give several replacements with commas, e.g. "a=4,@ s=5,$". Grows fast: a word with n substitutable letters yields up to 2ⁿ variants.'));
      break;
    case "usernames":
      wordsArea(host, cfg, changed, "One full name per line, e.g. Ada Lovelace");
      host.appendChild(el("p", "zp-hint", "Generates common username formats per name: ada.lovelace, adalovelace, alovelace, a.lovelace, ada_lovelace, lovelace.ada, ada, lovelace, …"));
      break;
    case "charBlocks":
      row(host, "Base string", input("text", cfg.base, (v) => changed({ base: v })));
      row(host, "Min length", input("number", String(cfg.minLength), (v) => changed({ minLength: Number(v) })));
      row(host, "Max length", input("number", String(cfg.maxLength), (v) => changed({ maxLength: Number(v) })));
      row(host, "Step", input("number", String(cfg.step), (v) => changed({ step: Number(v) })));
      host.appendChild(el("p", "zp-hint", "The base string repeated to each length — for finding length limits, truncation, and buffer-handling bugs."));
      break;
    case "nullPayloads":
      row(host, "How many", input("number", String(cfg.count), (v) => changed({ count: Number(v) })));
      host.appendChild(el("p", "zp-hint", "Sends the base request unchanged this many times (each position gets an empty string) — for rate-limit, lockout, and race testing."));
      break;
    case "customIterator": {
      const slotsHost = el("div");
      host.appendChild(slotsHost);
      const renderSlots = () => {
        slotsHost.textContent = "";
        const slots = getConfig().slots;
        slots.forEach((slot, idx) => {
          slotsHost.appendChild(el("div", "zp-intruder-field-label", `Position ${idx + 1}`));
          const area = document.createElement("textarea");
          area.style.minHeight = "60px";
          area.placeholder = "One item per line";
          area.value = slot.text || "";
          area.addEventListener("input", () => changed({ slots: getConfig().slots.map((s, i) => (i === idx ? { ...s, text: area.value } : s)) }));
          slotsHost.appendChild(area);
          if (idx < slots.length - 1) {
            row(slotsHost, "Separator after", input("text", slot.separator, (v) => changed({ slots: getConfig().slots.map((s, i) => (i === idx ? { ...s, separator: v } : s)) })));
          }
        });
        const buttons = el("div", "zp-toolbar");
        const add = el("button", "zp-btn zp-btn-small", "+ Position");
        add.type = "button";
        add.disabled = slots.length >= 8;
        add.addEventListener("click", () => {
          changed({ slots: [...getConfig().slots, { text: "", separator: "" }] });
          renderSlots();
        });
        const remove = el("button", "zp-btn zp-btn-small", "− Position");
        remove.type = "button";
        remove.disabled = slots.length <= 1;
        remove.addEventListener("click", () => {
          changed({ slots: getConfig().slots.slice(0, -1) });
          renderSlots();
        });
        buttons.append(add, remove);
        slotsHost.appendChild(buttons);
      };
      renderSlots();
      host.appendChild(el("p", "zp-hint", 'Every combination of one item per position, joined by the separators — e.g. usernames, "@", domains. Up to 8 positions (Burp\'s Custom iterator).'));
      break;
    }
    case "regexGenerator": {
      const status = el("p", "zp-hint", "");
      const validate = (v) => {
        try {
          parseRegexTemplate(v);
          status.textContent = "Generates every string matching the pattern. Supports literals, [classes], . \\d \\w \\s, (a|b) groups, and ? * + {n} {n,m} — * and + repeat up to the limit below.";
          status.style.color = "";
        } catch (err) {
          status.textContent = `⚠ ${err.message}`;
          status.style.color = "var(--danger)";
        }
      };
      row(host, "Pattern", input("text", cfg.pattern, (v) => {
        changed({ pattern: v });
        validate(v);
      })).placeholder = "e.g. ORD-[0-9]{4}  or  (admin|root)[0-9]?";
      row(host, "Max * / + repeats", input("number", String(cfg.maxRepeat ?? 3), (v) => changed({ maxRepeat: Number(v) })));
      host.appendChild(status);
      validate(cfg.pattern || "");
      break;
    }
    case "encodingVariants":
      wordsArea(host, cfg, changed, "One payload per line — each is emitted raw, URL, double-URL, URL-all, HTML entities (named, hex, decimal), \\u, \\x, and Base64 encoded");
      host.appendChild(el("p", "zp-hint", "For finding which encoding slips past a WAF or input filter: send the same attack string in every form and compare the responses."));
      break;
    case "illegalUnicode":
      wordsArea(host, cfg, changed, "One payload per line, e.g. ../ or <script>");
      row(host, "Characters to encode", input("text", cfg.targets, (v) => changed({ targets: v }))).placeholder = "empty = every non-alphanumeric character";
      host.appendChild(el("p", "zp-hint", "Rewrites the chosen characters as overlong UTF-8 (%C0%AF for /), %u-encoding, double percent-encoding, and full-width Unicode — forms a lenient decoder turns back into the original but a filter may not recognize."));
      break;
    case "characterFrobber":
      wordsArea(host, cfg, changed, "A token or value per line, e.g. a session ID");
      host.appendChild(el("p", "zp-hint", "Changes one character at a time (its code + 1). Compare responses to see which parts of a token the server actually checks — e.g. a session ID where only the first 8 characters matter."));
      break;
    case "bitFlipper":
      wordsArea(host, cfg, changed, "A value per line — text, or hex bytes with Format = hex");
      row(host, "Format", select([["text", "Text"], ["hex", "Hex bytes"]], cfg.format, (v) => changed({ format: v })));
      host.appendChild(el("p", "zp-hint", "Flips each bit of each byte, one at a time — for probing how encrypted or MAC'd tokens react to tampering (e.g. CBC bit-flipping)."));
      break;
    case "ecbShuffler":
      wordsArea(host, cfg, changed, "ECB ciphertext per line (base64 or hex), e.g. an encrypted cookie");
      row(host, "Format", select([["base64", "Base64"], ["hex", "Hex"]], cfg.format, (v) => changed({ format: v })));
      row(host, "Block size (bytes)", select([["8", "8 (DES/3DES)"], ["16", "16 (AES)"]], String(cfg.blockSize), (v) => changed({ blockSize: Number(v) })));
      host.appendChild(el("p", "zp-hint", "ECB encrypts each block on its own, so blocks can be swapped and still decrypt. Each payload replaces one block with another — useful when a cookie like role=user|admin is ECB-encrypted."));
      break;
    case "ipRange":
      wordsArea(host, cfg, changed, "One per line: 10.0.0.0/24, 192.168.1.1-192.168.1.50, or a single IP");
      host.appendChild(el("p", "zp-hint", "For SSRF targets and IP-based access control (e.g. X-Forwarded-For). IPv4 only."));
      break;
    case "randomStrings":
      row(host, "How many", input("number", String(cfg.count), (v) => changed({ count: Number(v) })));
      row(host, "Length", input("number", String(cfg.length), (v) => changed({ length: Number(v) })));
      row(host, "Characters", select([["hex", "Hex"], ["alphanumeric", "Letters + digits"], ["digits", "Digits"], ["lowercase", "Lowercase"], ["custom", "Custom…"]], cfg.charset, (v) => changed({ charset: v })));
      row(host, "Custom characters", input("text", cfg.custom, (v) => changed({ custom: v })));
      host.appendChild(el("p", "zp-hint", "Fresh random values on every run (cryptographically random) — for cache busting, unique-value constraints, and fuzzing ID formats."));
      break;
    case "uuids":
      row(host, "How many", input("number", String(cfg.count), (v) => changed({ count: Number(v) })));
      host.appendChild(el("p", "zp-hint", "Random version-4 UUIDs, new each run — e.g. to check an endpoint returns 404 (not 403 or data) for objects that don't exist."));
      break;
    default:
      return false;
  }
  if (!["nullPayloads", "charBlocks", "randomStrings", "uuids"].includes(cfg.type)) {
    host.appendChild(el("div", "zp-intruder-field-label", "Sample"));
    refreshSample = samplePreview(host, getConfig);
  }
  return true;
}
