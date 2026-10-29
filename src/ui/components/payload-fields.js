// Config fields for Intruder's newer payload types (Fuzz list, Dates, Case
// modification, Character substitution, Username generator, Character
// blocks, Null payloads). The original three types keep their fields in
// views/intruder.js. `update(patch)` merges into the active payload set's
// config and refreshes the payload count.
import { WORDLISTS, WORDLIST_IDS } from "../../intruder/wordlists.js";
import { DATE_FORMATS, DEFAULT_SUBSTITUTIONS, generatePayloads } from "../../intruder/payloads.js";

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
    default:
      return false;
  }
  if (cfg.type !== "nullPayloads" && cfg.type !== "charBlocks") {
    host.appendChild(el("div", "zp-intruder-field-label", "Sample"));
    refreshSample = samplePreview(host, getConfig);
  }
  return true;
}
