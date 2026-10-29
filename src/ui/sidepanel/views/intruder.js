// Burp Intruder-style automated attack tool. Sends the same base request
// repeatedly with different payloads substituted into user-marked §...§
// positions, via the same fetch()-from-extension-page mechanism Repeater
// uses (see components/http-send.js for what that can/can't set headers-wise).
// Core logic (marker finding/substitution, payload generation, attack-type
// combination) lives in src/intruder/*.js as pure, unit-tested functions —
// this file is just the UI wired on top of them.
import { createInspector } from "../../components/inspector.js";
import { infoIcon, hideActiveTooltip } from "../../components/tooltip.js";
import { sendRequest } from "../../components/http-send.js";
import { buildMacroEditor } from "../../components/macro-editor.js";
import {
  countPositions,
  clearMarkers,
  clearAllMarkers,
  applyPayloads,
  buildPreviewSegments,
  autoMarkUrl,
  autoMarkHeaders,
  autoMarkBody,
} from "../../../intruder/positions.js";
import { defaultConfig, estimateCount, generatePayloads, DEFAULT_GENERATION_CAP, PAYLOAD_TYPES } from "../../../intruder/payloads.js";
import { renderExtraPayloadFields } from "../../components/payload-fields.js";
import { resultsToCsv } from "../../../intruder/export.js";
import { downloadText } from "../../components/export.js";
import { combine, totalRequestCount, ATTACK_TYPES } from "../../../intruder/combine.js";
import { compileSearchQuery, searchResponse } from "../../../intruder/search.js";
import { defaultMacro, applyMacroValue, extractMacroValue } from "../../../intruder/macro.js";
import { parseHeaderLines } from "../../../parsers/headers.js";
import { PROCESSING_RULE_TYPES, ruleTakesValue, ruleTakesMatch, defaultProcessingRule, applyProcessingRulesToAll } from "../../../intruder/processing.js";
import { findAnomalies, sortResults, SORTABLE_RESULT_KEYS } from "../../../intruder/analysis.js";

// Real requests going out to a real target — these bound how big an attack
// can be before ZProxy makes you stop and think (or refuses outright).
// Burp has no such limit (it's a desktop tool with a resource pool you tune
// yourself); a browser extension sending sequential fetch() calls from a
// UI thread needs a hard backstop instead.
const CONFIRM_THRESHOLD = 100;
const HARD_CAP = 5000;
const MAX_CONCURRENCY = 10;

const METHOD_OPTIONS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function blankFields() {
  return { method: "GET", url: "https://example.com/?id=§1§", headersText: "User-Agent: ZProxy", body: "" };
}

function defaultIntruderState() {
  return {
    fields: blankFields(),
    attackType: "sniper",
    payloadSets: [defaultConfig("simpleList")],
    grepTerms: "",
    searchQuery: "",
    searchMode: "first",
    macro: defaultMacro(),
    delayMs: 0,
    concurrency: 1,
    retries: 0,
    stopOnMatch: false,
    resultsSortKey: null, // null = natural send order
    resultsSortDir: "asc",
    results: [],
    running: false,
    stopRequested: false,
    sentCount: 0,
    currentAbortController: null,
    notify: null,
  };
}

function headerValueFromText(headersText, name) {
  const lower = name.toLowerCase();
  const found = parseHeaderLines(headersText).find((h) => h.name.toLowerCase() === lower);
  return found?.value || "";
}

function addMarkerAtSelection(fieldEl) {
  const start = fieldEl.selectionStart ?? fieldEl.value.length;
  const end = fieldEl.selectionEnd ?? fieldEl.value.length;
  const selected = fieldEl.value.slice(start, end);
  fieldEl.focus();
  fieldEl.setRangeText(`§${selected}§`, start, end, "select");
  fieldEl.dispatchEvent(new Event("input", { bubbles: true }));
}

/** Ensures state.payloadSets has at least `n` entries, growing (never shrinking) with default Simple List configs — so payload text a user already typed for "Position 3" survives a temporary dip in marker count. */
function ensurePayloadSetsLength(state, n) {
  while (state.payloadSets.length < n) state.payloadSets.push(defaultConfig("simpleList"));
}

/** Computes {positionCount, lengths, total} using estimateCount() (never materializing payloads) — safe to call on every keystroke, and correctly reflects an astronomically large or Infinity brute-force config for the pre-attack safety checks. */
function computeTotal(state) {
  const positionCount = countPositions(state.fields);
  if (positionCount === 0) return { positionCount, lengths: [], total: 0 };
  let lengths;
  if (state.attackType === "sniper" || state.attackType === "batteringRam") {
    lengths = [estimateCount(state.payloadSets[0] || defaultConfig("simpleList"))];
  } else {
    ensurePayloadSetsLength(state, positionCount);
    lengths = state.payloadSets.slice(0, positionCount).map((cfg) => estimateCount(cfg));
  }
  const total = totalRequestCount(state.attackType, positionCount, lengths);
  return { positionCount, lengths, total };
}

function formatCount(n) {
  if (n === Infinity) return "an unbounded number of";
  return n.toLocaleString();
}

export function renderIntruder(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Intruder"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Automated attacks: mark payload positions in the request below with §, choose an attack type and payload source, then run it against the target. Every request is sent for real from this extension page — one at a time by default, or several in parallel with Concurrency."
    )
  );

  if (!ctx.sharedState.intruder) ctx.sharedState.intruder = defaultIntruderState();
  const state = ctx.sharedState.intruder;

  if (ctx.sharedState.intruderQueue && ctx.sharedState.intruderQueue.length) {
    const queued = ctx.sharedState.intruderQueue.pop();
    ctx.sharedState.intruderQueue.length = 0;
    if (state.running) {
      window.alert("An Intruder attack is currently running — stop it before loading a new base request.");
    } else if (queued?.request) {
      state.fields = {
        method: queued.request.method || "GET",
        url: clearMarkers(queued.request.url),
        headersText: (queued.request.headers || []).map((h) => `${h.name}: ${h.value}`).join("\n"),
        body: queued.request.body || "",
      };
      state.results = [];
      state.sentCount = 0;
    }
  }

  let activePayloadSetIndex = 0;
  let selectedResultIndex = null;

  // ---------- Base request editor ----------
  const editorToolbar = el("div", "zp-toolbar");
  const autoMarkBtn = el("button", "zp-btn zp-btn-small", "Auto §");
  autoMarkBtn.type = "button";
  const clearMarksBtn = el("button", "zp-btn zp-btn-small", "Clear §");
  clearMarksBtn.type = "button";
  editorToolbar.appendChild(autoMarkBtn);
  editorToolbar.appendChild(clearMarksBtn);
  editorToolbar.appendChild(
    infoIcon(
      "Auto § clears any existing markers and re-marks every detected parameter (URL query values, header values, form/JSON body values). Clear § removes every marker, leaving plain values.",
      { label: "About marking positions" }
    )
  );
  container.appendChild(editorToolbar);

  const line = el("div", "zp-req-line");
  const methodSelect = document.createElement("select");
  for (const m of METHOD_OPTIONS) methodSelect.appendChild(el("option", "", m));
  if (!METHOD_OPTIONS.includes(state.fields.method)) methodSelect.appendChild(el("option", "", state.fields.method));
  methodSelect.value = state.fields.method;
  methodSelect.className = "zp-method-input";
  const urlInput = document.createElement("input");
  urlInput.type = "text";
  urlInput.className = "zp-url-input";
  urlInput.value = state.fields.url;
  const urlMarkBtn = el("button", "zp-btn zp-btn-small", "§");
  urlMarkBtn.type = "button";
  urlMarkBtn.title = "Mark selection in URL";
  line.appendChild(methodSelect);
  line.appendChild(urlInput);
  line.appendChild(urlMarkBtn);
  container.appendChild(line);

  const headersHeading = el("div", "zp-subheading", "Headers (one per line: Name: value)");
  const headersMarkBtn = el("button", "zp-btn zp-btn-small", "§");
  headersMarkBtn.type = "button";
  headersMarkBtn.title = "Mark selection in headers";
  headersHeading.appendChild(headersMarkBtn);
  container.appendChild(headersHeading);
  const headersArea = document.createElement("textarea");
  headersArea.style.minHeight = "80px";
  headersArea.value = state.fields.headersText;
  container.appendChild(headersArea);

  const bodyHeading = el("div", "zp-subheading", "Body");
  const bodyMarkBtn = el("button", "zp-btn zp-btn-small", "§");
  bodyMarkBtn.type = "button";
  bodyMarkBtn.title = "Mark selection in body";
  bodyHeading.appendChild(bodyMarkBtn);
  container.appendChild(bodyHeading);
  const bodyArea = document.createElement("textarea");
  bodyArea.style.minHeight = "70px";
  bodyArea.value = state.fields.body;
  container.appendChild(bodyArea);

  // ---------- Positions preview ----------
  const positionsHeading = el("div", "zp-subheading", "Positions");
  positionsHeading.appendChild(infoIcon("Every §marked§ span becomes a numbered position payloads get substituted into. Unmarked text is sent unchanged.", { label: "About positions" }));
  container.appendChild(positionsHeading);
  const preview = el("div", "zp-intruder-preview");
  container.appendChild(preview);

  // ---------- Attack type ----------
  const attackTypeHeading = el("div", "zp-subheading", "Attack type");
  container.appendChild(attackTypeHeading);
  const attackTypeRow = el("div", "zp-form-row");
  const attackTypeSelect = document.createElement("select");
  for (const t of ATTACK_TYPES) {
    const opt = document.createElement("option");
    opt.value = t.id;
    opt.textContent = t.label;
    attackTypeSelect.appendChild(opt);
  }
  attackTypeSelect.value = state.attackType;
  attackTypeRow.appendChild(attackTypeSelect);
  const attackTypeInfo = infoIcon(ATTACK_TYPES.find((t) => t.id === state.attackType).description, { label: "About this attack type" });
  attackTypeRow.appendChild(attackTypeInfo);
  container.appendChild(attackTypeRow);

  // ---------- Payload sets ----------
  const payloadSetsHeading = el("div", "zp-subheading", "Payload sets");
  container.appendChild(payloadSetsHeading);
  const payloadTabsBar = el("div", "zp-repeater-tabs");
  container.appendChild(payloadTabsBar);
  const payloadConfigHost = el("div");
  container.appendChild(payloadConfigHost);

  // ---------- Grep - Match ----------
  container.appendChild(el("div", "zp-subheading", "Grep - Match"));
  const grepRow = el("div");
  const grepArea = document.createElement("textarea");
  grepArea.style.minHeight = "50px";
  grepArea.placeholder = "One term per line — e.g. \"Invalid password\". Each becomes a ✓/✗ column in the results below.";
  grepArea.value = state.grepTerms;
  grepRow.appendChild(grepArea);
  grepRow.appendChild(
    infoIcon("Checks each response body for these terms and shows the result as an extra column — useful for spotting the one response that's different from the rest (e.g. missing an error message).", {
      label: "About Grep - Match",
    })
  );
  container.appendChild(grepRow);

  // ---------- Search - Extract ----------
  container.appendChild(el("div", "zp-subheading", "Search - Extract"));
  const searchRow = el("div", "zp-form-row");
  const searchInput = document.createElement("input");
  searchInput.type = "text";
  searchInput.placeholder = 'e.g. "<h1>*</h1>" — * = any text, ? = one character';
  searchInput.value = state.searchQuery;
  searchRow.appendChild(searchInput);
  const searchModeSelect = document.createElement("select");
  for (const opt of [
    { value: "first", label: "First match" },
    { value: "all", label: "All matches" },
  ]) {
    const o = document.createElement("option");
    o.value = opt.value;
    o.textContent = opt.label;
    searchModeSelect.appendChild(o);
  }
  searchModeSelect.value = state.searchMode;
  searchRow.appendChild(searchModeSelect);
  searchRow.appendChild(
    infoIcon(
      'Searches each response\'s body and headers (including any cookies the extension can see — a browser restriction hides Set-Cookie from other responses) and shows what it finds as a "Search" column. Plain text matches as a literal substring. Add * (any run of characters) or ? (exactly one character) as wildcards — text on either side anchors the match, and the wildcard-matched portion is what gets extracted, e.g. "<h1>*</h1>" against "<h1>some text</h1>" extracts "some text". Can be set before or after starting the attack; results update live. "All matches" shows a count and the first hit — hover the cell to see every hit.',
      { label: "About Search - Extract" }
    )
  );
  container.appendChild(searchRow);

  // ---------- Session handling macro ----------
  if (!state.macro) state.macro = defaultMacro();
  const macroEditor = buildMacroEditor(state.macro);
  container.appendChild(macroEditor.element);
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "When enabled, this runs before every single attack request — not just once — since the whole point is handling a token that rotates on every response. That roughly doubles how long the attack takes; disable it if your target's token doesn't actually rotate."
    )
  );

  // ---------- Attack settings + run controls ----------
  container.appendChild(el("div", "zp-subheading", "Run"));
  const settingsRow = el("div", "zp-form-row");
  settingsRow.appendChild(el("label", "", "Delay between requests (ms)"));
  const delayInput = document.createElement("input");
  delayInput.type = "number";
  delayInput.min = "0";
  delayInput.value = String(state.delayMs);
  settingsRow.appendChild(delayInput);
  settingsRow.appendChild(infoIcon("Optional pause after each request (per worker when Concurrency > 1). 0 sends as fast as the target responds.", { label: "About delay" }));
  container.appendChild(settingsRow);

  function numberSetting(label, key, min, max, hint) {
    const row = el("div", "zp-form-row");
    row.appendChild(el("label", "", label));
    const input = document.createElement("input");
    input.type = "number";
    input.min = String(min);
    input.max = String(max);
    input.value = String(state[key]);
    input.addEventListener("change", () => {
      const v = Math.trunc(Number(input.value));
      state[key] = Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : min;
      input.value = String(state[key]);
    });
    row.appendChild(input);
    row.appendChild(infoIcon(hint, { label: `About ${label}` }));
    container.appendChild(row);
  }
  numberSetting("Concurrency", "concurrency", 1, MAX_CONCURRENCY, `How many requests are in flight at once (1–${MAX_CONCURRENCY}). Higher is faster but harder on the target and more likely to trip rate limits; a session-handling macro runs per request either way.`);
  numberSetting("Retries on network error", "retries", 0, 5, "Re-sends a request that failed at the network level (connection reset, timeout), up to this many times, before recording it as an error. HTTP error statuses (4xx/5xx) are real responses and are never retried.");

  const stopOnMatchRow = el("div", "zp-checkbox-row");
  const stopOnMatchCheck = document.createElement("input");
  stopOnMatchCheck.type = "checkbox";
  stopOnMatchCheck.id = "intruder-stop-on-match";
  stopOnMatchCheck.checked = state.stopOnMatch;
  stopOnMatchCheck.addEventListener("change", () => (state.stopOnMatch = stopOnMatchCheck.checked));
  const stopOnMatchLabel = el("label", "", "Stop at the first Grep-Match hit");
  stopOnMatchLabel.htmlFor = stopOnMatchCheck.id;
  stopOnMatchRow.appendChild(stopOnMatchCheck);
  stopOnMatchRow.appendChild(stopOnMatchLabel);
  stopOnMatchRow.appendChild(infoIcon("Ends the attack as soon as a response body contains any Grep-Match term — e.g. stop at the first \"Welcome back\" in a credential test instead of sending the rest.", { label: "About stop on match" }));
  container.appendChild(stopOnMatchRow);

  const totalPreview = el("p", "zp-hint", "");
  container.appendChild(totalPreview);

  const runToolbar = el("div", "zp-toolbar");
  const startBtn = el("button", "zp-btn zp-btn-primary zp-btn-small", "Start attack");
  startBtn.type = "button";
  const stopBtn = el("button", "zp-btn zp-btn-danger zp-btn-small", "Stop");
  stopBtn.type = "button";
  const exportCsvBtn = el("button", "zp-btn zp-btn-small", "Export CSV");
  exportCsvBtn.type = "button";
  runToolbar.appendChild(startBtn);
  runToolbar.appendChild(stopBtn);
  runToolbar.appendChild(exportCsvBtn);
  runToolbar.appendChild(infoIcon("Downloads the results table (payloads, status, length, time, Grep-Match hits, errors) as CSV for a spreadsheet or report.", { label: "About Export CSV" }));
  container.appendChild(runToolbar);
  const progressText = el("p", "zp-hint", "");
  container.appendChild(progressText);

  // ---------- Results ----------
  const resultsHeading = el("div", "zp-subheading", "Results");
  resultsHeading.appendChild(
    infoIcon(
      "Click #, Status, Length, or Time (ms) to sort — useful for finding the one response that's different from the rest. A ≠ badge (highlighted row) marks a response whose status or length differs from the majority of this attack's responses, recomputed whenever you sort or the attack finishes (not live during the run, to avoid re-scanning every result on every single request).",
      { label: "About sorting and anomalies" }
    )
  );
  container.appendChild(resultsHeading);
  const resultsWrap = el("div", "zp-split-top");
  resultsWrap.style.maxHeight = "260px";
  const table = document.createElement("table");
  table.className = "zp-table";
  const thead = document.createElement("thead");
  const tbody = document.createElement("tbody");
  table.appendChild(thead);
  table.appendChild(tbody);
  resultsWrap.appendChild(table);
  container.appendChild(resultsWrap);

  const inspectorEmptyMsg = el("div", "zp-empty", "Click a result row to inspect its request/response.");
  container.appendChild(inspectorEmptyMsg);
  const inspector = createInspector();
  inspector.element.hidden = true;
  container.appendChild(inspector.element);

  // ---------- Rendering helpers ----------

  function currentGrepTerms() {
    return (grepArea.value || "").split("\n").map((t) => t.trim()).filter(Boolean);
  }

  /** Runs the current Search - Extract query against a result row's response, live off state.searchQuery/searchMode — never stored on the row, so editing the query before or after an attack re-evaluates every row on the next render. Returns {text, title} for the cell: title carries every hit (for "all" mode's hover tooltip), text is what's shown ("N matches: first" when there's more than one). */
  function searchCell(row) {
    const compiled = compileSearchQuery(state.searchQuery);
    if (!compiled || !row.response) return { text: "", title: "" };
    const matches = searchResponse(row.response, compiled, state.searchMode);
    if (matches.length === 0) return { text: "", title: "" };
    if (matches.length === 1) return { text: matches[0], title: matches[0] };
    return { text: `${matches.length} matches: ${matches[0]}`, title: matches.join("\n") };
  }

  function refreshPreview() {
    preview.textContent = "";
    const segments = buildPreviewSegments(state.fields);
    let currentField = null;
    let fieldLine = null;
    for (const seg of segments) {
      if (seg.field !== currentField) {
        currentField = seg.field;
        const label = el("div", "zp-intruder-field-label", currentField === "url" ? "URL" : currentField === "headersText" ? "Headers" : "Body");
        preview.appendChild(label);
        fieldLine = el("pre", "zp-raw-view");
        fieldLine.style.margin = "0";
        preview.appendChild(fieldLine);
      }
      if (seg.isFieldBreak) continue;
      if (seg.isMarker) {
        const mark = document.createElement("mark");
        mark.className = "zp-intruder-mark";
        mark.textContent = seg.text || "(empty)";
        const badge = document.createElement("sup");
        badge.textContent = String(seg.index);
        mark.appendChild(badge);
        fieldLine.appendChild(mark);
      } else {
        fieldLine.appendChild(document.createTextNode(seg.text));
      }
    }
    positionsHeading.firstChild.textContent = `Positions (${countPositions(state.fields)} marked)`;
  }

  function renderPayloadTabs() {
    payloadTabsBar.textContent = "";
    const multi = state.attackType === "pitchfork" || state.attackType === "clusterBomb";
    const { positionCount } = computeTotal(state);
    const tabCount = multi ? Math.max(positionCount, 1) : 1;
    if (activePayloadSetIndex >= tabCount) activePayloadSetIndex = 0;
    if (!multi) {
      payloadTabsBar.hidden = true;
    } else {
      payloadTabsBar.hidden = false;
      for (let i = 0; i < tabCount; i++) {
        const btn = el("button", "zp-repeater-tab" + (i === activePayloadSetIndex ? " active" : ""), `Position ${i + 1}`);
        btn.type = "button";
        btn.addEventListener("click", () => {
          activePayloadSetIndex = i;
          renderPayloadTabs();
          renderPayloadConfig();
        });
        payloadTabsBar.appendChild(btn);
      }
    }
    renderPayloadConfig();
  }

  function renderPayloadConfig() {
    payloadConfigHost.textContent = "";
    ensurePayloadSetsLength(state, activePayloadSetIndex + 1);
    const config = state.payloadSets[activePayloadSetIndex];

    const typeRow = el("div", "zp-form-row");
    typeRow.appendChild(el("label", "", "Payload type"));
    const typeSelect = document.createElement("select");
    for (const opt of PAYLOAD_TYPES) {
      const o = document.createElement("option");
      o.value = opt.value;
      o.textContent = opt.label;
      typeSelect.appendChild(o);
    }
    typeSelect.value = config.type;
    typeRow.appendChild(typeSelect);
    payloadConfigHost.appendChild(typeRow);

    const fieldsHost = el("div");
    payloadConfigHost.appendChild(fieldsHost);
    const countLabel = el("p", "zp-hint", "");
    payloadConfigHost.appendChild(countLabel);
    const processingHost = el("div");
    payloadConfigHost.appendChild(processingHost);

    function renderProcessingRules() {
      processingHost.textContent = "";
      processingHost.appendChild(el("div", "zp-subheading", "Processing rules (optional)"));
      const cfg = state.payloadSets[activePayloadSetIndex];
      if (!cfg.processingRules) cfg.processingRules = [];
      const rulesHost = el("div", "zp-header-rows");
      processingHost.appendChild(rulesHost);
      cfg.processingRules.forEach((rule, idx) => {
        const row = el("div", "zp-header-row");
        const typeSelectForRule = document.createElement("select");
        for (const opt of PROCESSING_RULE_TYPES) {
          const o = document.createElement("option");
          o.value = opt.value;
          o.textContent = opt.label;
          typeSelectForRule.appendChild(o);
        }
        typeSelectForRule.value = rule.type;
        typeSelectForRule.addEventListener("change", () => {
          cfg.processingRules[idx] = defaultProcessingRule(typeSelectForRule.value);
          renderProcessingRules();
        });
        row.appendChild(typeSelectForRule);
        if (ruleTakesMatch(rule.type)) {
          const matchInput = document.createElement("input");
          matchInput.type = "text";
          matchInput.placeholder = "find";
          matchInput.value = rule.match || "";
          matchInput.addEventListener("input", () => {
            rule.match = matchInput.value;
          });
          row.appendChild(matchInput);
        }
        if (ruleTakesValue(rule.type)) {
          const valueInput = document.createElement("input");
          valueInput.type = "text";
          valueInput.placeholder = rule.type === "replace" ? "replace with" : rule.type === "skipIfMatches" ? "regex" : "text";
          valueInput.value = rule.value || "";
          valueInput.addEventListener("input", () => {
            rule.value = valueInput.value;
          });
          row.appendChild(valueInput);
        }
        const delBtn = el("button", "zp-icon-btn", "✕");
        delBtn.type = "button";
        delBtn.title = "Remove rule";
        delBtn.addEventListener("click", () => {
          cfg.processingRules.splice(idx, 1);
          renderProcessingRules();
        });
        row.appendChild(delBtn);
        rulesHost.appendChild(row);
      });
      const addRuleBtn = el("button", "zp-btn zp-btn-small", "+ Add rule");
      addRuleBtn.type = "button";
      addRuleBtn.addEventListener("click", () => {
        cfg.processingRules.push(defaultProcessingRule(PROCESSING_RULE_TYPES[0].value));
        renderProcessingRules();
      });
      processingHost.appendChild(addRuleBtn);
      processingHost.appendChild(
        infoIcon(
          "Applied to every payload in this set, in order, right before it's substituted into the request — e.g. add a prefix, then Base64-encode. Doesn't change the payload count shown above, only what actually gets sent.",
          { label: "About processing rules" }
        )
      );
    }

    function refreshCount() {
      const n = estimateCount(state.payloadSets[activePayloadSetIndex]);
      countLabel.textContent = `${formatCount(n)} payload${n === 1 ? "" : "s"} in this set.`;
      updateTotalPreview();
    }

    function renderFields() {
      fieldsHost.textContent = "";
      const cfg = state.payloadSets[activePayloadSetIndex];
      if (cfg.type === "simpleList") {
        const area = document.createElement("textarea");
        area.style.minHeight = "90px";
        area.placeholder = "One payload per line";
        area.value = cfg.text || "";
        area.addEventListener("input", () => {
          state.payloadSets[activePayloadSetIndex] = { ...cfg, text: area.value };
          refreshCount();
        });
        fieldsHost.appendChild(area);
        const loadRow = el("div", "zp-toolbar");
        const loadBtn = el("button", "zp-btn zp-btn-small", "Load from file");
        loadBtn.type = "button";
        const fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.accept = "text/plain,.txt,.csv,.lst";
        fileInput.hidden = true;
        loadBtn.addEventListener("click", () => fileInput.click());
        fileInput.addEventListener("change", async () => {
          const file = fileInput.files?.[0];
          fileInput.value = "";
          if (!file) return;
          const text = await file.text();
          area.value = text;
          state.payloadSets[activePayloadSetIndex] = { ...state.payloadSets[activePayloadSetIndex], text };
          refreshCount();
        });
        loadRow.appendChild(loadBtn);
        loadRow.appendChild(fileInput);
        loadRow.appendChild(infoIcon("Replaces the list above with the lines of a text file (one payload per line).", { label: "About Load from file" }));
        fieldsHost.appendChild(loadRow);
      } else if (cfg.type === "numbers") {
        function numRow(label, key, value) {
          const row = el("div", "zp-form-row");
          row.appendChild(el("label", "", label));
          const input = document.createElement("input");
          input.type = "text";
          input.value = value;
          input.addEventListener("input", () => {
            state.payloadSets[activePayloadSetIndex] = { ...state.payloadSets[activePayloadSetIndex], [key]: input.value };
            refreshCount();
          });
          row.appendChild(input);
          fieldsHost.appendChild(row);
        }
        numRow("From", "from", cfg.from);
        numRow("To", "to", cfg.to);
        numRow("Step", "step", cfg.step);
        const formatRow = el("div", "zp-form-row");
        formatRow.appendChild(el("label", "", "Format"));
        const formatSelect = document.createElement("select");
        for (const opt of ["decimal", "hex"]) formatSelect.appendChild(el("option", "", opt));
        formatSelect.value = cfg.format || "decimal";
        formatSelect.addEventListener("change", () => {
          state.payloadSets[activePayloadSetIndex] = { ...state.payloadSets[activePayloadSetIndex], format: formatSelect.value };
          refreshCount();
        });
        formatRow.appendChild(formatSelect);
        fieldsHost.appendChild(formatRow);
        numRow("Zero-pad to length (0 = off)", "padLength", String(cfg.padLength || 0));
      } else if (cfg.type === "bruteForce") {
        const charsetRow = el("div", "zp-form-row");
        charsetRow.appendChild(el("label", "", "Character set"));
        const charsetInput = document.createElement("input");
        charsetInput.type = "text";
        charsetInput.value = cfg.charset || "";
        charsetInput.addEventListener("input", () => {
          state.payloadSets[activePayloadSetIndex] = { ...state.payloadSets[activePayloadSetIndex], charset: charsetInput.value };
          refreshCount();
        });
        charsetRow.appendChild(charsetInput);
        fieldsHost.appendChild(charsetRow);
        function lenRow(label, key, value) {
          const row = el("div", "zp-form-row");
          row.appendChild(el("label", "", label));
          const input = document.createElement("input");
          input.type = "number";
          input.min = "1";
          input.value = String(value);
          input.addEventListener("input", () => {
            state.payloadSets[activePayloadSetIndex] = { ...state.payloadSets[activePayloadSetIndex], [key]: Number(input.value) };
            refreshCount();
          });
          row.appendChild(input);
          fieldsHost.appendChild(row);
        }
        lenRow("Min length", "minLength", cfg.minLength);
        lenRow("Max length", "maxLength", cfg.maxLength);
        fieldsHost.appendChild(
          el("p", "zp-hint", "Exhaustively tries every combination of the character set, from Min length to Max length — grows extremely fast with length. Generation is capped at " + DEFAULT_GENERATION_CAP.toLocaleString() + " payloads per set.")
        );
      } else {
        renderExtraPayloadFields(
          cfg,
          fieldsHost,
          (patch) => {
            state.payloadSets[activePayloadSetIndex] = { ...state.payloadSets[activePayloadSetIndex], ...patch };
            refreshCount();
          },
          () => state.payloadSets[activePayloadSetIndex]
        );
      }
      refreshCount();
    }

    typeSelect.addEventListener("change", () => {
      state.payloadSets[activePayloadSetIndex] = defaultConfig(typeSelect.value);
      renderFields();
    });

    renderFields();
    renderProcessingRules();
  }

  function updateTotalPreview() {
    const { positionCount, total } = computeTotal(state);
    if (positionCount === 0) {
      totalPreview.textContent = "Mark at least one position with § above to configure an attack.";
    } else {
      totalPreview.textContent = `${positionCount} position${positionCount === 1 ? "" : "s"} marked — this attack will send ${formatCount(total)} request${total === 1 ? "" : "s"}.`;
    }
  }

  function onFieldsChanged() {
    state.fields = { method: methodSelect.value, url: urlInput.value, headersText: headersArea.value, body: bodyArea.value };
    refreshPreview();
    renderPayloadTabs();
    updateTotalPreview();
  }

  // ---------- Results table rendering ----------

  const SORT_KEY_BY_LABEL = { "#": "index", Status: "status", Length: "length", "Time (ms)": "timeMs" };

  function renderResultsHeader() {
    thead.textContent = "";
    const headRow = document.createElement("tr");
    for (const label of ["#", "", "Payload(s)", "Status", "Length", "Time (ms)", ...currentGrepTerms(), "Search", "Error"]) {
      const th = el("th", "", label);
      const sortKey = SORT_KEY_BY_LABEL[label];
      if (sortKey) {
        th.style.cursor = "pointer";
        th.title = "Click to sort";
        th.addEventListener("click", () => {
          if (state.resultsSortKey === sortKey) state.resultsSortDir = state.resultsSortDir === "asc" ? "desc" : "asc";
          else {
            state.resultsSortKey = sortKey;
            state.resultsSortDir = "asc";
          }
          renderAllResults();
        });
      }
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
  }

  function payloadPreviewText(tuple) {
    return tuple.map((v) => (v === null || v === undefined ? "·" : v)).join(" | ");
  }

  function appendResultRow(row, isAnomaly = false) {
    const tr = document.createElement("tr");
    tr.className = [row.index === selectedResultIndex ? "selected" : "", isAnomaly ? "zp-intruder-anomaly" : ""].filter(Boolean).join(" ");
    tr.dataset.index = String(row.index);
    tr.addEventListener("click", () => selectResult(row.index));
    tr.appendChild(el("td", "", String(row.index)));
    const anomalyTd = document.createElement("td");
    if (isAnomaly) {
      const badge = el("span", "zp-badge zp-badge-security", "≠");
      badge.title = "This response's status or length differs from the majority of this attack's responses — possibly the one that worked.";
      anomalyTd.appendChild(badge);
    }
    tr.appendChild(anomalyTd);
    tr.appendChild(el("td", "", payloadPreviewText(row.payloads)));
    tr.appendChild(el("td", row.status ? `zp-status-${String(row.status)[0]}` : "", row.status != null ? String(row.status) : ""));
    tr.appendChild(el("td", "", row.length != null ? String(row.length) : ""));
    tr.appendChild(el("td", "", row.timeMs != null ? String(row.timeMs) : ""));
    for (const term of currentGrepTerms()) {
      const matched = row.response && row.response.body && row.response.body.includes(term);
      tr.appendChild(el("td", "", matched ? "✓" : "✗"));
    }
    const search = searchCell(row);
    const searchTd = el("td", "", search.text);
    if (search.title) searchTd.title = search.title;
    tr.appendChild(searchTd);
    const errTd = el("td", "", row.error || "");
    if (row.error) errTd.className = "zp-status-5";
    tr.appendChild(errTd);
    tbody.appendChild(tr);
  }

  /** Full, sorted (if a sort is active), anomaly-highlighted re-render — the only path that recomputes anomalies, since that means re-scanning every result for the current majority status/length. */
  function renderAllResults() {
    renderResultsHeader();
    tbody.textContent = "";
    const rows = state.resultsSortKey ? sortResults(state.results, state.resultsSortKey, state.resultsSortDir) : state.results;
    const anomalies = findAnomalies(state.results);
    for (const row of rows) appendResultRow(row, anomalies.has(row.index));
  }

  function selectResult(index) {
    selectedResultIndex = index;
    const row = state.results.find((r) => r.index === index);
    for (const tr of tbody.querySelectorAll("tr")) tr.classList.remove("selected");
    if (!row) return;
    // Looked up by data-index, not DOM position — the table can be sorted,
    // so "row N" is no longer necessarily the Nth child.
    tbody.querySelector(`tr[data-index="${index}"]`)?.classList.add("selected");
    inspectorEmptyMsg.hidden = true;
    inspector.element.hidden = false;
    inspector.setItem({ request: row.request, response: row.response }, { requestEditable: false, responseEditable: false });
  }

  function updateProgress() {
    const { total } = computeTotal(state);
    if (!state.running && state.sentCount === 0) {
      progressText.textContent = "";
    } else {
      progressText.textContent = `Sent ${state.sentCount}${total ? ` / ${formatCount(total)}` : ""}${state.running ? "…" : state.stoppedOnMatch ? ` (stopped at #${state.stoppedOnMatch}: Grep-Match hit)` : state.stopRequested ? " (stopped)" : " (done)"}`;
    }
    startBtn.disabled = state.running;
    stopBtn.disabled = !state.running;
  }

  // ---------- Wiring ----------

  autoMarkBtn.addEventListener("click", () => {
    const cleared = clearAllMarkers(state.fields);
    const contentType = headerValueFromText(headersArea.value, "Content-Type");
    urlInput.value = autoMarkUrl(cleared.url);
    headersArea.value = autoMarkHeaders(cleared.headersText);
    bodyArea.value = autoMarkBody(cleared.body, contentType);
    onFieldsChanged();
  });
  clearMarksBtn.addEventListener("click", () => {
    const cleared = clearAllMarkers(state.fields);
    urlInput.value = cleared.url;
    headersArea.value = cleared.headersText;
    bodyArea.value = cleared.body;
    onFieldsChanged();
  });
  urlMarkBtn.addEventListener("click", () => {
    addMarkerAtSelection(urlInput);
    onFieldsChanged();
  });
  headersMarkBtn.addEventListener("click", () => {
    addMarkerAtSelection(headersArea);
    onFieldsChanged();
  });
  bodyMarkBtn.addEventListener("click", () => {
    addMarkerAtSelection(bodyArea);
    onFieldsChanged();
  });
  methodSelect.addEventListener("change", onFieldsChanged);
  urlInput.addEventListener("input", onFieldsChanged);
  headersArea.addEventListener("input", onFieldsChanged);
  bodyArea.addEventListener("input", onFieldsChanged);

  attackTypeSelect.addEventListener("change", () => {
    state.attackType = attackTypeSelect.value;
    hideActiveTooltip();
    attackTypeInfo.remove();
    const newInfo = infoIcon(ATTACK_TYPES.find((t) => t.id === state.attackType).description, { label: "About this attack type" });
    attackTypeRow.appendChild(newInfo);
    activePayloadSetIndex = 0;
    renderPayloadTabs();
    updateTotalPreview();
  });

  grepArea.addEventListener("change", () => {
    state.grepTerms = grepArea.value;
    renderAllResults();
  });

  searchInput.addEventListener("input", () => {
    state.searchQuery = searchInput.value;
    renderAllResults();
  });
  searchModeSelect.addEventListener("change", () => {
    state.searchMode = searchModeSelect.value;
    renderAllResults();
  });

  delayInput.addEventListener("change", () => {
    const v = Number(delayInput.value);
    state.delayMs = Number.isFinite(v) && v >= 0 ? v : 0;
  });

  startBtn.addEventListener("click", async () => {
    const { positionCount, total } = computeTotal(state);
    if (positionCount === 0) {
      window.alert("Mark at least one position with § before starting an attack.");
      return;
    }
    if (total === 0) {
      window.alert("Configure at least one payload for every position before starting an attack.");
      return;
    }
    if (total > HARD_CAP) {
      window.alert(`This attack would send ${formatCount(total)} requests, which exceeds ZProxy's safety cap of ${HARD_CAP.toLocaleString()}. Narrow your payload set(s) or switch attack type.`);
      return;
    }
    if (total > CONFIRM_THRESHOLD) {
      let host = "";
      try {
        host = new URL(state.fields.url).host;
      } catch {
        /* invalid URL — caught properly per-request below */
      }
      if (!window.confirm(`This will send ${formatCount(total)} real requests${host ? ` to ${host}` : ""}. Continue?`)) return;
    }
    await runAttack();
  });

  stopBtn.addEventListener("click", () => {
    state.stopRequested = true;
    state.currentAbortController?.abort();
  });

  async function runAttack() {
    state.running = true;
    state.stopRequested = false;
    state.results = [];
    state.sentCount = 0;
    selectedResultIndex = null;
    renderAllResults();
    updateProgress();

    const { positionCount } = computeTotal(state);
    async function buildPayloadSet(cfg) {
      const { payloads } = generatePayloads(cfg, { limit: DEFAULT_GENERATION_CAP });
      return applyProcessingRulesToAll(payloads, cfg.processingRules);
    }
    const setsForRun =
      state.attackType === "sniper" || state.attackType === "batteringRam"
        ? [await buildPayloadSet(state.payloadSets[0] || defaultConfig("simpleList"))]
        : await Promise.all(state.payloadSets.slice(0, positionCount).map((cfg) => buildPayloadSet(cfg)));

    // A pool of `concurrency` workers pulling from ONE shared generator, so
    // every combination is sent exactly once and indexes stay in send order.
    // One AbortController for the whole attack: Stop cancels every in-flight
    // request at once.
    const tuples = combine(state.attackType, setsForRun, positionCount);
    const controller = new AbortController();
    state.currentAbortController = controller;
    const grepTerms = currentGrepTerms();
    const pause = () => (state.delayMs > 0 ? new Promise((resolve) => setTimeout(resolve, state.delayMs)) : null);
    let nextIndex = 0;

    /** Inserts a finished row in index order (workers finish out of order) and tells the mounted view. */
    function record(row) {
      let at = state.results.length;
      while (at > 0 && state.results[at - 1].index > row.index) at--;
      state.results.splice(at, 0, row);
      state.sentCount += 1;
      // Looked up fresh (not the closure's own appendResultRow/updateProgress)
      // because this loop keeps running even if the user navigates away and
      // back mid-attack — renderIntruder tears down and rebuilds this view's
      // DOM on every navigation, so "the currently mounted view" is whatever
      // the latest render pointed state.notify at, not necessarily this one.
      state.notify?.(row);
      if (state.stopOnMatch && row.response && grepTerms.some((t) => row.response.body.includes(t))) {
        state.stopRequested = true;
        state.stoppedOnMatch = row.index;
        controller.abort();
      }
    }

    async function worker() {
      while (!state.stopRequested) {
        const next = tuples.next();
        if (next.done) return;
        await sendOne(next.value, ++nextIndex);
        await pause();
      }
    }

    async function sendOne(tuple, index) {
      let built = applyPayloads(state.fields, tuple);

      if (state.macro?.enabled) {
        // Run fresh before every single request, not just once — a rotating
        // CSRF/session token is exactly the case this exists for, and a
        // value extracted once would go stale after request #1 just like an
        // unassisted attack does. See the cost note next to the macro editor.
        const macroRequest = {
          method: state.macro.method,
          url: state.macro.url,
          httpVersion: "HTTP/1.1",
          headers: parseHeaderLines(state.macro.headersText),
          body: state.macro.body,
        };
        const macroResult = await sendRequest(macroRequest, { signal: controller.signal });
        if (macroResult.aborted) return;
        if (!macroResult.ok) {
          record({ index, payloads: tuple, request: null, response: null, status: null, length: null, timeMs: null, error: `Session handling macro failed: ${macroResult.error}` });
          return;
        }
        const macroValue = extractMacroValue(macroResult.response, state.macro.extractQuery);
        if (macroValue == null) {
          record({ index, payloads: tuple, request: null, response: null, status: null, length: null, timeMs: null, error: "Session handling macro ran, but its Extract value query found no match." });
          return;
        }
        built = applyMacroValue(built, macroValue);
      }

      const request = {
        method: state.fields.method,
        url: built.url,
        httpVersion: "HTTP/1.1",
        headers: parseHeaderLines(built.headersText),
        body: built.body,
      };
      let result = await sendRequest(request, { signal: controller.signal });
      // Network-level failures only — an HTTP 4xx/5xx is a real answer, never retried.
      for (let attempt = 0; attempt < (state.retries ?? 0) && !result.ok && !result.aborted; attempt++) {
        result = await sendRequest(request, { signal: controller.signal });
      }
      if (result.aborted) return;
      record({
        index,
        payloads: tuple,
        request,
        response: result.ok ? result.response : null,
        status: result.ok ? result.response.statusCode : null,
        length: result.ok ? result.response.body.length : null,
        timeMs: result.ok ? result.response.durationMs : null,
        error: result.ok ? null : result.error,
      });
    }

    state.stoppedOnMatch = null;
    const workerCount = Math.max(1, Math.min(MAX_CONCURRENCY, state.concurrency ?? 1));
    await Promise.all(Array.from({ length: workerCount }, worker));
    state.running = false;
    state.currentAbortController = null;
    state.notify?.();
  }

  exportCsvBtn.addEventListener("click", async () => {
    if (!state.results.length) return;
    const csv = resultsToCsv(state.results, currentGrepTerms());
    await downloadText(`zproxy-intruder-${Date.now()}.csv`, csv, "text/csv");
  });

  // A stable reference so cleanup can tell "is state.notify still mine?"
  // rather than blindly nulling it out from under a newer mount. A live row
  // during a running attack is a cheap append UNLESS a sort is active (a
  // plain append would land at the wrong position once sorted, and
  // anomalies are only recomputed on a full render — see renderAllResults);
  // the no-row call at the very end of an attack always does the full,
  // sorted, anomaly-highlighted render regardless.
  const myNotify = (row) => {
    if (row) {
      // A plain append is only right when the row landed last — with
      // Concurrency > 1 a lower-index request can finish after a higher one.
      if (state.resultsSortKey || state.results[state.results.length - 1] !== row) renderAllResults();
      else appendResultRow(row);
    } else {
      renderAllResults();
    }
    updateProgress();
  };
  state.notify = myNotify;

  // ---------- Initial render ----------
  refreshPreview();
  renderPayloadTabs();
  updateTotalPreview();
  renderAllResults();
  updateProgress();

  return () => {
    if (state.notify === myNotify) state.notify = null;
    hideActiveTooltip();
  };
}
