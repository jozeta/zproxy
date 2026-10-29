// Rule editor for both engines (see src/interception/match-replace.js and
// src/background/dnr-rules.js for what each can actually do):
//  - "static"  = declarativeNetRequest-backed. Works with no debugger
//    attached, but can only unconditionally SET/remove a header or redirect
//    a URL — never conditioned on the current header/body content.
//  - "content" = debugger-backed substring/regex find-and-replace against
//    the real header/body bytes. Only runs while Intercept is attached.
import { downloadText } from "../../components/export.js";
import { infoIcon } from "../../components/tooltip.js";
import { coalesced } from "../../components/history-feed.js";
import { testRule } from "../../../interception/match-replace.js";
import { MATCH_REPLACE_PRESETS } from "../../../interception/match-replace-presets.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function uid() {
  return `rule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function defaultRule() {
  return {
    id: uid(),
    name: "New rule",
    enabled: true,
    engine: "content",
    scope: "request",
    location: "header",
    headerName: "",
    matchType: "contains",
    match: "",
    replace: "",
    urlFilter: "",
    staticAction: "set",
    staticValue: "",
  };
}

function selectField(label, value, options, onChange, info) {
  const row = el("div", "zp-form-row");
  const labelEl = el("label", "", label);
  if (info) labelEl.appendChild(infoIcon(info, { label: `About ${label}` }));
  row.appendChild(labelEl);
  const select = document.createElement("select");
  for (const opt of options) select.appendChild(el("option", "", opt));
  select.value = value;
  select.addEventListener("change", () => onChange(select.value));
  row.appendChild(select);
  return { element: row, select };
}

function textField(label, value, placeholder, onChange, info) {
  const row = el("div", "zp-form-row");
  const labelEl = el("label", "", label);
  if (info) labelEl.appendChild(infoIcon(info, { label: `About ${label}` }));
  row.appendChild(labelEl);
  const input = document.createElement("input");
  input.type = "text";
  input.value = value || "";
  if (placeholder) input.placeholder = placeholder;
  input.addEventListener("input", () => onChange(input.value));
  row.appendChild(input);
  return { element: row, input };
}

export function renderMatchReplace(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Match & Replace"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "“Static” rules run always (via declarativeNetRequest) but can only set/remove a header or redirect a URL. “Content” rules do real substring/regex find-and-replace on header or body text, but only while Intercept is attached to the tab."
    )
  );

  let rules = [];

  const toolbar = el("div", "zp-toolbar");
  const addBtn = el("button", "zp-btn zp-btn-primary zp-btn-small", "+ New rule");
  addBtn.type = "button";
  const importBtn = el("button", "zp-btn zp-btn-small", "Import");
  importBtn.type = "button";
  const exportBtn = el("button", "zp-btn zp-btn-small", "Export");
  exportBtn.type = "button";
  const fileInput = document.createElement("input");
  fileInput.type = "file";
  fileInput.accept = "application/json";
  fileInput.hidden = true;
  toolbar.appendChild(addBtn);
  toolbar.appendChild(infoIcon("Adds a blank rule below, defaulted to the \"content\" engine (works only while Intercept is attached).", { label: "About New rule" }));
  toolbar.appendChild(importBtn);
  toolbar.appendChild(exportBtn);
  toolbar.appendChild(
    infoIcon("Import merges a JSON array of rules (e.g. from examples/match-replace-rules/) into the current list. Export downloads the current list as JSON.", { label: "About Import & Export" })
  );
  toolbar.appendChild(fileInput);
  container.appendChild(toolbar);

  const toolbar2 = el("div", "zp-toolbar");
  const presetSelect = document.createElement("select");
  const presetPlaceholder = el("option", "", "Add a preset…");
  presetPlaceholder.value = "";
  presetSelect.appendChild(presetPlaceholder);
  for (const preset of MATCH_REPLACE_PRESETS) {
    const o = el("option", "", preset.label);
    o.value = preset.id;
    presetSelect.appendChild(o);
  }
  const enableAllBtn = el("button", "zp-btn zp-btn-small", "Enable all");
  enableAllBtn.type = "button";
  const disableAllBtn = el("button", "zp-btn zp-btn-small", "Disable all");
  disableAllBtn.type = "button";
  const filterInput = document.createElement("input");
  filterInput.type = "search";
  filterInput.className = "zp-search-input";
  filterInput.placeholder = "Filter rules by name, header, or pattern…";
  toolbar2.appendChild(presetSelect);
  toolbar2.appendChild(infoIcon("Common rewrites, ready to use — IP spoofing, CORS Origin, stripping CSP/X-Frame-Options, revealing hidden fields, flipping an isAdmin flag, … Presets are added switched OFF: review, then tick the checkbox to enable.", { label: "About presets" }));
  toolbar2.appendChild(enableAllBtn);
  toolbar2.appendChild(disableAllBtn);
  toolbar2.appendChild(filterInput);
  container.appendChild(toolbar2);

  const list = el("div");
  container.appendChild(list);

  // The tester's sample text (rule._sample) is view-only and may hold real
  // tokens pasted from traffic — it is never saved or exported.
  const withoutTransient = (list) => list.map(({ _sample, ...rule }) => rule);

  async function persist() {
    await ctx.api("rules:save", { rules: withoutTransient(rules) });
  }
  // Text fields save as you type — debounced, since every save also rebuilds
  // the declarativeNetRequest rule set in the service worker.
  const persistSoon = coalesced(() => persist().catch(() => {}), 400);

  function ruleCard(rule) {
    const card = el("div", rule.enabled ? "zp-rule-card" : "zp-rule-card disabled");

    const headRow = el("div", "zp-form-row");
    const enabledCheck = document.createElement("input");
    enabledCheck.type = "checkbox";
    enabledCheck.checked = rule.enabled;
    enabledCheck.addEventListener("change", async () => {
      rule.enabled = enabledCheck.checked;
      card.classList.toggle("disabled", !rule.enabled);
      await persist();
    });
    headRow.appendChild(enabledCheck);
    headRow.appendChild(infoIcon("Unchecking disables this rule without deleting it — it stops applying, static (DNR) or content, until re-enabled.", { label: "About enabled" }));

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.value = rule.name;
    nameInput.style.flex = "1";
    nameInput.addEventListener("input", async () => {
      rule.name = nameInput.value;
      persistSoon();
    });
    headRow.appendChild(nameInput);

    const index = rules.indexOf(rule);
    for (const [label, title, action] of [
      ["↑", "Move up — rules apply top to bottom", () => move(index, -1)],
      ["↓", "Move down", () => move(index, 1)],
      ["Duplicate", "Copy this rule (added switched off, right below)", () => duplicate(rule)],
    ]) {
      const b = el("button", "zp-btn zp-btn-small", label);
      b.type = "button";
      b.title = title;
      b.addEventListener("click", action);
      headRow.appendChild(b);
    }

    const delBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Delete");
    delBtn.type = "button";
    delBtn.addEventListener("click", async () => {
      rules = rules.filter((r) => r.id !== rule.id);
      await persist();
      renderList();
    });
    headRow.appendChild(delBtn);
    card.appendChild(headRow);

    const engine = selectField(
      "Engine",
      rule.engine,
      ["static", "content"],
      async (v) => {
        rule.engine = v;
        persistSoon();
        renderList();
      },
      "\"static\" (declarativeNetRequest) runs always, no debugger needed, but can only unconditionally set/remove a header or redirect a URL. \"content\" does real find-and-replace on header/body text, but only while Intercept is attached."
    );
    card.appendChild(engine.element);

    const scope = selectField(
      "Applies to",
      rule.scope,
      ["request", "response"],
      async (v) => {
        rule.scope = v;
        persistSoon();
      },
      "Whether this rule acts on the outgoing request or the incoming response."
    );
    card.appendChild(scope.element);

    const locationOptions = rule.engine === "static" ? ["header", "url"] : ["header", "url", "body"];
    if (!locationOptions.includes(rule.location)) rule.location = locationOptions[0];
    const location = selectField(
      "Location",
      rule.location,
      locationOptions,
      async (v) => {
        rule.location = v;
        persistSoon();
        renderList();
      },
      "What part of the request/response this rule touches — a single header, the URL, or (content engine only) the body."
    );
    card.appendChild(location.element);

    if (rule.location === "header") {
      const headerName = textField(
        "Header name",
        rule.headerName,
        "e.g. Authorization",
        async (v) => {
          rule.headerName = v;
          persistSoon();
        },
        "Case-insensitive header name this rule reads/writes."
      );
      card.appendChild(headerName.element);
    }

    if (rule.engine === "static") {
      const urlFilter = textField(
        "URL filter (optional)",
        rule.urlFilter,
        "substring or /regex/, blank = all URLs",
        async (v) => {
          rule.urlFilter = v;
          persistSoon();
        },
        "Restricts this rule to matching URLs. Wrap in slashes for a regex (/pattern/), otherwise it's treated as a plain substring. Leave blank to match every URL."
      );
      card.appendChild(urlFilter.element);

      if (rule.location === "header") {
        const action = selectField(
          "Action",
          rule.staticAction,
          ["set", "remove"],
          async (v) => {
            rule.staticAction = v;
            persistSoon();
            renderList();
          },
          "\"set\" always overwrites the header to a fixed value; \"remove\" strips it entirely. Neither can look at the header's current value — that needs the content engine instead."
        );
        card.appendChild(action.element);
        if (rule.staticAction === "set") {
          const value = textField(
            "Set value",
            rule.staticValue,
            "",
            async (v) => {
              rule.staticValue = v;
              persistSoon();
            },
            "The fixed value this header is unconditionally set to."
          );
          card.appendChild(value.element);
        }
      } else {
        const value = textField(
          "Redirect to",
          rule.staticValue,
          "https://...",
          async (v) => {
            rule.staticValue = v;
            persistSoon();
          },
          "The destination URL every matching request is redirected to."
        );
        card.appendChild(value.element);
        card.appendChild(el("p", "zp-hint", "URL location rules require a URL filter above matching the original request, or every navigation will redirect here."));
      }
    } else {
      const matchType = selectField(
        "Match type",
        rule.matchType,
        ["contains", "regex"],
        async (v) => {
          rule.matchType = v;
          persistSoon();
        },
        "\"contains\" does a plain substring match; \"regex\" treats Match as a regular expression (no surrounding slashes)."
      );
      card.appendChild(matchType.element);
      const match = textField(
        "Match",
        rule.match,
        rule.matchType === "regex" ? "pattern (no slashes)" : "substring",
        async (v) => {
          rule.match = v;
          persistSoon();
        },
        "Text (or regex pattern) to find in the header/body/URL bytes while Intercept is attached."
      );
      card.appendChild(match.element);
      const replace = textField(
        "Replace with",
        rule.replace,
        "",
        async (v) => {
          rule.replace = v;
          persistSoon();
        },
        "Text every match is replaced with. Leave blank to delete the matched text."
      );
      card.appendChild(replace.element);
    }

    if (rule.engine === "content") card.appendChild(ruleTester(rule, card));
    return card;
  }

  /** Live preview of a content rule on sample text — the same engine code live traffic goes through. */
  function ruleTester(rule, card) {
    const box = document.createElement("details");
    box.className = "zp-rule-tester";
    const summary = el("summary", "zp-mono-small", "Test this rule");
    box.appendChild(summary);
    const sample = document.createElement("textarea");
    sample.style.minHeight = "60px";
    sample.placeholder = "Paste sample text (a header value, URL, or body) to see what this rule does to it…";
    sample.value = rule._sample || "";
    const status = el("div", "zp-mono-small", "");
    const output = el("pre", "zp-raw-view zp-intruder-preview");
    box.append(sample, status, output);
    function run() {
      rule._sample = sample.value;
      if (!sample.value) {
        status.textContent = "";
        output.textContent = "";
        return;
      }
      const result = testRule(rule, sample.value);
      status.textContent = result.error ? `⚠ Invalid regex: ${result.error} — this rule currently does nothing.` : `${result.matches} match${result.matches === 1 ? "" : "es"}`;
      status.style.color = result.error ? "var(--danger)" : "";
      output.textContent = result.output;
    }
    sample.addEventListener("input", run);
    // Re-run when any of the rule's own fields change.
    card.addEventListener("input", (e) => e.target !== sample && run());
    card.addEventListener("change", (e) => e.target !== sample && run());
    run();
    return box;
  }

  function move(index, delta) {
    const target = index + delta;
    if (target < 0 || target >= rules.length) return;
    [rules[index], rules[target]] = [rules[target], rules[index]];
    persist();
    renderList();
  }

  function duplicate(rule) {
    const { _sample, ...rest } = rule;
    const copy = { ...structuredClone(rest), id: uid(), name: `${rule.name} (copy)`, enabled: false };
    rules.splice(rules.indexOf(rule) + 1, 0, copy);
    persist();
    renderList();
  }

  function matchesFilter(rule, q) {
    if (!q) return true;
    const needle = q.toLowerCase();
    return [rule.name, rule.headerName, rule.match, rule.replace, rule.staticValue, rule.urlFilter].some((v) => (v || "").toLowerCase().includes(needle));
  }

  function renderList() {
    list.textContent = "";
    if (rules.length === 0) {
      list.appendChild(el("div", "zp-empty", "No rules yet. Add one, pick a preset above, or Import an example set from examples/match-replace-rules/."));
      return;
    }
    const visible = rules.filter((r) => matchesFilter(r, filterInput.value));
    if (visible.length === 0) list.appendChild(el("div", "zp-empty", "No rules match the filter."));
    for (const rule of visible) list.appendChild(ruleCard(rule));
  }

  filterInput.addEventListener("input", renderList);

  presetSelect.addEventListener("change", async () => {
    const preset = MATCH_REPLACE_PRESETS.find((p) => p.id === presetSelect.value);
    presetSelect.value = "";
    if (!preset) return;
    rules.push({ ...defaultRule(), ...structuredClone(preset.rule), enabled: false });
    await persist();
    renderList();
    list.lastElementChild?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  });

  for (const [btn, enabled] of [
    [enableAllBtn, true],
    [disableAllBtn, false],
  ]) {
    btn.addEventListener("click", async () => {
      for (const r of rules) r.enabled = enabled;
      await persist();
      renderList();
    });
  }

  addBtn.addEventListener("click", async () => {
    rules.push(defaultRule());
    await persist();
    renderList();
  });

  exportBtn.addEventListener("click", async () => {
    await downloadText(`zproxy-rules-${Date.now()}.json`, JSON.stringify(withoutTransient(rules), null, 2), "application/json");
  });

  importBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    fileInput.value = "";
    if (!file) return;
    try {
      const text = await file.text();
      const imported = JSON.parse(text);
      if (!Array.isArray(imported)) throw new Error("Expected a JSON array of rules.");
      for (const r of imported) if (!r.id) r.id = uid();
      rules = [...rules, ...imported];
      await persist();
      renderList();
    } catch (err) {
      window.alert(`Could not import rules: ${err.message}`);
    }
  });

  async function refresh() {
    rules = await ctx.api("rules:get");
    renderList();
  }
  refresh();
}
