// Rule editor for both engines (see src/interception/match-replace.js and
// src/background/dnr-rules.js for what each can actually do):
//  - "static"  = declarativeNetRequest-backed. Works with no debugger
//    attached, but can only unconditionally SET/remove a header or redirect
//    a URL — never conditioned on the current header/body content.
//  - "content" = debugger-backed substring/regex find-and-replace against
//    the real header/body bytes. Only runs while Intercept is attached.
import { downloadText } from "../../components/export.js";
import { infoIcon } from "../../components/tooltip.js";

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

  const list = el("div");
  container.appendChild(list);

  async function persist() {
    await ctx.api("rules:save", { rules });
  }

  function ruleCard(rule) {
    const card = el("div", "zp-rule-card");

    const headRow = el("div", "zp-form-row");
    const enabledCheck = document.createElement("input");
    enabledCheck.type = "checkbox";
    enabledCheck.checked = rule.enabled;
    enabledCheck.addEventListener("change", async () => {
      rule.enabled = enabledCheck.checked;
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
      await persist();
    });
    headRow.appendChild(nameInput);

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
        await persist();
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
        await persist();
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
        await persist();
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
          await persist();
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
          await persist();
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
            await persist();
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
              await persist();
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
            await persist();
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
          await persist();
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
          await persist();
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
          await persist();
        },
        "Text every match is replaced with. Leave blank to delete the matched text."
      );
      card.appendChild(replace.element);
    }

    return card;
  }

  function renderList() {
    list.textContent = "";
    if (rules.length === 0) {
      list.appendChild(el("div", "zp-empty", "No rules yet. Add one, or Import an example set from examples/match-replace-rules/."));
      return;
    }
    for (const rule of rules) list.appendChild(ruleCard(rule));
  }

  addBtn.addEventListener("click", async () => {
    rules.push(defaultRule());
    await persist();
    renderList();
  });

  exportBtn.addEventListener("click", async () => {
    await downloadText(`zproxy-rules-${Date.now()}.json`, JSON.stringify(rules, null, 2), "application/json");
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
