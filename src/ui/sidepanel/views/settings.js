import { infoIcon } from "../../components/tooltip.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function renderSettings(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Settings"));
  container.appendChild(el("p", "zp-hint", "Everything here is stored locally (chrome.storage) — nothing leaves the machine. See docs/SECURITY.md."));

  const form = el("div");
  container.appendChild(form);

  let settings = null;

  function labelWithInfo(text, hint) {
    const lbl = el("label", "", text);
    if (hint) lbl.appendChild(infoIcon(hint, { label: `About ${text}` }));
    return lbl;
  }

  function numberRow(label, key, hint) {
    const row = el("div", "zp-form-row");
    row.appendChild(labelWithInfo(label, hint));
    const input = document.createElement("input");
    input.type = "number";
    input.min = "0";
    input.value = settings[key];
    input.addEventListener("change", async () => {
      const value = Number(input.value);
      if (!Number.isFinite(value) || value < 0) return;
      settings = await ctx.api("settings:update", { patch: { [key]: value } });
    });
    row.appendChild(input);
    form.appendChild(row);
  }

  function checkboxRow(label, key, hint) {
    const row = el("div", "zp-checkbox-row");
    const input = document.createElement("input");
    input.type = "checkbox";
    const id = `settings-${key}`;
    input.id = id;
    input.checked = settings[key];
    input.addEventListener("change", async () => {
      settings = await ctx.api("settings:update", { patch: { [key]: input.checked } });
    });
    const lbl = document.createElement("label");
    lbl.htmlFor = id;
    lbl.textContent = label;
    row.appendChild(input);
    row.appendChild(lbl);
    if (hint) row.appendChild(infoIcon(hint, { label: `About ${label}` }));
    form.appendChild(row);
  }

  function selectRow(label, key, options, hint) {
    const row = el("div", "zp-form-row");
    row.appendChild(labelWithInfo(label, hint));
    const select = document.createElement("select");
    for (const opt of options) {
      const optionEl = document.createElement("option");
      optionEl.value = opt.value;
      optionEl.textContent = opt.label;
      select.appendChild(optionEl);
    }
    select.value = settings[key];
    select.addEventListener("change", async () => {
      settings = await ctx.api("settings:update", { patch: { [key]: select.value } });
    });
    row.appendChild(select);
    form.appendChild(row);
  }

  function checkboxSetRow(key, options, hint) {
    const current = new Set(settings[key] || []);
    options.forEach((opt, idx) => {
      const row = el("div", "zp-checkbox-row");
      const input = document.createElement("input");
      input.type = "checkbox";
      const id = `settings-${key}-${opt.value}`;
      input.id = id;
      input.checked = current.has(opt.value);
      input.addEventListener("change", async () => {
        const next = new Set(settings[key] || []);
        if (input.checked) next.add(opt.value);
        else next.delete(opt.value);
        settings = await ctx.api("settings:update", { patch: { [key]: [...next] } });
      });
      const lbl = document.createElement("label");
      lbl.htmlFor = id;
      lbl.textContent = opt.label;
      row.appendChild(input);
      row.appendChild(lbl);
      if (hint && idx === 0) row.appendChild(infoIcon(hint, { label: "About skipped resource types" }));
      form.appendChild(row);
    });
  }

  function shortcutRow(label, key, hint) {
    const row = el("div", "zp-form-row");
    row.appendChild(labelWithInfo(label, hint));
    const input = document.createElement("input");
    input.type = "text";
    input.value = settings.shortcuts[key];
    input.addEventListener("change", async () => {
      settings = await ctx.api("settings:update", { patch: { shortcuts: { ...settings.shortcuts, [key]: input.value } } });
    });
    row.appendChild(input);
    form.appendChild(row);
  }

  async function renderForm() {
    form.textContent = "";

    form.appendChild(el("div", "zp-subheading", "History"));
    numberRow("Max history entries", "maxHistoryEntries", "Oldest entries are dropped once this cap is hit (ring buffer).");
    checkboxRow(
      "Persist history to disk",
      "persistHistoryToDisk",
      "Off by default: history lives in chrome.storage.session (memory-only, cleared on browser restart) to avoid leaving captured traffic — which may include secrets — on disk."
    );
    numberRow("Max body bytes stored per entry", "maxBodyBytesStored", "Larger bodies are truncated before being saved, to keep the UI responsive.");

    form.appendChild(el("div", "zp-subheading", "Interception"));
    selectRow(
      "Intercept",
      "interceptStage",
      [
        { value: "both", label: "Requests and responses" },
        { value: "request", label: "Requests only" },
        { value: "response", label: "Responses only" },
      ],
      "Which stage(s) actually pause at all. A stage left out here never pauses — cheaper than pausing and immediately forwarding it — and content-engine Match/Replace rules scoped to that stage won't run either, since there's nothing paused for them to act on. Applies immediately to any tab Intercept is already attached to, no need to reattach. Also changeable from the Intercept view."
    );
    checkboxRow("Pause intercepted traffic by default", "manualPauseEnabled", "Can also be toggled from the Intercept view. When off, Match/Replace rules still run, but nothing is held for manual review.");
    numberRow("Auto-forward timeout (ms)", "autoForwardTimeoutMs", "Reserved for a future auto-forward-if-untouched safety net.");

    form.appendChild(el("div", "zp-subheading", "Skip intercepting these resource types"));
    checkboxSetRow(
      "excludedResourceTypes",
      [
        { value: "Stylesheet", label: "CSS" },
        { value: "Image", label: "Images" },
        { value: "Font", label: "Fonts" },
        { value: "Media", label: "Media (audio/video)" },
        { value: "Script", label: "Scripts" },
      ],
      "Checked types never pause, so there's nothing to manually forward for them (they still pass through to the page normally, and still show up in History, which is unaffected by this setting). Applies immediately to any tab Intercept is already attached to."
    );

    form.appendChild(el("div", "zp-subheading", "Keyboard shortcuts"));
    form.appendChild(
      el(
        "p",
        "zp-hint",
        'Format: modifiers joined with "+", e.g. "Ctrl+Shift+F" (Cmd on macOS also satisfies "Ctrl"). Forward only does something on Intercept\'s currently selected item; Send to Repeater works from Intercept or History (whichever is showing a selected item); Search focuses History\'s search box. Takes effect within ~5s, no reload needed. Note: a combo the browser itself reserves (Ctrl+R for reload, Ctrl+T for a new tab, ...) never reaches ZProxy at all — pick something Chrome doesn\'t already own.'
      )
    );
    shortcutRow("Forward", "forward");
    shortcutRow("Send to Repeater", "sendToRepeater");
    shortcutRow("Search", "search");
    shortcutRow("Clear history", "clearHistory");
    shortcutRow("Toggle intercept", "toggleIntercept");

    form.appendChild(el("div", "zp-subheading", "Data"));
    const dataRow = el("div", "zp-pending-actions");
    const clearHistoryBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Clear history");
    clearHistoryBtn.type = "button";
    clearHistoryBtn.addEventListener("click", async () => {
      await ctx.api("history:clear");
    });
    const clearCookiesBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Clear all cookies");
    clearCookiesBtn.type = "button";
    clearCookiesBtn.addEventListener("click", async () => {
      if (!window.confirm("Delete every cookie ZProxy can see? This affects real browser sessions, not just captured data.")) return;
      const cookies = await ctx.api("cookies:getAll", {});
      for (const c of cookies) {
        const domain = c.domain.startsWith(".") ? c.domain.slice(1) : c.domain;
        await ctx.api("cookies:remove", { url: `${c.secure ? "https" : "http"}://${domain}${c.path}`, name: c.name });
      }
    });
    const clearRulesBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Clear rules & scope");
    clearRulesBtn.type = "button";
    clearRulesBtn.addEventListener("click", async () => {
      if (!window.confirm("Delete all Match/Replace rules and reset Scope to disabled?")) return;
      await ctx.api("rules:save", { rules: [] });
      await ctx.api("scope:save", { scope: { enabled: false, include: [], exclude: [] } });
    });
    dataRow.appendChild(clearHistoryBtn);
    dataRow.appendChild(clearCookiesBtn);
    dataRow.appendChild(clearRulesBtn);
    dataRow.appendChild(
      infoIcon("Destructive, local-only actions: they delete captured/configured data from this browser but never touch the sites you're testing (aside from removing their cookies, if you use Clear all cookies).", { label: "About these actions" })
    );
    form.appendChild(dataRow);
  }

  async function refresh() {
    settings = await ctx.api("settings:get");
    await renderForm();
  }
  refresh();
}
