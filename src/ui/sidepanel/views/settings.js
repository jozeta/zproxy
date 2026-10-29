import { infoIcon } from "../../components/tooltip.js";
import { applyTheme } from "../../components/theme.js";
import { HIDEABLE_VIEWS } from "../../../utils/nav-visibility.js";
import { scopeIsDefined } from "../../../background/findings-monitor.js";

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
  // Read from the manifest — the single source of truth for the version (see CHANGELOG.md).
  container.appendChild(el("p", "zp-mono-small", `ZProxy version ${chrome.runtime.getManifest().version}`));

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
      if (key === "theme") applyTheme(settings.theme);
    });
    row.appendChild(select);
    form.appendChild(row);
  }

  function checkboxSetRow(key, options, hint, hintLabel = "About skipped resource types") {
    const current = new Set(settings[key] || []);
    options.forEach((opt, idx) => {
      const row = el("div", "zp-checkbox-row");
      const input = document.createElement("input");
      input.type = "checkbox";
      const id = `settings-${key}-${opt.value}`;
      input.id = id;
      input.checked = current.has(opt.value) && !opt.lockedReason;
      // A locked option can't be changed right now; its reason is shown next to it.
      input.disabled = !!opt.lockedReason;
      input.addEventListener("change", async () => {
        const next = new Set(settings[key] || []);
        if (input.checked) next.add(opt.value);
        else next.delete(opt.value);
        settings = await ctx.api("settings:update", { patch: { [key]: [...next] } });
        // app.js redraws the navigation on this — no need to wait for its 5s settings poll.
        if (key === "hiddenViews") window.dispatchEvent(new CustomEvent("zproxy:settings-changed", { detail: settings }));
      });
      const lbl = document.createElement("label");
      lbl.htmlFor = id;
      lbl.textContent = opt.label;
      row.appendChild(input);
      row.appendChild(lbl);
      if (opt.lockedReason) row.appendChild(el("span", "zp-mono-small", opt.lockedReason));
      if (hint && idx === 0) row.appendChild(infoIcon(hint, { label: hintLabel }));
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

    form.appendChild(el("div", "zp-subheading", "Appearance"));
    selectRow(
      "Theme",
      "theme",
      [
        { value: "dark", label: "Polar Night (dark)" },
        { value: "light", label: "Snow Storm (light)" },
        { value: "system", label: "Match system" },
      ],
      "Applies immediately. \"Match system\" follows your operating system's light/dark setting and switches with it."
    );

    // Findings runs (and stays in the nav) whenever Scope has an Include pattern.
    const scopeDefined = scopeIsDefined(await ctx.api("scope:get"));
    form.appendChild(el("div", "zp-subheading", "Hide from navigation"));
    checkboxSetRow(
      "hiddenViews",
      HIDEABLE_VIEWS.map((v) => ({
        value: v.id,
        label: v.label,
        lockedReason: v.id === "findings" && scopeDefined ? "— always shown while a Scope is defined" : null,
      })),
      "Checked views are left out of the side navigation to keep it focused — nothing is disabled. A hidden view still opens when another view sends you there (e.g. History → Send to Decoder), and the Scope badge in the header always opens Scope. Applies immediately.",
      "About hiding views"
    );

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
    checkboxRow(
      "Capture response bodies without Intercept",
      "captureBodiesWithoutIntercept",
      "While a Scope is defined, ZProxy attaches Chrome's debugger in observe-only mode to every tab showing an in-scope page, so History and Findings get response bodies (secrets, SQL errors, reflected input, …) without Intercept — nothing is paused or changed. Chrome shows its \"ZProxy started debugging this browser\" banner while this is active; clicking Cancel on it stops observing that tab until it closes. Turn this off to only capture bodies while Intercept is attached."
    );
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
    const resetSettingsBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Reset settings to defaults");
    resetSettingsBtn.type = "button";
    resetSettingsBtn.addEventListener("click", async () => {
      if (!window.confirm("Reset every setting on this page (including keyboard shortcuts) to its default? Rules, Scope, and History are not affected.")) return;
      const defaults = await ctx.api("settings:reset");
      applyTheme(defaults.theme);
      window.dispatchEvent(new CustomEvent("zproxy:settings-changed", { detail: defaults }));
      await refresh();
    });
    dataRow.appendChild(clearHistoryBtn);
    dataRow.appendChild(clearCookiesBtn);
    dataRow.appendChild(clearRulesBtn);
    dataRow.appendChild(resetSettingsBtn);
    dataRow.appendChild(
      infoIcon("Destructive, local-only actions: they delete captured/configured data from this browser but never touch the sites you're testing (aside from removing their cookies, if you use Clear all cookies). Reset settings only restores this page's options — Rules, Scope, and History are left alone.", { label: "About these actions" })
    );
    form.appendChild(dataRow);
  }

  async function refresh() {
    settings = await ctx.api("settings:get");
    await renderForm();
  }
  refresh();
}
