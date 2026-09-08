import { infoIcon } from "../../components/tooltip.js";

// Scope gates every passive capture and every debugger interception —
// fail-closed by design (src/background/scope.js): disabled or empty means
// "see nothing", never "see everything". See docs/THREAT_MODEL.md C2.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function patternList(title, hint, patterns, onChange) {
  const wrap = el("div", "zp-scope-card");
  wrap.appendChild(el("div", "zp-subheading", title));
  wrap.appendChild(el("p", "zp-hint", hint));

  const rows = el("div", "zp-header-rows");
  wrap.appendChild(rows);

  function renderRows() {
    rows.textContent = "";
    if (patterns.length === 0) {
      rows.appendChild(el("div", "zp-empty", "None."));
    }
    patterns.forEach((pattern, idx) => {
      const row = el("div", "zp-header-row");
      row.appendChild(el("span", "zp-mono-small", pattern));
      const delBtn = el("button", "zp-icon-btn", "✕");
      delBtn.type = "button";
      delBtn.addEventListener("click", () => {
        patterns.splice(idx, 1);
        renderRows();
        onChange();
      });
      row.appendChild(delBtn);
      rows.appendChild(row);
    });
  }
  renderRows();

  const addRow = el("div", "zp-form-row");
  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = "example.com or *.example.com";
  const addBtn = el("button", "zp-btn zp-btn-small", "+ Add");
  addBtn.type = "button";
  addBtn.addEventListener("click", () => {
    const value = input.value.trim();
    if (!value) return;
    patterns.push(value);
    input.value = "";
    renderRows();
    onChange();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") addBtn.click();
  });
  addRow.appendChild(input);
  addRow.appendChild(addBtn);
  addRow.appendChild(
    infoIcon("An exact host (example.com) matches only that host. A *.example.com wildcard also matches every subdomain. Press Enter or click + Add.", { label: "About patterns" })
  );
  wrap.appendChild(addRow);

  return wrap;
}

export function renderScope(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Scope"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Only in-scope hosts are ever captured or intercepted. Leaving Scope disabled or empty means ZProxy sees nothing — this fails closed on purpose. Only add hosts you're authorized to test."
    )
  );

  let scope = { enabled: false, include: [], exclude: [] };

  // chrome.webRequest (History's data source) and Intercept both need the
  // <all_urls> host permission granted before they can see anything, even
  // for hosts already listed in Include below — so this is the natural
  // first place to ask for it.
  const hostNotice = el(
    "div",
    "zp-warning",
    "⚠ Without host access, ZProxy can't observe traffic for the hosts below yet — History will stay empty and Intercept won't pause anything."
  );
  const grantBtn = el("button", "zp-btn zp-btn-small", "Grant host access");
  grantBtn.type = "button";
  hostNotice.appendChild(document.createElement("br"));
  hostNotice.appendChild(grantBtn);
  hostNotice.appendChild(
    infoIcon("Requests the optional <all_urls> permission that chrome.webRequest and Intercept both need before they can see traffic for any host, even one already listed below.", { label: "About host access" })
  );
  hostNotice.hidden = true;
  container.appendChild(hostNotice);
  grantBtn.addEventListener("click", async () => {
    await ctx.api("permissions:requestHostAccess");
    hostNotice.hidden = await ctx.api("permissions:hasHostAccess");
  });

  const enabledRow = el("div", "zp-checkbox-row");
  const enabledCheck = document.createElement("input");
  enabledCheck.type = "checkbox";
  enabledCheck.id = "scope-enabled";
  const enabledLabel = document.createElement("label");
  enabledLabel.htmlFor = "scope-enabled";
  enabledLabel.textContent = "Scope enabled";
  enabledRow.appendChild(enabledCheck);
  enabledRow.appendChild(enabledLabel);
  enabledRow.appendChild(
    infoIcon("Master switch for Scope. Off (or on with an empty Include list) means ZProxy captures and intercepts nothing at all — fails closed on purpose.", { label: "About Scope enabled" })
  );
  container.appendChild(enabledRow);

  const listsHost = el("div");
  container.appendChild(listsHost);

  async function save() {
    await ctx.api("scope:save", { scope });
  }

  function renderLists() {
    listsHost.textContent = "";
    listsHost.appendChild(
      patternList(
        "Include",
        "Hosts ZProxy will capture/intercept. Supports exact hosts and *.example.com wildcards.",
        scope.include,
        save
      )
    );
    listsHost.appendChild(
      patternList("Exclude", "Hosts to always skip, even if they match Include (e.g. auth/SSO you don't want to touch).", scope.exclude, save)
    );
  }

  enabledCheck.addEventListener("change", () => {
    scope.enabled = enabledCheck.checked;
    save();
  });

  async function refresh() {
    scope = await ctx.api("scope:get");
    enabledCheck.checked = scope.enabled;
    hostNotice.hidden = await ctx.api("permissions:hasHostAccess");
    renderLists();
  }
  refresh();
}
