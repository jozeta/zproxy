import { infoIcon } from "../../components/tooltip.js";
import { domainScopePattern, addPatternToScope } from "../../../background/scope.js";

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
  input.placeholder = "example.com, *.example.com, https://example.com:8443/api/";
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
    infoIcon(
      "Format: [scheme://]host[:port][/path]. Only the host is required. An exact host (example.com) matches only that host; *.example.com also matches every subdomain. Add a scheme (https://) or port (:8443) to require it, and/or a path to match only URLs whose path starts with it — * is a wildcard, and ending a path with / stops it at a segment (\"/api/\" matches /api/users but not /apifoo). Static Match & Replace rules can only use host-only patterns: a scheme/port/path-restricted Include gives them nothing, and such an Exclude is ignored by them. Press Enter or click + Add.",
      { label: "About patterns" }
    )
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

  // "Add current site": the active tab's registrable domain as a wildcard
  // (domainScopePattern), so one click covers the site and all subdomains.
  // The button label always shows the exact pattern before it's added.
  const siteRow = el("div", "zp-pending-actions");
  const addSiteBtn = el("button", "zp-btn zp-btn-primary zp-btn-small", "Add current site");
  addSiteBtn.type = "button";
  addSiteBtn.disabled = true;
  const siteStatus = el("span", "zp-mono-small", "");
  siteRow.appendChild(addSiteBtn);
  siteRow.appendChild(
    infoIcon(
      "Adds the active tab's domain with every subdomain — e.g. on app.shop.example.com it adds *.example.com, which matches example.com, shop.example.com, api.example.com, and so on — and switches Scope on. Country domains are handled (shop.example.co.uk → *.example.co.uk), and IP addresses or localhost are added exactly. Only add sites you're authorized to test.",
      { label: "About Add current site" }
    )
  );
  siteRow.appendChild(siteStatus);
  container.appendChild(siteRow);
  let sitePattern = null;

  async function refreshSiteButton() {
    const tab = await ctx.api("tabs:current").catch(() => null);
    let url = null;
    try {
      url = tab?.url ? new URL(tab.url) : null;
    } catch {
      /* unparseable — treated like a non-web page below */
    }
    sitePattern = url && ["http:", "https:"].includes(url.protocol) ? domainScopePattern(url.hostname) : null;
    addSiteBtn.disabled = !sitePattern;
    addSiteBtn.textContent = sitePattern ? `Add current site (${sitePattern})` : "Add current site";
    addSiteBtn.title = sitePattern ? "" : "The active tab isn't a website (http/https) — switch to the site you want to test.";
    if (sitePattern && scope.include.some((p) => p.trim().toLowerCase() === sitePattern)) {
      addSiteBtn.disabled = true;
      siteStatus.textContent = "Already in Scope.";
    } else {
      siteStatus.textContent = "";
    }
  }

  addSiteBtn.addEventListener("click", async () => {
    if (!sitePattern) return;
    if (!(await ctx.api("permissions:hasHostAccess"))) {
      const granted = await ctx.api("permissions:requestHostAccess");
      if (!granted) {
        siteStatus.textContent = "Host access is needed before ZProxy can see this site.";
        return;
      }
    }
    scope = addPatternToScope(scope, sitePattern);
    await save();
    enabledCheck.checked = scope.enabled;
    hostNotice.hidden = await ctx.api("permissions:hasHostAccess");
    renderLists();
    await refreshSiteButton();
    siteStatus.textContent = `Added ${sitePattern} — the site and all its subdomains are now in Scope.`;
  });

  const listsHost = el("div");
  container.appendChild(listsHost);

  async function save() {
    await ctx.api("scope:save", { scope });
    refreshSiteButton();
  }

  function renderLists() {
    listsHost.textContent = "";
    listsHost.appendChild(
      patternList(
        "Include",
        "Hosts (optionally narrowed to a scheme, port, or path) ZProxy will capture/intercept, e.g. *.example.com or example.com/api/.",
        scope.include,
        save
      )
    );
    listsHost.appendChild(
      patternList("Exclude", "Hosts or paths to always skip, even if they match Include (e.g. auth/SSO you don't want to touch, or example.com/logout).", scope.exclude, save)
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
    await refreshSiteButton();
  }
  refresh();
}
