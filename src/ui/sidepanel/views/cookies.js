import { infoIcon } from "../../components/tooltip.js";

// Full cookie CRUD via chrome.cookies. Reading/writing a cookie for a given
// domain requires host permission for that domain (see docs/CAPABILITIES.md)
// — with the optional <all_urls> permission granted (same one Intercept and
// Repeater use) this covers every domain; without it, only cookies for
// origins the extension already has access to are visible.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function cookieUrl(c) {
  const domain = c.domain.startsWith(".") ? c.domain.slice(1) : c.domain;
  return `${c.secure ? "https" : "http"}://${domain}${c.path || "/"}`;
}

function formatExpiration(c) {
  if (c.session) return "Session";
  if (!c.expirationDate) return "";
  return new Date(c.expirationDate * 1000).toLocaleString();
}

export function renderCookies(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Cookies"));
  container.appendChild(el("p", "zp-hint", "Full read/write access to the browser's cookie jar. Changes take effect immediately."));

  const hostNotice = el("div", "zp-warning", "⚠ Without host access, only cookies for a few already-accessible origins are visible.");
  const grantBtn = el("button", "zp-btn zp-btn-small", "Grant host access");
  grantBtn.type = "button";
  hostNotice.appendChild(document.createElement("br"));
  hostNotice.appendChild(grantBtn);
  hostNotice.appendChild(
    infoIcon("Requests the optional <all_urls> permission so ZProxy can read/write cookies for every domain, not just a few already-accessible origins.", { label: "About host access" })
  );
  hostNotice.hidden = true;
  container.appendChild(hostNotice);

  const toolbar = el("div", "zp-toolbar");
  const searchInput = document.createElement("input");
  searchInput.type = "text";
  searchInput.className = "zp-search-input";
  searchInput.placeholder = "Filter by domain, name, or value…";
  const addBtn = el("button", "zp-btn zp-btn-small", "+ Add cookie");
  addBtn.type = "button";
  toolbar.appendChild(searchInput);
  toolbar.appendChild(infoIcon("Filters the list below by domain, name, or value — doesn't change or delete anything.", { label: "About search" }));
  toolbar.appendChild(addBtn);
  toolbar.appendChild(infoIcon("Opens a blank cookie form. Saving writes it to the browser's real cookie jar immediately.", { label: "About Add cookie" }));
  container.appendChild(toolbar);

  const formHost = el("div");
  container.appendChild(formHost);

  const list = el("div", "zp-cookie-list");
  container.appendChild(list);

  let cookies = [];
  let search = "";

  function fieldRow(labelText, inputEl, info) {
    const row = el("div", "zp-form-row");
    const label = el("label", "", labelText);
    if (info) label.appendChild(infoIcon(info, { label: `About ${labelText}` }));
    row.appendChild(label);
    row.appendChild(inputEl);
    return row;
  }

  function buildForm(existing, onCancel) {
    formHost.textContent = "";
    const card = el("div", "zp-cookie-card");

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.value = existing?.name || "";
    nameInput.placeholder = "session_id";

    const valueInput = document.createElement("input");
    valueInput.type = "text";
    valueInput.value = existing?.value || "";

    const domainInput = document.createElement("input");
    domainInput.type = "text";
    domainInput.value = existing?.domain || "";
    domainInput.placeholder = "example.com or .example.com";

    const pathInput = document.createElement("input");
    pathInput.type = "text";
    pathInput.value = existing?.path || "/";

    const sameSiteSelect = document.createElement("select");
    for (const opt of ["unspecified", "no_restriction", "lax", "strict"]) sameSiteSelect.appendChild(el("option", "", opt));
    sameSiteSelect.value = existing?.sameSite || "lax";

    const secureCheck = document.createElement("input");
    secureCheck.type = "checkbox";
    secureCheck.checked = existing?.secure ?? false;
    const httpOnlyCheck = document.createElement("input");
    httpOnlyCheck.type = "checkbox";
    httpOnlyCheck.checked = existing?.httpOnly ?? false;

    const expiresInput = document.createElement("input");
    expiresInput.type = "text";
    expiresInput.placeholder = "blank = session cookie; or an ISO date";
    if (existing?.expirationDate) expiresInput.value = new Date(existing.expirationDate * 1000).toISOString();

    card.appendChild(fieldRow("Name", nameInput, "The cookie's name — part of its identity along with Domain and Path."));
    card.appendChild(fieldRow("Value", valueInput, "The raw cookie value, sent exactly as typed."));
    card.appendChild(fieldRow("Domain", domainInput, "example.com applies only to that host; .example.com (leading dot) also applies to its subdomains."));
    card.appendChild(fieldRow("Path", pathInput, "Restricts the cookie to URLs under this path. \"/\" applies it to the whole domain."));
    card.appendChild(fieldRow("SameSite", sameSiteSelect, "Controls whether this cookie is sent on cross-site requests. \"strict\"/\"lax\" block more; \"no_restriction\" requires Secure."));
    card.appendChild(fieldRow("Expires", expiresInput, "Leave blank for a session cookie (cleared when the browser closes), or set an ISO date/time for a persistent one."));
    const flagsRow = el("div", "zp-checkbox-row");
    flagsRow.appendChild(secureCheck);
    flagsRow.appendChild(el("label", "", "Secure"));
    flagsRow.appendChild(httpOnlyCheck);
    flagsRow.appendChild(el("label", "", "HttpOnly"));
    flagsRow.appendChild(
      infoIcon("Secure: only sent over HTTPS. HttpOnly: hidden from page JavaScript (document.cookie) — a common defense against XSS cookie theft.", { label: "About Secure & HttpOnly" })
    );
    card.appendChild(flagsRow);

    const actions = el("div", "zp-pending-actions");
    const saveBtn = el("button", "zp-btn zp-btn-primary zp-btn-small", "Save");
    saveBtn.type = "button";
    const cancelBtn = el("button", "zp-btn zp-btn-small", "Cancel");
    cancelBtn.type = "button";
    actions.appendChild(saveBtn);
    actions.appendChild(cancelBtn);
    actions.appendChild(
      infoIcon("Save writes this cookie to the browser immediately, replacing any existing cookie with the same Name/Domain/Path. Cancel discards the form without changing anything.", { label: "About Save & Cancel" })
    );
    card.appendChild(actions);

    cancelBtn.addEventListener("click", () => {
      formHost.textContent = "";
      onCancel?.();
    });

    saveBtn.addEventListener("click", async () => {
      const domain = domainInput.value.trim();
      const secure = secureCheck.checked;
      const path = pathInput.value.trim() || "/";
      if (!domain || !nameInput.value.trim()) {
        window.alert("Domain and Name are required.");
        return;
      }
      const details = {
        url: `${secure ? "https" : "http"}://${domain.replace(/^\./, "")}${path}`,
        name: nameInput.value.trim(),
        value: valueInput.value,
        domain,
        path,
        secure,
        httpOnly: httpOnlyCheck.checked,
        sameSite: sameSiteSelect.value,
      };
      const expiresText = expiresInput.value.trim();
      if (expiresText) {
        const ms = Date.parse(expiresText);
        if (!Number.isNaN(ms)) details.expirationDate = ms / 1000;
      }
      try {
        if (existing && (existing.name !== details.name || existing.domain !== details.domain || existing.path !== details.path)) {
          await ctx.api("cookies:remove", { url: cookieUrl(existing), name: existing.name });
        }
        await ctx.api("cookies:set", details);
      } catch (err) {
        window.alert(`Could not save cookie: ${err.message}`);
        return;
      }
      formHost.textContent = "";
      onCancel?.();
      await refresh();
    });

    formHost.appendChild(card);
  }

  function matches(c, q) {
    if (!q) return true;
    const n = q.toLowerCase();
    return c.domain.toLowerCase().includes(n) || c.name.toLowerCase().includes(n) || c.value.toLowerCase().includes(n);
  }

  function renderList() {
    list.textContent = "";
    const visible = cookies.filter((c) => matches(c, search));
    if (visible.length === 0) {
      list.appendChild(el("div", "zp-empty", cookies.length === 0 ? "No cookies visible yet." : "No cookies match the filter."));
      return;
    }
    for (const c of visible) {
      const card = el("div", "zp-cookie-card");
      const nv = el("div", "zp-cookie-name-value", `${c.name} = ${c.value}`);
      card.appendChild(nv);
      const attrs = [
        `Domain=${c.domain}`,
        `Path=${c.path}`,
        c.secure && "Secure",
        c.httpOnly && "HttpOnly",
        c.sameSite && `SameSite=${c.sameSite}`,
        `Expires=${formatExpiration(c)}`,
      ].filter(Boolean);
      card.appendChild(el("div", "zp-cookie-attrs", attrs.join("  ")));

      const actions = el("div", "zp-pending-actions");
      const editBtn = el("button", "zp-btn zp-btn-small", "Edit");
      editBtn.type = "button";
      editBtn.addEventListener("click", () => buildForm(c, () => {}));
      const delBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Delete");
      delBtn.type = "button";
      delBtn.addEventListener("click", async () => {
        await ctx.api("cookies:remove", { url: cookieUrl(c), name: c.name });
        await refresh();
      });
      actions.appendChild(editBtn);
      actions.appendChild(delBtn);
      card.appendChild(actions);

      list.appendChild(card);
    }
  }

  searchInput.addEventListener("input", () => {
    search = searchInput.value;
    renderList();
  });
  addBtn.addEventListener("click", () => buildForm(null, () => {}));
  grantBtn.addEventListener("click", async () => {
    await ctx.api("permissions:requestHostAccess");
    await refresh();
  });

  async function refresh() {
    hostNotice.hidden = await ctx.api("permissions:hasHostAccess");
    cookies = await ctx.api("cookies:getAll", {});
    renderList();
  }
  refresh();
}
