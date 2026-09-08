// The shared request/response viewer+editor used by History, Intercept, and
// Repeater. Every value that came from captured traffic is rendered via
// textContent/input.value or the sandboxed-iframe preview — never innerHTML.
// See docs/SECURITY.md "Preview isolation".
import { parseQueryParams, requestToRawHttp, responseToRawHttp } from "../../parsers/http.js";
import { prettyPrintJson, looksLikeJson } from "../../parsers/json.js";
import { findJwtInHeaders } from "../../parsers/jwt.js";
import { parseAllSetCookies } from "../../parsers/cookies.js";
import { checkResponse } from "../../parsers/passive-checks.js";
import { renderJsonPretty } from "./code-view.js";
import { renderSandboxedPreview, setTextSafely } from "../../utils/sanitize.js";
import { infoIcon } from "./tooltip.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function createTabs(defs) {
  const nav = el("div", "zp-tab-nav");
  const panelsWrap = el("div", "zp-tab-panels");
  const panelEls = {};
  let active = defs[0]?.id;

  function show(id) {
    active = id;
    for (const d of defs) {
      nav.querySelector(`[data-tab="${d.id}"]`)?.classList.toggle("active", d.id === id);
      panelEls[d.id].hidden = d.id !== id;
    }
    const def = defs.find((d) => d.id === id);
    def?.onShow?.(panelEls[id]);
  }

  for (const d of defs) {
    const btn = el("button", "zp-tab-btn", d.label);
    btn.type = "button";
    btn.dataset.tab = d.id;
    btn.addEventListener("click", () => show(d.id));
    nav.appendChild(btn);

    const panel = el("div", "zp-tab-panel");
    panelEls[d.id] = panel;
    panelsWrap.appendChild(panel);
    d.render(panel);
  }

  if (active) show(active);

  const wrap = el("div", "zp-tabs");
  wrap.appendChild(nav);
  wrap.appendChild(panelsWrap);
  return { element: wrap, show };
}

function buildHeaderTable(initialHeaders, editable) {
  const wrap = el("div", "zp-header-table");
  const rows = el("div", "zp-header-rows");
  wrap.appendChild(rows);

  function addRow(name = "", value = "", enabled = true) {
    const row = el("div", "zp-header-row");

    const enabledInput = document.createElement("input");
    enabledInput.type = "checkbox";
    enabledInput.checked = enabled;
    enabledInput.disabled = !editable;
    row.appendChild(enabledInput);

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.value = name;
    nameInput.placeholder = "Header-Name";
    nameInput.readOnly = !editable;
    nameInput.className = "zp-header-name";
    row.appendChild(nameInput);

    const valueInput = document.createElement("input");
    valueInput.type = "text";
    valueInput.value = value;
    valueInput.placeholder = "value";
    valueInput.readOnly = !editable;
    valueInput.className = "zp-header-value";
    row.appendChild(valueInput);

    if (editable) {
      const delBtn = el("button", "zp-icon-btn", "✕");
      delBtn.type = "button";
      delBtn.title = "Remove header";
      delBtn.addEventListener("click", () => row.remove());
      row.appendChild(delBtn);
    }

    rows.appendChild(row);
  }

  for (const h of initialHeaders) addRow(h.name, h.value, h.enabled !== false);

  if (editable) {
    const addBtn = el("button", "zp-btn zp-btn-small", "+ Add header");
    addBtn.type = "button";
    addBtn.addEventListener("click", () => addRow());
    wrap.appendChild(addBtn);
    wrap.appendChild(infoIcon("Uncheck a header to drop it, or edit its name/value directly. Changes are only sent once you click Forward.", { label: "About editing headers" }));
  }

  function getHeaders() {
    return [...rows.querySelectorAll(".zp-header-row")]
      .filter((row) => row.querySelector("input[type=checkbox]").checked)
      .map((row) => ({
        name: row.querySelector(".zp-header-name").value,
        value: row.querySelector(".zp-header-value").value,
      }))
      .filter((h) => h.name.trim().length > 0);
  }

  return { element: wrap, getHeaders };
}

function renderQueryParams(container, url) {
  const params = parseQueryParams(url || "");
  if (params.length === 0) {
    container.appendChild(el("div", "zp-empty", "No query parameters."));
    return;
  }
  const table = el("div", "zp-header-table");
  for (const p of params) {
    const row = el("div", "zp-header-row zp-header-row-readonly");
    row.appendChild(el("span", "zp-header-name", p.name));
    row.appendChild(el("span", "zp-header-value", p.value));
    table.appendChild(row);
  }
  container.appendChild(table);
}

function renderRawInto(container, computeText) {
  container.textContent = "";
  const pre = el("pre", "zp-raw-view");
  setTextSafely(pre, computeText());
  container.appendChild(pre);
}

function renderJwtInto(container, jwtInfo) {
  container.textContent = "";
  if (!jwtInfo.ok) {
    container.appendChild(el("div", "zp-empty", jwtInfo.error));
    return;
  }
  const warning = el("div", "zp-warning", `⚠ ${jwtInfo.warning}`);
  container.appendChild(warning);
  container.appendChild(el("div", "zp-subheading", "Header"));
  const headerBox = el("div", "zp-json-box");
  renderJsonPretty(headerBox, JSON.stringify(jwtInfo.header, null, 2));
  container.appendChild(headerBox);
  container.appendChild(el("div", "zp-subheading", "Payload"));
  const payloadBox = el("div", "zp-json-box");
  renderJsonPretty(payloadBox, JSON.stringify(jwtInfo.payload, null, 2));
  container.appendChild(payloadBox);
  container.appendChild(el("div", "zp-subheading", "Signature (not verified)"));
  container.appendChild(el("div", "zp-mono-small", jwtInfo.signature));
}

const SEVERITY_BADGE_CLASS = { high: "zp-badge-danger", medium: "zp-badge-warn", low: "zp-badge-info", info: "" };

function renderFindingsInto(container, findings) {
  container.textContent = "";
  const note = el(
    "p",
    "zp-hint",
    "Passive, zero-request heuristics on this response/request pair already captured — missing security headers, cookie flags, permissive CORS, secret-shaped strings in the body, and request values reflected back unescaped. Not a scanner; finding nothing here is not the same as \"secure.\""
  );
  container.appendChild(note);
  if (findings.length === 0) {
    container.appendChild(el("div", "zp-empty", "No passive findings for this response."));
    return;
  }
  for (const f of findings) {
    const card = el("div", "zp-finding");
    const title = el("div", "zp-finding-title");
    title.appendChild(el("span", `zp-badge ${SEVERITY_BADGE_CLASS[f.severity] || ""}`.trim(), f.severity.toUpperCase()));
    title.appendChild(document.createTextNode(f.title));
    card.appendChild(title);
    card.appendChild(el("div", "zp-finding-detail", f.detail));
    container.appendChild(card);
  }
}

function renderCookiesInto(container, headers) {
  const cookies = parseAllSetCookies(headers || []);
  container.textContent = "";
  if (cookies.length === 0) {
    container.appendChild(el("div", "zp-empty", "No Set-Cookie headers on this response."));
    return;
  }
  for (const c of cookies) {
    const card = el("div", "zp-cookie-card");
    card.appendChild(el("div", "zp-cookie-name-value", `${c.name} = ${c.value}`));
    const attrs = [
      c.domain && `Domain=${c.domain}`,
      c.path && `Path=${c.path}`,
      c.expires && `Expires=${c.expires}`,
      c.maxAge != null && !Number.isNaN(c.maxAge) && `Max-Age=${c.maxAge}`,
      c.secure && "Secure",
      c.httpOnly && "HttpOnly",
      c.sameSite && `SameSite=${c.sameSite}`,
    ].filter(Boolean);
    card.appendChild(el("div", "zp-cookie-attrs", attrs.join("  ")));
    container.appendChild(card);
  }
}

/** Builds one self-contained request panel (method/url line + Headers/Query/Body/Raw/JWT tabs). Returns {element, snapshot} rather than writing into a fixed column, so the same builder serves both the normal single-panel view and the original/edited side-by-side comparison. */
function buildRequestPanel(request, editable, columnLabel) {
  const col = el("div", "zp-inspector-col");
  if (columnLabel) col.appendChild(el("div", "zp-col-title", columnLabel));

  const line = el("div", "zp-req-line");
  const methodInput = document.createElement("input");
  methodInput.className = "zp-method-input";
  methodInput.value = request?.method || "GET";
  methodInput.readOnly = !editable;
  const urlInput = document.createElement("input");
  urlInput.className = "zp-url-input";
  urlInput.value = request?.url || "";
  urlInput.readOnly = !editable;
  line.appendChild(methodInput);
  line.appendChild(urlInput);
  if (editable) {
    line.appendChild(infoIcon("Edit the method and/or URL before forwarding — the request is sent exactly as shown here.", { label: "About method & URL" }));
  }
  col.appendChild(line);

  const headerTable = buildHeaderTable(request?.headers || [], editable);

  const bodyTextarea = document.createElement("textarea");
  bodyTextarea.className = "zp-body-textarea";
  bodyTextarea.value = request?.body ?? "";
  bodyTextarea.readOnly = !editable;
  bodyTextarea.spellcheck = false;

  const jwtInfo = findJwtInHeaders(request?.headers || []);

  const snapshot = () => ({
    method: methodInput.value,
    url: urlInput.value,
    httpVersion: "HTTP/1.1",
    headers: headerTable.getHeaders(),
    body: bodyTextarea.value,
  });

  const tabDefs = [
    { id: "headers", label: `Headers (${(request?.headers || []).length})`, render: (p) => p.appendChild(headerTable.element) },
    { id: "query", label: "Query", render: (p) => renderQueryParams(p, request?.url) },
    {
      id: "body",
      label: "Body",
      render: (p) => {
        const toolbar = el("div", "zp-toolbar");
        const prettyBtn = el("button", "zp-btn zp-btn-small", "Pretty JSON");
        prettyBtn.type = "button";
        prettyBtn.addEventListener("click", () => {
          bodyTextarea.value = prettyPrintJson(bodyTextarea.value);
        });
        toolbar.appendChild(prettyBtn);
        toolbar.appendChild(infoIcon("Reformats the body text as indented JSON, if it parses as valid JSON. Leaves it unchanged otherwise.", { label: "About Pretty JSON" }));
        if (looksLikeJson(request?.body || "")) {
          const validBadge = el("span", "zp-badge", "JSON detected");
          toolbar.appendChild(validBadge);
        }
        p.appendChild(toolbar);
        p.appendChild(bodyTextarea);
      },
    },
    { id: "raw", label: "Raw", onShow: (p) => renderRawInto(p, () => requestToRawHttp(snapshot())), render: () => {} },
  ];
  if (jwtInfo) tabDefs.push({ id: "jwt", label: "JWT", render: (p) => renderJwtInto(p, jwtInfo) });

  col.appendChild(createTabs(tabDefs).element);
  return { element: col, snapshot };
}

/** Builds one self-contained response panel (status line + Headers/Body/Cookies/Security/Raw/Preview tabs), or a "no response" placeholder. Returns {element, snapshot} — see buildRequestPanel(). `requestUrl` is only used for the Security tab's scheme-dependent checks (HSTS, cookies-over-HTTP). */
function buildResponsePanel(response, editable, columnLabel, requestUrl) {
  const col = el("div", "zp-inspector-col");
  if (columnLabel) col.appendChild(el("div", "zp-col-title", columnLabel));

  if (!response) {
    col.appendChild(el("div", "zp-empty", "No response yet."));
    return { element: col, snapshot: () => null };
  }

  const line = el("div", "zp-res-line");
  const statusInput = document.createElement("input");
  statusInput.className = "zp-status-input";
  statusInput.value = response.statusCode ?? "";
  statusInput.readOnly = !editable;
  const statusTextInput = document.createElement("input");
  statusTextInput.className = "zp-status-text-input";
  statusTextInput.value = response.statusText || "";
  statusTextInput.readOnly = !editable;
  line.appendChild(statusInput);
  line.appendChild(statusTextInput);
  if (editable) {
    line.appendChild(infoIcon("Edit the status code/text and the headers/body in the tabs below before forwarding — sent exactly as shown here.", { label: "About status" }));
  }
  if (response.bodyTruncated) line.appendChild(el("span", "zp-badge zp-badge-warn", "body truncated"));
  if (response.bodyAvailable === false) line.appendChild(el("span", "zp-badge zp-badge-warn", "body unavailable"));
  col.appendChild(line);

  const headerTable = buildHeaderTable(response.headers || [], editable);

  const bodyTextarea = document.createElement("textarea");
  bodyTextarea.className = "zp-body-textarea";
  bodyTextarea.value = response.body ?? "";
  bodyTextarea.readOnly = !editable;
  bodyTextarea.spellcheck = false;

  const snapshot = () => ({
    statusCode: Number(statusInput.value) || 0,
    statusText: statusTextInput.value,
    headers: headerTable.getHeaders(),
    body: bodyTextarea.value,
    mimeType: response.mimeType,
  });

  const isHtml = (response.mimeType || "").includes("html");
  const findings = checkResponse({ url: requestUrl }, response);

  const tabDefs = [
    { id: "headers", label: `Headers (${(response.headers || []).length})`, render: (p) => p.appendChild(headerTable.element) },
    {
      id: "body",
      label: "Body",
      render: (p) => {
        const toolbar = el("div", "zp-toolbar");
        const prettyBtn = el("button", "zp-btn zp-btn-small", "Pretty JSON");
        prettyBtn.type = "button";
        prettyBtn.addEventListener("click", () => {
          bodyTextarea.value = prettyPrintJson(bodyTextarea.value);
        });
        toolbar.appendChild(prettyBtn);
        toolbar.appendChild(infoIcon("Reformats the body text as indented JSON, if it parses as valid JSON. Leaves it unchanged otherwise.", { label: "About Pretty JSON" }));
        p.appendChild(toolbar);
        p.appendChild(bodyTextarea);
      },
    },
    { id: "cookies", label: "Cookies", render: (p) => renderCookiesInto(p, response.headers) },
    {
      id: "security",
      label: `Security${findings.length ? ` (${findings.length})` : ""}`,
      render: (p) => renderFindingsInto(p, findings),
    },
    { id: "raw", label: "Raw", onShow: (p) => renderRawInto(p, () => responseToRawHttp(snapshot())), render: () => {} },
  ];
  if (isHtml) {
    tabDefs.push({
      id: "preview",
      label: "Preview",
      render: (p) => {
        p.appendChild(el("div", "zp-warning", "⚠ Preview only — scripts are disabled in this sandbox."));
        const box = el("div", "zp-preview-box");
        p.appendChild(box);
      },
      onShow: (p) => {
        const box = p.querySelector(".zp-preview-box");
        if (box) renderSandboxedPreview(box, bodyTextarea.value);
      },
    });
  }

  col.appendChild(createTabs(tabDefs).element);
  return { element: col, snapshot };
}

export function createInspector() {
  const root = el("div", "zp-inspector-root");
  const reqHost = el("div", "zp-inspector-panel-host");
  const resHost = el("div", "zp-inspector-panel-host");

  const outerTabs = createTabs([
    { id: "request", label: "Request", render: (p) => p.appendChild(reqHost) },
    { id: "response", label: "Response", render: (p) => p.appendChild(resHost) },
  ]);
  root.appendChild(outerTabs.element);

  let refs = {};

  function renderRequestTab(request, editable, original) {
    reqHost.textContent = "";
    if (original) {
      // History's "edited" view: original (read-only) vs. what was actually
      // sent, side by side — never editable, this is a retrospective record.
      const diffRow = el("div", "zp-diff-row");
      const originalPanel = buildRequestPanel(original, false, "Original");
      const editedPanel = buildRequestPanel(request, false, "Sent (edited)");
      diffRow.appendChild(originalPanel.element);
      diffRow.appendChild(editedPanel.element);
      reqHost.appendChild(diffRow);
      refs.request = editedPanel;
    } else {
      const panel = buildRequestPanel(request, editable, null);
      reqHost.appendChild(panel.element);
      refs.request = panel;
    }
  }

  function renderResponseTab(response, editable, original, requestUrl) {
    resHost.textContent = "";
    if (original) {
      const diffRow = el("div", "zp-diff-row");
      const originalPanel = buildResponsePanel(original, false, "Original", requestUrl);
      const editedPanel = buildResponsePanel(response, false, "Sent (edited)", requestUrl);
      diffRow.appendChild(originalPanel.element);
      diffRow.appendChild(editedPanel.element);
      resHost.appendChild(diffRow);
      refs.response = editedPanel;
    } else {
      const panel = buildResponsePanel(response, editable, null, requestUrl);
      resHost.appendChild(panel.element);
      refs.response = panel;
    }
  }

  function setItem(item, options = {}) {
    const { requestEditable = false, responseEditable = false, defaultTab } = options;
    // item.editDiff (from History, for an edited entry) carries the
    // authoritative before/after snapshot captured at edit time — NOT
    // item.request/item.response themselves, which for History entries
    // come from chrome.webRequest and can't be trusted to reflect a
    // CDP-level edit (see docs/CAPABILITIES.md row 9 and the note in
    // edited-tracker.js: webRequest never carries a response body at all,
    // and never reflects a request URL/method override either).
    const diff = item?.editDiff;
    const reqEdited = diff?.kind === "request" ? diff.edited : item?.request;
    const reqOriginal = diff?.kind === "request" ? diff.original : null;
    const resEdited = diff?.kind === "response" ? diff.edited : item?.response;
    const resOriginal = diff?.kind === "response" ? diff.original : null;
    renderRequestTab(reqEdited, requestEditable, reqOriginal);
    renderResponseTab(resEdited, responseEditable, resOriginal, item?.request?.url);
    if (defaultTab) outerTabs.show(defaultTab);
  }

  return {
    element: root,
    setItem,
    getEditedRequest: () => refs.request?.snapshot(),
    getEditedResponse: () => refs.response?.snapshot(),
  };
}
