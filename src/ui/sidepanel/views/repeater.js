import { infoIcon } from "../../components/tooltip.js";
import { sendRequest, sendRequestGroup, FORBIDDEN_REQUEST_HEADERS, DNR_OVERRIDABLE_HEADERS } from "../../components/http-send.js";
import { buildMacroEditor } from "../../components/macro-editor.js";
import { defaultMacro, applyMacroValue, extractMacroValue } from "../../../intruder/macro.js";
import { parseHeaderLines } from "../../../parsers/headers.js";
import { responseToRawHttp, requestToCurl } from "../../../parsers/http.js";
import { diffText } from "../../../parsers/diff.js";
import { recordSend, stepHistory, previousResponse, groupOutliers } from "../../../utils/repeater-history.js";
import { parseCurl } from "../../../parsers/curl.js";
import { prettyPrintJson, looksLikeJson } from "../../../parsers/json.js";
import { renderSandboxedPreview } from "../../../utils/sanitize.js";
import { makeResizable } from "../../components/resizable.js";
import { coalesced } from "../../components/history-feed.js";

let nextTabId = 1;
const MAX_GROUP_SIZE = 50;
const DEFAULT_TIMEOUT_MS = 30_000;

// Repeater tabs survive the side panel closing: they're kept in
// chrome.storage.session — memory-only, cleared when the browser quits,
// the same trust level as History (docs/SECURITY.md). Send history and
// group results are left out and response bodies are capped, because that
// storage area's quota is shared with History.
const SESSION_KEY = "repeaterTabs";
const MAX_SAVED_BODY = 50_000;

function serializeTabs(state) {
  const tabs = state.repeaterTabs.map((t) => ({
    id: t.id,
    name: t.name,
    request: t.request,
    macro: t.macro,
    timeoutMs: t.timeoutMs,
    view: t.view,
    response: t.response ? { ...t.response, body: t.response.body.slice(0, MAX_SAVED_BODY) } : null,
    error: t.error,
  }));
  return { tabs, activeId: state.repeaterActiveId, nextTabId };
}

async function loadSavedTabs() {
  try {
    const { [SESSION_KEY]: saved } = await chrome.storage.session.get(SESSION_KEY);
    return saved || null;
  } catch {
    return null;
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function blankRequest() {
  return { method: "GET", url: "https://example.com/", httpVersion: "HTTP/1.1", headers: [], body: "" };
}

function newTab(id, request) {
  return {
    id,
    name: null, // shown instead of "#id" once renamed (double-click the tab)
    timeoutMs: DEFAULT_TIMEOUT_MS,
    view: "pretty", // response view: pretty | raw | headers | preview
    search: "",
    request: { ...blankRequest(), ...request },
    response: null,
    error: null,
    macro: defaultMacro(),
    history: [],
    historyIndex: -1,
    showDiff: false,
    group: null, // { results, outliers } from the last "Send group"
  };
}

/** Runs {{macro}} substitution against a request object (headers as an array, not headersText) by round-tripping through the same free-text header format applyMacroValue works on. */
function substituteMacroToken(request, value) {
  const headersText = request.headers.map((h) => `${h.name}: ${h.value}`).join("\n");
  const applied = applyMacroValue({ url: request.url, headersText, body: request.body }, value);
  return { ...request, url: applied.url, headers: parseHeaderLines(applied.headersText), body: applied.body };
}

function renderDiff(container, before, after) {
  const { segments, truncated } = diffText(responseToRawHttp(before), responseToRawHttp(after));
  if (truncated) container.appendChild(el("div", "zp-warning", "⚠ Too large for a word-level diff — showing both responses as whole removed/added blocks."));
  const view = el("pre", "zp-diff-view");
  for (const seg of segments) {
    if (seg.type === "equal") {
      view.appendChild(document.createTextNode(seg.text));
    } else {
      view.appendChild(el("span", seg.type === "removed" ? "zp-diff-removed" : "zp-diff-added", seg.text));
    }
  }
  container.appendChild(view);
}

/** Text with every case-insensitive occurrence of `query` wrapped in <mark> — DOM nodes only, never markup. Returns the hit count. */
function appendHighlighted(parent, text, query) {
  if (!query) {
    parent.appendChild(document.createTextNode(text));
    return 0;
  }
  const lower = text.toLowerCase();
  const needle = query.toLowerCase();
  let from = 0;
  let hits = 0;
  for (let at = lower.indexOf(needle); at !== -1; at = lower.indexOf(needle, at + needle.length)) {
    parent.appendChild(document.createTextNode(text.slice(from, at)));
    const mark = document.createElement("mark");
    mark.textContent = text.slice(at, at + needle.length);
    parent.appendChild(mark);
    from = at + needle.length;
    hits++;
  }
  parent.appendChild(document.createTextNode(text.slice(from)));
  return hits;
}

export function renderRepeater(container, ctx) {
  container.textContent = "";
  const state = ctx.sharedState;

  // First open since the panel loaded: restore saved tabs, then render for real.
  if (!state.repeaterRestored) {
    state.repeaterRestored = true;
    loadSavedTabs().then((saved) => {
      if (saved?.tabs?.length && !state.repeaterTabs?.length) {
        state.repeaterTabs = saved.tabs.map((t) => ({ ...newTab(t.id), ...t, history: [], historyIndex: -1, group: null, showDiff: false }));
        state.repeaterActiveId = saved.activeId;
        nextTabId = Math.max(nextTabId, saved.nextTabId || 1);
      }
      if (container.isConnected) renderRepeater(container, ctx);
    });
    return;
  }

  container.appendChild(el("h2", "zp-view-title", "Repeater"));
  container.appendChild(el("p", "zp-hint", "Edit a request and resend it as many times as you like. Sent via fetch() from this extension page — see the notes below the headers for the few the browser handles specially. Tabs are kept until the browser closes."));

  if (!state.repeaterTabs) state.repeaterTabs = [];
  if (!state.repeaterActiveId) state.repeaterActiveId = null;
  const persist = () => chrome.storage.session.set({ [SESSION_KEY]: serializeTabs(state) }).catch(() => {});
  const persistSoon = coalesced(persist, 600);

  // Drain anything sent over from History/Intercept ("Send to Repeater").
  if (state.repeaterQueue && state.repeaterQueue.length) {
    for (const queued of state.repeaterQueue.splice(0, state.repeaterQueue.length)) {
      const id = nextTabId++;
      state.repeaterTabs.push(newTab(id, queued.request));
      state.repeaterActiveId = id;
    }
  }
  if (state.repeaterTabs.length === 0) {
    const id = nextTabId++;
    state.repeaterTabs.push(newTab(id));
    state.repeaterActiveId = id;
  }

  const tabsBar = el("div", "zp-repeater-tabs");
  container.appendChild(tabsBar);

  const toolbar = el("div", "zp-repeater-toolbar");
  const sendBtn = el("button", "zp-btn zp-btn-primary zp-btn-small", "Send");
  sendBtn.type = "button";
  const backBtn = el("button", "zp-btn zp-btn-small", "◀");
  backBtn.type = "button";
  backBtn.title = "Previous send in this tab";
  const forwardBtn = el("button", "zp-btn zp-btn-small", "▶");
  forwardBtn.type = "button";
  forwardBtn.title = "Next send in this tab";
  const historyLabel = el("span", "zp-mono-small", "");
  const groupCountInput = document.createElement("input");
  groupCountInput.type = "number";
  groupCountInput.min = "2";
  groupCountInput.max = String(MAX_GROUP_SIZE);
  groupCountInput.value = "10";
  groupCountInput.style.width = "4em";
  const sendGroupBtn = el("button", "zp-btn zp-btn-small", "Send group");
  sendGroupBtn.type = "button";
  const sendToIntruderBtn = el("button", "zp-btn zp-btn-small", "Send to Intruder");
  sendToIntruderBtn.type = "button";
  const closeBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Close tab");
  closeBtn.type = "button";
  toolbar.appendChild(sendBtn);
  toolbar.appendChild(
    infoIcon("Sends the request above for real via fetch() from this extension page, and shows the response below.", { label: "About Send" })
  );
  toolbar.appendChild(backBtn);
  toolbar.appendChild(forwardBtn);
  toolbar.appendChild(historyLabel);
  toolbar.appendChild(
    infoIcon("Step back and forth through this tab's previous sends — each restores the request exactly as sent and its response. Sending again from an older entry adds a new entry at the end; nothing is discarded. Up to 50 per tab, kept until the side panel closes.", { label: "About send history" })
  );
  toolbar.appendChild(groupCountInput);
  toolbar.appendChild(sendGroupBtn);
  toolbar.appendChild(
    infoIcon(
      `Sends N copies of the request (2–${MAX_GROUP_SIZE}) at the same moment, for race-condition testing (double-spend, limit bypass, duplicate redemption). Results that differ from the majority are marked. Honest limit: these are parallel fetch() calls, so they leave close together but not in one TCP packet the way Burp's single-packet attack does — network jitter still separates them a little. Sends real, possibly state-changing requests.`,
      { label: "About Send group" }
    )
  );
  toolbar.appendChild(sendToIntruderBtn);
  toolbar.appendChild(infoIcon("Loads the request currently in the editor as Intruder's base request for an automated attack.", { label: "About Send to Intruder" }));
  toolbar.appendChild(closeBtn);
  toolbar.appendChild(infoIcon("Closes the current Repeater tab. If it's the last one, a fresh blank tab replaces it.", { label: "About Close tab" }));
  container.appendChild(toolbar);

  const toolbar2 = el("div", "zp-repeater-toolbar");
  const duplicateBtn = el("button", "zp-btn zp-btn-small", "Duplicate tab");
  duplicateBtn.type = "button";
  const copyCurlBtn = el("button", "zp-btn zp-btn-small", "Copy as cURL");
  copyCurlBtn.type = "button";
  const importCurlBtn = el("button", "zp-btn zp-btn-small", "Import cURL");
  importCurlBtn.type = "button";
  const timeoutLabel = el("label", "", "Timeout (s)");
  const timeoutInput = document.createElement("input");
  timeoutInput.type = "number";
  timeoutInput.min = "0";
  timeoutInput.style.width = "4.5em";
  toolbar2.appendChild(duplicateBtn);
  toolbar2.appendChild(copyCurlBtn);
  toolbar2.appendChild(importCurlBtn);
  toolbar2.appendChild(
    infoIcon("Copy as cURL puts the request in the editor on your clipboard as a curl command. Import cURL replaces the editor with a pasted curl command — e.g. from your browser DevTools' \"Copy as cURL\". Double-click a tab's name to rename it.", { label: "About cURL" })
  );
  toolbar2.appendChild(timeoutLabel);
  toolbar2.appendChild(timeoutInput);
  toolbar2.appendChild(infoIcon("Gives up on a request that hasn't answered within this many seconds (0 = wait forever). Applies to Send and Send group in this tab.", { label: "About timeout" }));
  container.appendChild(toolbar2);

  const importBox = el("div", "zp-rule-card");
  importBox.hidden = true;
  const importArea = document.createElement("textarea");
  importArea.style.minHeight = "80px";
  importArea.placeholder = "curl 'https://example.com/api' -H 'accept: application/json' …";
  const importRow = el("div", "zp-pending-actions");
  const importGo = el("button", "zp-btn zp-btn-primary zp-btn-small", "Import into this tab");
  importGo.type = "button";
  const importCancel = el("button", "zp-btn zp-btn-small", "Cancel");
  importCancel.type = "button";
  const importError = el("span", "zp-mono-small", "");
  importRow.appendChild(importGo);
  importRow.appendChild(importCancel);
  importRow.appendChild(importError);
  importBox.appendChild(importArea);
  importBox.appendChild(importRow);
  container.appendChild(importBox);

  const hostAccessNotice = el("div", "zp-warning");
  const hostAccessText = el(
    "span",
    "",
    "⚠ Without cross-origin host access, Repeater can only reach same-origin/CORS-permitting targets."
  );
  const requestHostBtn = el("button", "zp-btn zp-btn-small", "Grant host access");
  requestHostBtn.type = "button";
  hostAccessNotice.appendChild(hostAccessText);
  hostAccessNotice.appendChild(document.createElement("br"));
  hostAccessNotice.appendChild(requestHostBtn);
  hostAccessNotice.appendChild(
    infoIcon("Requests the optional <all_urls> permission, which lets extension-page fetches like this one bypass CORS for cross-origin targets.", { label: "About host access" })
  );
  hostAccessNotice.hidden = true;
  container.appendChild(hostAccessNotice);

  const split = el("div", "zp-split");
  const editorWrap = el("div", "zp-split-top");
  const responseWrap = el("div", "zp-split-bottom");
  split.appendChild(editorWrap);
  split.appendChild(responseWrap);
  container.appendChild(split);
  makeResizable(split, editorWrap, responseWrap, { storageKey: "zproxy.split.repeater", minTop: 120, minBottom: 120, label: "Resize request editor" });

  // A fresh editor per active tab so getEditedRequest() always reflects
  // exactly the tab currently on screen.
  let editor = null;
  let macroEditor = null;

  function activeTab() {
    return state.repeaterTabs.find((t) => t.id === state.repeaterActiveId) || state.repeaterTabs[0];
  }

  function renderTabsBar() {
    tabsBar.textContent = "";
    for (const tab of state.repeaterTabs) {
      const btn = el("button", "zp-repeater-tab" + (tab.id === state.repeaterActiveId ? " active" : ""), tab.name || `#${tab.id}`);
      btn.type = "button";
      btn.title = "Double-click to rename";
      btn.addEventListener("click", () => {
        if (state.repeaterActiveId === tab.id) return;
        captureEditor();
        state.repeaterActiveId = tab.id;
        renderAll();
      });
      btn.addEventListener("dblclick", () => {
        const input = document.createElement("input");
        input.type = "text";
        input.value = tab.name || "";
        input.placeholder = `#${tab.id}`;
        input.style.width = "10em";
        let finished = false;
        const done = (save) => {
          if (finished) return; // Enter re-renders the bar, which then blurs the removed input
          finished = true;
          if (save) tab.name = input.value.trim() || null;
          renderTabsBar();
          persistSoon();
        };
        input.addEventListener("keydown", (e) => {
          if (e.key === "Enter") done(true);
          if (e.key === "Escape") done(false);
        });
        input.addEventListener("blur", () => done(true));
        btn.replaceWith(input);
        input.focus();
        input.select();
      });
      tabsBar.appendChild(btn);
    }
    const addBtn = el("button", "zp-repeater-tab", "+");
    addBtn.type = "button";
    addBtn.title = "New request";
    addBtn.addEventListener("click", () => {
      captureEditor();
      const id = nextTabId++;
      state.repeaterTabs.push(newTab(id));
      state.repeaterActiveId = id;
      renderAll();
      persist();
    });
    tabsBar.appendChild(addBtn);
  }

  function renderHistoryControls() {
    const tab = activeTab();
    const count = tab.history?.length || 0;
    backBtn.disabled = !count || tab.historyIndex <= 0;
    forwardBtn.disabled = !count || tab.historyIndex >= count - 1;
    historyLabel.textContent = count ? `${tab.historyIndex + 1}/${count}` : "";
  }

  function renderEditor() {
    editorWrap.textContent = "";
    const tab = activeTab();
    editor = { element: document.createElement("div") };

    const line = el("div", "zp-req-line");
    const methodInput = document.createElement("input");
    methodInput.className = "zp-method-input";
    methodInput.value = tab.request.method;
    const urlInput = document.createElement("input");
    urlInput.className = "zp-url-input";
    urlInput.value = tab.request.url;
    line.appendChild(methodInput);
    line.appendChild(urlInput);
    line.appendChild(infoIcon("The HTTP method and full URL to send. Both are editable — change them freely before clicking Send.", { label: "About method & URL" }));
    editorWrap.appendChild(line);

    const headersHeading = el("div", "zp-subheading", "Headers (one per line: Name: value)");
    headersHeading.appendChild(
      infoIcon(
        "One header per line, formatted as \"Name: value\". Cookie, Origin, and Referer are applied through a temporary browser rule for this one request (an empty \"Cookie:\" line sends no cookies at all). Framing headers (Host, Content-Length, Connection, ...) can never be set and are dropped.",
        { label: "About headers" }
      )
    );
    editorWrap.appendChild(headersHeading);
    const headersArea = document.createElement("textarea");
    headersArea.style.minHeight = "90px";
    headersArea.value = tab.request.headers.map((h) => `${h.name}: ${h.value}`).join("\n");
    editorWrap.appendChild(headersArea);

    const bodyHeading = el("div", "zp-subheading", "Body");
    bodyHeading.appendChild(infoIcon("Sent as the raw request body. Ignored for GET/HEAD requests.", { label: "About body" }));
    editorWrap.appendChild(bodyHeading);
    const bodyArea = document.createElement("textarea");
    bodyArea.value = tab.request.body || "";
    editorWrap.appendChild(bodyArea);

    editor.getRequest = () => {
      const headers = headersArea.value
        .split("\n")
        .map((line) => {
          const idx = line.indexOf(":");
          if (idx === -1) return null;
          return { name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() };
        })
        .filter(Boolean);
      return { method: methodInput.value.trim() || "GET", url: urlInput.value.trim(), httpVersion: "HTTP/1.1", headers, body: bodyArea.value };
    };
    // Keep the tab's request current as it's typed, so switching tabs or
    // closing the panel never loses an unsent edit.
    for (const input of [methodInput, urlInput, headersArea, bodyArea]) {
      input.addEventListener("input", () => {
        tab.request = editor.getRequest();
        persistSoon();
      });
    }
    timeoutInput.value = String(Math.round((tab.timeoutMs ?? DEFAULT_TIMEOUT_MS) / 1000));

    const forbidden = tab.request.headers.filter((h) => FORBIDDEN_REQUEST_HEADERS.has(h.name.toLowerCase()));
    const overridden = forbidden.filter((h) => DNR_OVERRIDABLE_HEADERS.has(h.name.toLowerCase()));
    const dropped = forbidden.filter((h) => !DNR_OVERRIDABLE_HEADERS.has(h.name.toLowerCase()));
    if (overridden.length) {
      editorWrap.appendChild(
        el(
          "div",
          "zp-hint",
          `ℹ ${overridden.map((h) => h.name).join(", ")} will be set via a temporary browser rule for this request only (any Set-Cookie in the response is discarded when Cookie is overridden, so your own session isn't replaced). Confirm against an echo endpoint before relying on it — see README.`
        )
      );
    }
    if (dropped.length) {
      editorWrap.appendChild(
        el("div", "zp-warning", `⚠ Browsers never let a script set: ${dropped.map((h) => h.name).join(", ")}. These are sent as the browser chooses, not your edited value.`)
      );
    }

    if (!tab.macro) tab.macro = defaultMacro();
    macroEditor = buildMacroEditor(tab.macro);
    editorWrap.appendChild(macroEditor.element);
  }

  function renderGroupResults(tab) {
    const { results, outliers } = tab.group;
    const heading = el("div", "zp-subheading", `Group results (${results.length} sent together)`);
    const clearBtn = el("button", "zp-btn zp-btn-small", "Clear");
    clearBtn.type = "button";
    clearBtn.addEventListener("click", () => {
      tab.group = null;
      renderResponse();
    });
    heading.appendChild(clearBtn);
    responseWrap.appendChild(heading);
    const outlierCount = outliers.filter(Boolean).length;
    responseWrap.appendChild(
      el("div", "zp-hint", outlierCount ? `${outlierCount} result(s) differ from the majority (status/length) — marked ≠. Click a row to view it.` : "All results matched. Click a row to view it.")
    );
    const table = el("table", "zp-table");
    const head = document.createElement("tr");
    for (const title of ["#", "", "Status", "Length", "Time"]) head.appendChild(el("th", "", title));
    const thead = document.createElement("thead");
    thead.appendChild(head);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    results.forEach((r, i) => {
      const tr = document.createElement("tr");
      tr.appendChild(el("td", "", String(i + 1)));
      const flagTd = document.createElement("td");
      if (outliers[i]) flagTd.appendChild(el("span", "zp-badge zp-badge-warn", "≠"));
      tr.appendChild(flagTd);
      tr.appendChild(el("td", "", r.ok ? String(r.response.statusCode) : "error"));
      tr.appendChild(el("td", "", r.ok ? String(r.response.body.length) : r.error));
      tr.appendChild(el("td", "", r.ok ? `${r.response.durationMs}ms` : ""));
      tr.addEventListener("click", () => {
        tab.response = r.ok ? r.response : null;
        tab.error = r.ok ? null : r.error;
        renderResponse();
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    responseWrap.appendChild(table);
  }

  function renderResponse() {
    responseWrap.textContent = "";
    renderHistoryControls();
    const tab = activeTab();
    if (tab.group) renderGroupResults(tab);
    if (tab.error) {
      responseWrap.appendChild(el("div", "zp-warning", `⚠ ${tab.error}`));
      return;
    }
    if (!tab.response) {
      responseWrap.appendChild(el("div", "zp-empty", "No response yet. Edit the request above and click Send."));
      return;
    }
    const statusLine = el(
      "div",
      "zp-mono-small",
      `${tab.response.statusCode} ${tab.response.statusText || ""}  ·  ${tab.response.durationMs}ms  ·  ${tab.response.body.length} bytes`
    );
    responseWrap.appendChild(statusLine);

    const previous = previousResponse(tab);
    if (previous) {
      const diffRow = el("div", "zp-checkbox-row");
      const diffCheck = document.createElement("input");
      diffCheck.type = "checkbox";
      diffCheck.id = `repeater-diff-${tab.id}`;
      diffCheck.checked = tab.showDiff;
      diffCheck.addEventListener("change", () => {
        tab.showDiff = diffCheck.checked;
        renderResponse();
      });
      const diffLabel = el("label", "", "Diff against the previous response");
      diffLabel.htmlFor = diffCheck.id;
      diffRow.appendChild(diffCheck);
      diffRow.appendChild(diffLabel);
      diffRow.appendChild(infoIcon("Word-level diff of this response (status line, headers, and body) against the one sent just before it in this tab. Red = only in the previous response, green = only in this one.", { label: "About response diff" }));
      responseWrap.appendChild(diffRow);
      if (tab.showDiff) {
        renderDiff(responseWrap, previous, tab.response);
        return;
      }
    }

    renderResponseBody(tab);
  }

  function renderResponseBody(tab) {
    const res = tab.response;
    if (res.redirected && res.finalUrl) {
      responseWrap.appendChild(el("div", "zp-hint", `Redirects were followed — this is the response from ${res.finalUrl}`));
    }
    const contentType = (res.headers.find((h) => h.name.toLowerCase() === "content-type")?.value || "").toLowerCase();
    const isJson = looksLikeJson(res.body, contentType);
    const isHtml = contentType.includes("html");

    const bar = el("div", "zp-toolbar");
    const nav = el("div", "zp-tab-nav");
    nav.style.marginBottom = "0";
    const views = [
      ["pretty", isJson ? "Pretty" : "Body"],
      ["raw", "Raw"],
      ["headers", `Headers (${res.headers.length})`],
      ...(isHtml ? [["preview", "Preview"]] : []),
    ];
    if (!views.some(([id]) => id === tab.view)) tab.view = "pretty";
    for (const [id, label] of views) {
      const b = el("button", "zp-tab-btn" + (tab.view === id ? " active" : ""), label);
      b.type = "button";
      b.addEventListener("click", () => {
        tab.view = id;
        persistSoon();
        renderResponse();
      });
      nav.appendChild(b);
    }
    bar.appendChild(nav);
    const search = document.createElement("input");
    search.type = "search";
    search.className = "zp-search-input";
    search.placeholder = "Find in response…";
    search.value = tab.search || "";
    const hitCount = el("span", "zp-mono-small", "");
    bar.appendChild(search);
    bar.appendChild(hitCount);
    responseWrap.appendChild(bar);

    const output = el("div");
    responseWrap.appendChild(output);

    function draw() {
      output.textContent = "";
      hitCount.textContent = "";
      if (tab.view === "preview") {
        const box = el("div", "zp-preview-box");
        output.appendChild(box);
        // Scripts never run here — see sanitize.js.
        renderSandboxedPreview(box, res.body);
        return;
      }
      const text =
        tab.view === "headers"
          ? res.headers.map((h) => `${h.name}: ${h.value}`).join("\n")
          : tab.view === "raw"
            ? responseToRawHttp(res)
            : isJson
              ? prettyPrintJson(res.body)
              : res.body;
      const pre = el("pre", "zp-raw-view");
      const hits = appendHighlighted(pre, text, tab.search);
      output.appendChild(pre);
      if (tab.search) {
        hitCount.textContent = hits ? `${hits} match${hits === 1 ? "" : "es"}` : "no matches";
        pre.querySelector("mark")?.scrollIntoView({ block: "nearest" });
      }
    }
    search.addEventListener("input", () => {
      tab.search = search.value;
      draw();
    });
    draw();
  }

  function renderAll() {
    renderTabsBar();
    renderEditor();
    renderResponse();
  }

  async function refreshHostAccessNotice() {
    const has = await ctx.api("permissions:hasHostAccess");
    hostAccessNotice.hidden = has;
  }

  requestHostBtn.addEventListener("click", async () => {
    await ctx.api("permissions:requestHostAccess");
    await refreshHostAccessNotice();
  });

  sendToIntruderBtn.addEventListener("click", () => {
    const tab = activeTab();
    tab.request = editor.getRequest();
    ctx.sharedState.intruderQueue.push({ request: tab.request });
    ctx.navigateTo("intruder");
  });

  closeBtn.addEventListener("click", () => {
    const idx = state.repeaterTabs.findIndex((t) => t.id === state.repeaterActiveId);
    if (idx === -1) return;
    state.repeaterTabs.splice(idx, 1);
    if (state.repeaterTabs.length === 0) state.repeaterTabs.push(newTab(nextTabId++));
    state.repeaterActiveId = state.repeaterTabs[Math.max(0, idx - 1)].id;
    renderAll();
    persist();
  });

  /** Saves what's in the editor into the active tab before the editor is rebuilt. */
  function captureEditor() {
    const tab = activeTab();
    if (tab && editor?.getRequest) tab.request = editor.getRequest();
  }

  duplicateBtn.addEventListener("click", () => {
    captureEditor();
    const source = activeTab();
    const copy = newTab(nextTabId++, structuredClone(source.request));
    copy.name = source.name ? `${source.name} (copy)` : null;
    copy.macro = structuredClone(source.macro);
    copy.timeoutMs = source.timeoutMs;
    state.repeaterTabs.splice(state.repeaterTabs.indexOf(source) + 1, 0, copy);
    state.repeaterActiveId = copy.id;
    renderAll();
    persist();
  });

  copyCurlBtn.addEventListener("click", async () => {
    const original = copyCurlBtn.textContent;
    try {
      await navigator.clipboard.writeText(requestToCurl(editor.getRequest()));
      copyCurlBtn.textContent = "Copied";
    } catch {
      copyCurlBtn.textContent = "Clipboard blocked";
    }
    setTimeout(() => (copyCurlBtn.textContent = original), 1400);
  });

  importCurlBtn.addEventListener("click", () => {
    importBox.hidden = !importBox.hidden;
    importError.textContent = "";
    if (!importBox.hidden) importArea.focus();
  });
  importCancel.addEventListener("click", () => {
    importBox.hidden = true;
  });
  importGo.addEventListener("click", () => {
    try {
      const tab = activeTab();
      tab.request = parseCurl(importArea.value);
      importArea.value = "";
      importBox.hidden = true;
      renderEditor();
      persist();
    } catch (err) {
      importError.textContent = `Couldn't import: ${err.message}.`;
    }
  });

  timeoutInput.addEventListener("change", () => {
    const seconds = Number(timeoutInput.value);
    activeTab().timeoutMs = Number.isFinite(seconds) && seconds > 0 ? Math.round(seconds * 1000) : 0;
    persistSoon();
  });

  for (const [btn, delta] of [
    [backBtn, -1],
    [forwardBtn, 1],
  ]) {
    btn.addEventListener("click", () => {
      if (stepHistory(activeTab(), delta)) {
        renderEditor();
        renderResponse();
      }
    });
  }

  function setBusy(busy, label) {
    sendBtn.disabled = busy;
    sendGroupBtn.disabled = busy;
    sendBtn.textContent = busy && label ? label : "Send";
  }

  /** Runs the tab's session-handling macro, if enabled; returns the request to send, or null (tab.error set) on failure. */
  async function prepareRequest(tab, request) {
    if (!tab.macro?.enabled) return request;
    const macroRequest = {
      method: tab.macro.method,
      url: tab.macro.url,
      httpVersion: "HTTP/1.1",
      headers: parseHeaderLines(tab.macro.headersText),
      body: tab.macro.body,
    };
    const macroResult = await sendRequest(macroRequest);
    if (!macroResult.ok) {
      tab.error = `Session handling macro failed: ${macroResult.error}`;
      macroEditor?.setStatus(tab.error, true);
      return null;
    }
    const value = extractMacroValue(macroResult.response, tab.macro.extractQuery);
    if (value == null) {
      tab.error = "Session handling macro ran, but its Extract value query found no match in the response.";
      macroEditor?.setStatus(tab.error, true);
      return null;
    }
    macroEditor?.setStatus(`Macro extracted: ${value}`);
    return substituteMacroToken(request, value);
  }

  sendBtn.addEventListener("click", async () => {
    const tab = activeTab();
    tab.error = null;
    setBusy(true, tab.macro?.enabled ? "Running macro…" : "Sending…");
    macroEditor?.setStatus("");
    const request = await prepareRequest(tab, editor.getRequest());
    if (!request) {
      tab.response = null;
      setBusy(false);
      renderResponse();
      return;
    }
    sendBtn.textContent = "Sending…";
    const result = await sendRequest(request, { timeoutMs: tab.timeoutMs });
    recordSend(tab, { request, response: result.ok ? result.response : null, error: result.ok ? null : result.error });
    setBusy(false);
    renderResponse();
    persist();
  });

  sendGroupBtn.addEventListener("click", async () => {
    const tab = activeTab();
    const count = Math.min(MAX_GROUP_SIZE, Math.max(2, Math.floor(Number(groupCountInput.value)) || 2));
    groupCountInput.value = String(count);
    const base = editor.getRequest();
    if (!window.confirm(`Send ${count} copies of ${base.method} ${base.url} at the same time? These are real requests and may change server state.`)) return;
    tab.error = null;
    setBusy(true, "Sending group…");
    macroEditor?.setStatus("");
    // The macro runs once: every copy must carry the same token to be a fair race.
    const request = await prepareRequest(tab, base);
    if (!request) {
      setBusy(false);
      renderResponse();
      return;
    }
    tab.request = request;
    const results = await sendRequestGroup(Array.from({ length: count }, () => request), { timeoutMs: tab.timeoutMs });
    tab.group = { results, outliers: groupOutliers(results) };
    const first = results.find((r) => r.ok);
    tab.response = first ? first.response : null;
    tab.error = first ? null : results[0]?.error || "Every request in the group failed.";
    setBusy(false);
    renderResponse();
    persist();
  });

  renderAll();
  refreshHostAccessNotice();
  persistSoon();
  return () => {
    captureEditor();
    persistSoon.cancel();
    persist();
  };
}
