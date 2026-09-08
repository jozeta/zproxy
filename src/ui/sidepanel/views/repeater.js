import { infoIcon } from "../../components/tooltip.js";
import { sendRequest, FORBIDDEN_REQUEST_HEADERS } from "../../components/http-send.js";
import { buildMacroEditor } from "../../components/macro-editor.js";
import { defaultMacro, applyMacroValue, extractMacroValue } from "../../../intruder/macro.js";
import { parseHeaderLines } from "../../../parsers/headers.js";

let nextTabId = 1;

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
  return { id, request: { ...blankRequest(), ...request }, response: null, error: null, macro: defaultMacro() };
}

/** Runs {{macro}} substitution against a request object (headers as an array, not headersText) by round-tripping through the same free-text header format applyMacroValue works on. */
function substituteMacroToken(request, value) {
  const headersText = request.headers.map((h) => `${h.name}: ${h.value}`).join("\n");
  const applied = applyMacroValue({ url: request.url, headersText, body: request.body }, value);
  return { ...request, url: applied.url, headers: parseHeaderLines(applied.headersText), body: applied.body };
}

export function renderRepeater(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Repeater"));
  container.appendChild(el("p", "zp-hint", "Edit a request and resend it as many times as you like. Sent via fetch() from this extension page — see the warning below for headers the browser never lets scripts set."));

  const state = ctx.sharedState;
  if (!state.repeaterTabs) state.repeaterTabs = [];
  if (!state.repeaterActiveId) state.repeaterActiveId = null;

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
  const sendToIntruderBtn = el("button", "zp-btn zp-btn-small", "Send to Intruder");
  sendToIntruderBtn.type = "button";
  const closeBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Close tab");
  closeBtn.type = "button";
  toolbar.appendChild(sendBtn);
  toolbar.appendChild(
    infoIcon("Sends the request above for real via fetch() from this extension page, and shows the response below.", { label: "About Send" })
  );
  toolbar.appendChild(sendToIntruderBtn);
  toolbar.appendChild(infoIcon("Loads the request currently in the editor as Intruder's base request for an automated attack.", { label: "About Send to Intruder" }));
  toolbar.appendChild(closeBtn);
  toolbar.appendChild(infoIcon("Closes the current Repeater tab. If it's the last one, a fresh blank tab replaces it.", { label: "About Close tab" }));
  container.appendChild(toolbar);

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
      const btn = el("button", "zp-repeater-tab" + (tab.id === state.repeaterActiveId ? " active" : ""), `#${tab.id}`);
      btn.type = "button";
      btn.addEventListener("click", () => {
        state.repeaterActiveId = tab.id;
        renderAll();
      });
      tabsBar.appendChild(btn);
    }
    const addBtn = el("button", "zp-repeater-tab", "+");
    addBtn.type = "button";
    addBtn.title = "New request";
    addBtn.addEventListener("click", () => {
      const id = nextTabId++;
      state.repeaterTabs.push(newTab(id));
      state.repeaterActiveId = id;
      renderAll();
    });
    tabsBar.appendChild(addBtn);
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
      infoIcon("One header per line, formatted as \"Name: value\". A handful of headers (Host, Origin, Cookie, Content-Length, ...) can never be set by page/extension script and are dropped before sending — see the warning below if that applies.", { label: "About headers" })
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

    const forbidden = tab.request.headers.filter((h) => FORBIDDEN_REQUEST_HEADERS.has(h.name.toLowerCase()));
    if (forbidden.length) {
      editorWrap.appendChild(
        el(
          "div",
          "zp-warning",
          `⚠ Browsers never let a script set: ${forbidden.map((h) => h.name).join(", ")}. These will be sent as the browser/cookie-jar chooses, not your edited value.`
        )
      );
    }

    if (!tab.macro) tab.macro = defaultMacro();
    macroEditor = buildMacroEditor(tab.macro);
    editorWrap.appendChild(macroEditor.element);
  }

  function renderResponse() {
    responseWrap.textContent = "";
    const tab = activeTab();
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
    responseWrap.appendChild(el("div", "zp-subheading", "Headers"));
    const headerBox = el("div", "zp-json-box");
    for (const h of tab.response.headers) headerBox.appendChild(el("div", "zp-mono-small", `${h.name}: ${h.value}`));
    responseWrap.appendChild(headerBox);
    responseWrap.appendChild(el("div", "zp-subheading", "Body"));
    const pre = el("pre", "zp-raw-view");
    pre.textContent = tab.response.body;
    responseWrap.appendChild(pre);
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
  });

  sendBtn.addEventListener("click", async () => {
    const tab = activeTab();
    let request = editor.getRequest();
    tab.error = null;
    sendBtn.disabled = true;
    sendBtn.textContent = tab.macro?.enabled ? "Running macro…" : "Sending…";
    macroEditor?.setStatus("");

    if (tab.macro?.enabled) {
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
        tab.response = null;
        macroEditor?.setStatus(tab.error, true);
        sendBtn.disabled = false;
        sendBtn.textContent = "Send";
        renderResponse();
        return;
      }
      const value = extractMacroValue(macroResult.response, tab.macro.extractQuery);
      if (value == null) {
        tab.error = "Session handling macro ran, but its Extract value query found no match in the response.";
        tab.response = null;
        macroEditor?.setStatus(tab.error, true);
        sendBtn.disabled = false;
        sendBtn.textContent = "Send";
        renderResponse();
        return;
      }
      macroEditor?.setStatus(`Macro extracted: ${value}`);
      request = substituteMacroToken(request, value);
      sendBtn.textContent = "Sending…";
    }

    tab.request = request;
    const result = await sendRequest(tab.request);
    if (result.ok) {
      tab.response = result.response;
    } else {
      tab.error = result.error;
      tab.response = null;
    }
    sendBtn.disabled = false;
    sendBtn.textContent = "Send";
    renderResponse();
  });

  renderAll();
  refreshHostAccessNotice();
}
