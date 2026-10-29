// Live log of WebSocket frames for tabs Intercept is attached to. Frames are
// captured by interception/websocket-interceptor.js through CDP's Network
// domain — observation only: CDP has no hook to hold or rewrite a frame
// (docs/CAPABILITIES.md row 15), so this is a viewer, not an interceptor.
import { infoIcon } from "../../components/tooltip.js";
import { coalesced } from "../../components/history-feed.js";
import { describeFrame, filterFrames } from "../../../parsers/websocket-frames.js";
import { prettyPrintJson } from "../../../parsers/json.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function renderWebSockets(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "WebSockets"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Frames sent and received by WebSockets in tabs Intercept is attached to — attach first, then load the page (sockets opened before attaching aren't seen). Observation only: Chrome's debugging protocol can't pause or edit a frame. Kept in memory per tab (last 500 frames per socket) until Intercept detaches."
    )
  );

  let viewingTabId = null;
  let selectedSocketId = null;
  let selectedFrameIndex = null;
  let sockets = [];
  let frames = [];
  const filters = { direction: "all", query: "" };

  const tabRow = el("div", "zp-form-row");
  tabRow.appendChild(el("label", "", "Tab"));
  const tabSelect = document.createElement("select");
  tabRow.appendChild(tabSelect);
  container.appendChild(tabRow);

  const notAttached = el("div", "zp-empty", "Intercept isn't attached to any tab. Click Intercept in the header on the tab you're testing, then load the page.");
  container.appendChild(notAttached);

  const body = el("div");
  container.appendChild(body);

  const socketsHeading = el("div", "zp-subheading", "Sockets");
  body.appendChild(socketsHeading);
  const socketList = el("div", "zp-header-rows");
  body.appendChild(socketList);

  const toolbar = el("div", "zp-toolbar");
  const directionSelect = document.createElement("select");
  for (const [value, label] of [
    ["all", "Both directions"],
    ["sent", "Sent ↑"],
    ["received", "Received ↓"],
  ]) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    directionSelect.appendChild(opt);
  }
  const searchInput = document.createElement("input");
  searchInput.type = "search";
  searchInput.className = "zp-search-input";
  searchInput.placeholder = "Filter frames…";
  toolbar.appendChild(directionSelect);
  toolbar.appendChild(searchInput);
  toolbar.appendChild(infoIcon("Case-insensitive substring match on the frame payload. Binary frames are matched on their base64 text.", { label: "About frame filter" }));
  body.appendChild(toolbar);

  const table = el("table", "zp-table");
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const title of ["", "Time", "Type", "Length", "Payload"]) headRow.appendChild(el("th", "", title));
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  body.appendChild(table);

  const detailHeading = el("div", "zp-subheading", "Frame");
  const detail = el("pre", "zp-raw-view");
  body.appendChild(detailHeading);
  body.appendChild(detail);

  function renderSockets() {
    socketList.textContent = "";
    if (sockets.length === 0) {
      socketList.appendChild(el("div", "zp-empty", "No WebSockets seen in this tab yet."));
      return;
    }
    for (const s of sockets) {
      const row = el("button", "zp-header-row" + (s.requestId === selectedSocketId ? " selected" : ""));
      row.type = "button";
      row.appendChild(el("span", "zp-mono-small", s.url));
      row.appendChild(el("span", "zp-badge zp-badge-info", `${s.frameCount} frames`));
      row.addEventListener("click", () => {
        selectedSocketId = s.requestId;
        selectedFrameIndex = null;
        loadFrames();
      });
      socketList.appendChild(row);
    }
  }

  function renderFrames() {
    tbody.textContent = "";
    const visible = filterFrames(frames, filters);
    if (visible.length === 0) {
      const tr = document.createElement("tr");
      const td = el("td", "zp-empty", selectedSocketId ? "No frames match." : "Select a socket above.");
      td.colSpan = 5;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
    for (const frame of visible) {
      const index = frames.indexOf(frame);
      const { kind, preview } = describeFrame(frame);
      const tr = document.createElement("tr");
      if (index === selectedFrameIndex) tr.className = "selected";
      tr.appendChild(el("td", "", frame.direction === "sent" ? "↑" : "↓"));
      tr.appendChild(el("td", "", new Date(frame.time).toLocaleTimeString()));
      tr.appendChild(el("td", "", kind));
      tr.appendChild(el("td", "", String((frame.data ?? "").length)));
      tr.appendChild(el("td", "zp-mono-small", preview));
      tr.addEventListener("click", () => {
        selectedFrameIndex = index;
        renderFrames();
      });
      tbody.appendChild(tr);
    }
    renderDetail();
  }

  function renderDetail() {
    const frame = frames[selectedFrameIndex];
    detailHeading.hidden = !frame;
    detail.hidden = !frame;
    if (!frame) return;
    const { kind, isJson } = describeFrame(frame);
    // textContent only — a frame payload is untrusted (docs/SECURITY.md).
    detail.textContent = `${frame.direction === "sent" ? "↑ sent" : "↓ received"} · ${kind}\n\n${isJson ? prettyPrintJson(frame.data) : frame.data ?? ""}`;
  }

  async function loadFrames() {
    renderSockets();
    frames = selectedSocketId == null || viewingTabId == null ? [] : await ctx.api("websocket:frames", { tabId: viewingTabId, requestId: selectedSocketId });
    renderFrames();
  }

  let refreshToken = 0;
  async function refresh() {
    const myToken = ++refreshToken;
    const attached = await ctx.api("intercept:attachedTabs");
    if (myToken !== refreshToken) return;
    notAttached.hidden = attached.length > 0;
    body.hidden = attached.length === 0;
    tabRow.hidden = attached.length === 0;
    if (!attached.some((t) => t.id === viewingTabId)) {
      const activeId = ctx.getTab()?.id;
      viewingTabId = attached.some((t) => t.id === activeId) ? activeId : attached[0]?.id ?? null;
      selectedSocketId = null;
      selectedFrameIndex = null;
    }
    tabSelect.textContent = "";
    for (const t of attached) {
      const opt = document.createElement("option");
      opt.value = String(t.id);
      opt.textContent = t.title || t.url || `Tab ${t.id}`;
      opt.selected = t.id === viewingTabId;
      tabSelect.appendChild(opt);
    }
    sockets = viewingTabId == null ? [] : await ctx.api("websocket:list", { tabId: viewingTabId });
    if (myToken !== refreshToken) return;
    if (selectedSocketId == null && sockets.length) selectedSocketId = sockets[sockets.length - 1].requestId;
    await loadFrames();
  }

  tabSelect.addEventListener("change", () => {
    viewingTabId = Number(tabSelect.value);
    selectedSocketId = null;
    selectedFrameIndex = null;
    refresh();
  });
  directionSelect.addEventListener("change", () => {
    filters.direction = directionSelect.value;
    renderFrames();
  });
  searchInput.addEventListener("input", () => {
    filters.query = searchInput.value;
    renderFrames();
  });

  refresh();
  // A chatty socket can push dozens of frames a second — re-fetch at most every 250ms.
  const refreshSoon = coalesced(refresh);
  const unsub = ctx.onPush((event) => {
    if (event.type !== "intercept:event") return;
    const t = event.event?.type;
    if (t === "websocket-created" || t === "websocket-frame" || t === "attached" || t === "detached") refreshSoon();
  });
  return () => {
    unsub();
    refreshSoon.cancel();
  };
}
