import { createInspector } from "../../components/inspector.js";
import { downloadText } from "../../components/export.js";
import { requestToCurl, buildHar, buildPostmanCollection, hostAndPath, withBodyUnavailable } from "../../../parsers/http.js";
import { matchesEntryQuery } from "../../../parsers/entry-search.js";
import { findingsFor, coalesced } from "../../components/history-feed.js";
import { infoIcon } from "../../components/tooltip.js";

const METHOD_OPTIONS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const STATUS_CHIPS = [
  { id: "2xx", label: "2xx", test: (s) => s >= 200 && s < 300 },
  { id: "3xx", label: "3xx", test: (s) => s >= 300 && s < 400 },
  { id: "4xx", label: "4xx", test: (s) => s >= 400 && s < 500 },
  { id: "5xx", label: "5xx", test: (s) => s >= 500 && s < 600 },
];
// Same categories exposed in Settings/Intercept's "skip intercepting these
// resource types" — different underlying vocabulary though: this is
// chrome.webRequest's own ResourceType strings (lowercase, what History's
// entries are actually tagged with via traffic-manager.js), not CDP Fetch's
// capitalized resourceType strings used by the interception-side setting.
const RESOURCE_TYPE_FILTERS = [
  { id: "stylesheet", label: "CSS" },
  { id: "image", label: "Images" },
  { id: "font", label: "Fonts" },
  { id: "media", label: "Media" },
  { id: "script", label: "Scripts" },
];

// Row highlight/triage, mirroring Burp's Proxy history "Highlight" — cycled
// by clicking a row's tag dot, in this order, wrapping back to "" (none).
const TAG_COLORS = ["", "red", "orange", "yellow", "green", "blue", "purple"];
function nextTag(current) {
  const idx = TAG_COLORS.indexOf(current || "");
  return TAG_COLORS[(idx + 1) % TAG_COLORS.length];
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function contentTypeOf(entry) {
  return (entry.response?.mimeType || "").split(";")[0] || "";
}

export function renderHistory(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "History"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Passively captured traffic for in-scope hosts. Response bodies are captured for text responses (HTML, JSON, JS, …) while Intercept is attached to the tab; without it, only headers are available. A ✎ badge marks a request/response actually sent as an edited version (via Intercept or a Match/Replace rule); a ⚠ badge marks passive security findings (missing headers, cookie flags, ...) — open the row's Response > Security tab for details."
    )
  );

  // Filters live in sharedState (same pattern Repeater's tabs already use)
  // so they survive navigating away to another view and back — this view
  // module is fully torn down and rebuilt on every navigation, so any state
  // kept in local variables here would otherwise reset every time.
  if (!ctx.sharedState.historyFilters) {
    ctx.sharedState.historyFilters = {
      sortKey: "startedAt",
      sortDir: "desc",
      search: "",
      searchRegex: false,
      methodFilter: "",
      statusChip: "",
      hiddenResourceTypes: new Set(),
    };
  }
  const filters = ctx.sharedState.historyFilters;

  let entries = [];
  let filtered = [];
  let selectedId = null;

  const toolbar = el("div", "zp-toolbar");
  const searchInput = document.createElement("input");
  searchInput.type = "text";
  searchInput.className = "zp-search-input";
  searchInput.placeholder = "Search URL, method, status, headers, body…";
  searchInput.value = filters.search;
  toolbar.appendChild(searchInput);
  const regexRow = el("span", "zp-checkbox-row");
  regexRow.style.marginBottom = "0";
  const regexCheckbox = document.createElement("input");
  regexCheckbox.type = "checkbox";
  regexCheckbox.id = "history-search-regex";
  regexCheckbox.checked = filters.searchRegex;
  const regexLabel = document.createElement("label");
  regexLabel.htmlFor = "history-search-regex";
  regexLabel.textContent = "Regex";
  regexRow.appendChild(regexCheckbox);
  regexRow.appendChild(regexLabel);
  toolbar.appendChild(regexRow);
  toolbar.appendChild(
    infoIcon(
      "Filters rows by URL, method, status code, every request/response header, and any body ZProxy has bytes for (request bodies, plus response bodies on edited entries — a plain response body is never available without Intercept). Matches anywhere in the text, not just the start. Check Regex to use a JavaScript regular expression instead of a plain substring; an invalid pattern is treated as no filter.",
      { label: "About search" }
    )
  );

  const methodSelect = document.createElement("select");
  methodSelect.appendChild(el("option", "", "All methods"));
  for (const m of METHOD_OPTIONS) methodSelect.appendChild(el("option", "", m));
  methodSelect.value = filters.methodFilter;
  toolbar.appendChild(methodSelect);

  for (const chip of STATUS_CHIPS) {
    const btn = el("button", "zp-filter-chip", chip.label);
    btn.type = "button";
    btn.dataset.chip = chip.id;
    btn.addEventListener("click", () => {
      filters.statusChip = filters.statusChip === chip.id ? "" : chip.id;
      applyFilters();
    });
    toolbar.appendChild(btn);
  }
  toolbar.appendChild(infoIcon("Click a status-code range to show only matching rows; click again to clear it. Only one range can be active at a time.", { label: "About status filters" }));

  const clearBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Clear history");
  clearBtn.type = "button";
  toolbar.appendChild(clearBtn);
  toolbar.appendChild(infoIcon("Permanently deletes every captured entry from History. Does not affect Scope, rules, or cookies.", { label: "About Clear history" }));

  const exportHarBtn = el("button", "zp-btn zp-btn-small", "Export HAR");
  exportHarBtn.type = "button";
  toolbar.appendChild(exportHarBtn);
  toolbar.appendChild(infoIcon("Downloads the currently filtered rows (or everything, if no filter is active) as a .har file for import into other HTTP tools.", { label: "About Export HAR" }));

  const exportJsonBtn = el("button", "zp-btn zp-btn-small", "Export JSON");
  exportJsonBtn.type = "button";
  toolbar.appendChild(exportJsonBtn);
  toolbar.appendChild(infoIcon("Downloads the currently filtered rows (or everything, if no filter is active) as raw ZProxy JSON.", { label: "About Export JSON" }));

  const exportPostmanBtn = el("button", "zp-btn zp-btn-small", "Export Postman");
  exportPostmanBtn.type = "button";
  toolbar.appendChild(exportPostmanBtn);
  toolbar.appendChild(
    infoIcon("Downloads the currently filtered rows (or everything, if no filter is active) as a Postman Collection v2.1 file, importable directly into Postman/Insomnia.", { label: "About Export Postman" })
  );

  container.appendChild(toolbar);

  const typeToolbar = el("div", "zp-toolbar");
  typeToolbar.appendChild(el("span", "zp-hint", "Hide:"));
  typeToolbar.appendChild(infoIcon("Toggle a resource type off to hide those rows from the table below — this only filters the view, it doesn't stop them from being captured.", { label: "About type filters" }));
  for (const rt of RESOURCE_TYPE_FILTERS) {
    const btn = el("button", "zp-filter-chip", rt.label);
    btn.type = "button";
    btn.dataset.resourceType = rt.id;
    btn.addEventListener("click", () => {
      if (filters.hiddenResourceTypes.has(rt.id)) filters.hiddenResourceTypes.delete(rt.id);
      else filters.hiddenResourceTypes.add(rt.id);
      applyFilters();
    });
    typeToolbar.appendChild(btn);
  }
  container.appendChild(typeToolbar);

  const split = el("div", "zp-split");
  const top = el("div", "zp-split-top");
  const bottom = el("div", "zp-split-bottom");
  split.appendChild(top);
  split.appendChild(bottom);
  container.appendChild(split);

  const table = document.createElement("table");
  table.className = "zp-table";
  const columns = [
    { key: "tag", label: "" },
    { key: "edited", label: "" },
    { key: "findings", label: "" },
    { key: "startedAt", label: "Time" },
    { key: "method", label: "Method" },
    { key: "status", label: "Status" },
    { key: "host", label: "Host" },
    { key: "path", label: "Path" },
    { key: "type", label: "Type" },
    { key: "durationMs", label: "ms" },
    { key: "comment", label: "Comment" },
  ];
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const col of columns) {
    const th = el("th", "", col.label);
    th.style.cursor = "pointer";
    th.addEventListener("click", () => {
      if (filters.sortKey === col.key) filters.sortDir = filters.sortDir === "asc" ? "desc" : "asc";
      else {
        filters.sortKey = col.key;
        filters.sortDir = "asc";
      }
      applyFilters();
    });
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  top.appendChild(table);

  const bottomToolbar = el("div", "zp-toolbar");
  const commentInput = document.createElement("input");
  commentInput.type = "text";
  commentInput.placeholder = "Comment on the selected row…";
  commentInput.disabled = true;
  commentInput.style.minWidth = "180px";
  bottomToolbar.appendChild(commentInput);
  bottomToolbar.appendChild(infoIcon("Select a row above first. Saved on Enter or when you click away — shown as the row's Comment column, and searchable like everything else above.", { label: "About comments" }));
  const sendToRepeaterBtn = el("button", "zp-btn zp-btn-small", "Send to Repeater");
  sendToRepeaterBtn.type = "button";
  sendToRepeaterBtn.disabled = true;
  const sendToIntruderBtn = el("button", "zp-btn zp-btn-small", "Send to Intruder");
  sendToIntruderBtn.type = "button";
  sendToIntruderBtn.disabled = true;
  const exportCurlBtn = el("button", "zp-btn zp-btn-small", "Copy as cURL");
  exportCurlBtn.type = "button";
  exportCurlBtn.disabled = true;
  const sendToDecoderBtn = el("button", "zp-btn zp-btn-small", "Send to Decoder");
  sendToDecoderBtn.type = "button";
  sendToDecoderBtn.disabled = true;
  const sendToComparerBtn = el("button", "zp-btn zp-btn-small", "Send to Comparer");
  sendToComparerBtn.type = "button";
  sendToComparerBtn.disabled = true;
  bottomToolbar.appendChild(sendToRepeaterBtn);
  bottomToolbar.appendChild(sendToIntruderBtn);
  bottomToolbar.appendChild(exportCurlBtn);
  bottomToolbar.appendChild(sendToDecoderBtn);
  bottomToolbar.appendChild(sendToComparerBtn);
  bottomToolbar.appendChild(
    infoIcon(
      "Select a row above first. Send to Repeater copies its request into a new Repeater tab for editing/resending; Send to Intruder loads it as the base request for an automated attack; Copy as cURL downloads a runnable curl script for it; Send to Decoder loads its response body (or request body, if no response body is available) into Decoder; Send to Comparer queues it into Comparer's next empty side (A, then B).",
      { label: "About these actions" }
    )
  );
  bottom.appendChild(bottomToolbar);

  const inspectorEmptyMsg = el("div", "zp-empty", "Select a request above to inspect it.");
  bottom.appendChild(inspectorEmptyMsg);
  const inspector = createInspector();
  inspector.element.hidden = true;
  bottom.appendChild(inspector.element);

  function rowValue(entry, key) {
    const { host, path } = hostAndPath(entry.request.url);
    switch (key) {
      case "tag":
        return entry.tag || "";
      case "comment":
        return entry.comment || "";
      case "edited":
        return entry.edited ? 1 : 0;
      case "findings":
        return findingsFor(entry).length;
      case "startedAt":
        return entry.startedAt || 0;
      case "method":
        return entry.request.method || "";
      case "status":
        return entry.response?.statusCode ?? -1;
      case "host":
        return host;
      case "path":
        return path;
      case "type":
        return entry.type || "";
      case "durationMs":
        return entry.durationMs ?? -1;
      default:
        return "";
    }
  }

  function applyFilters() {
    filtered = entries.filter((e) => {
      if (filters.methodFilter && e.request.method !== filters.methodFilter) return false;
      if (filters.statusChip) {
        const chip = STATUS_CHIPS.find((c) => c.id === filters.statusChip);
        if (!chip.test(e.response?.statusCode ?? 0)) return false;
      }
      if (filters.hiddenResourceTypes.has(e.type)) return false;
      if (!matchesEntryQuery(e, filters.search, filters.searchRegex)) return false;
      return true;
    });
    filtered.sort((a, b) => {
      const av = rowValue(a, filters.sortKey);
      const bv = rowValue(b, filters.sortKey);
      const cmp = av > bv ? 1 : av < bv ? -1 : 0;
      return filters.sortDir === "asc" ? cmp : -cmp;
    });
    for (const chipBtn of toolbar.querySelectorAll(".zp-filter-chip")) {
      chipBtn.classList.toggle("active", chipBtn.dataset.chip === filters.statusChip);
    }
    for (const chipBtn of typeToolbar.querySelectorAll(".zp-filter-chip")) {
      chipBtn.classList.toggle("active", filters.hiddenResourceTypes.has(chipBtn.dataset.resourceType));
    }
    renderRows();
  }

  function renderRows() {
    tbody.textContent = "";
    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columns.length;
      td.className = "zp-empty";
      td.textContent = entries.length === 0 ? "No traffic captured yet. Set a Scope and browse the target app." : "No entries match the current filters.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const entry of filtered) {
      const { host, path } = hostAndPath(entry.request.url);
      const tr = document.createElement("tr");
      tr.className = [entry.id === selectedId ? "selected" : "", entry.tag ? `zp-tag-${entry.tag}` : ""].filter(Boolean).join(" ");
      tr.addEventListener("click", () => selectEntry(entry.id));

      const tagTd = document.createElement("td");
      const tagDot = el("button", "zp-tag-dot");
      tagDot.type = "button";
      tagDot.title = entry.tag ? `Tagged ${entry.tag} — click to change` : "Click to tag this row";
      tagDot.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        const tag = nextTag(entry.tag);
        entry.tag = tag;
        await ctx.api("history:update", { id: entry.id, patch: { tag } });
        renderRows();
      });
      tagTd.appendChild(tagDot);
      tr.appendChild(tagTd);

      const editedTd = document.createElement("td");
      if (entry.edited) {
        const badge = el("span", "zp-badge zp-badge-warn", "✎");
        badge.title = "Sent as an edited version — via Intercept or a Match/Replace rule";
        editedTd.appendChild(badge);
      }
      tr.appendChild(editedTd);

      const findingsTd = document.createElement("td");
      const findingCount = findingsFor(entry).length;
      if (findingCount > 0) {
        const badge = el("span", "zp-badge zp-badge-security", `⚠ ${findingCount}`);
        badge.title = "Passive security findings — click the row, then the Response tab's Security tab for details.";
        findingsTd.appendChild(badge);
      }
      tr.appendChild(findingsTd);

      const time = new Date(entry.startedAt || 0);
      tr.appendChild(el("td", "", time.toLocaleTimeString()));

      const methodTd = el("td", `zp-method zp-method-${entry.request.method}`, entry.request.method);
      tr.appendChild(methodTd);

      const status = entry.response?.statusCode;
      let statusClass = "";
      let statusText = "…";
      if (status) {
        statusClass = `zp-status-${String(status)[0]}`;
        statusText = String(status);
      } else if (entry.status === "error") {
        // A request that never got an HTTP status at all (aborted,
        // connection refused, DNS failure, ...) — chrome.webRequest's own
        // net-error string (e.g. "net::ERR_ABORTED") is far more useful
        // here than a bare "ERR" that just says "something failed".
        statusClass = "zp-status-5";
        statusText = (entry.error || "ERR").replace(/^net::/, "");
      }
      const statusTd = el("td", statusClass, statusText);
      if (entry.error) statusTd.title = entry.error;
      tr.appendChild(statusTd);

      tr.appendChild(el("td", "", host));
      tr.appendChild(el("td", "", path));
      tr.appendChild(el("td", "", contentTypeOf(entry) || entry.type || ""));
      tr.appendChild(el("td", "", entry.durationMs != null ? String(entry.durationMs) : ""));

      const commentTd = el("td", "zp-comment-cell", entry.comment || "");
      if (entry.comment) commentTd.title = entry.comment;
      tr.appendChild(commentTd);

      tbody.appendChild(tr);
    }
  }

  function selectEntry(id) {
    selectedId = id;
    const entry = entries.find((e) => e.id === id);
    renderRows();
    sendToRepeaterBtn.disabled = !entry;
    sendToIntruderBtn.disabled = !entry;
    exportCurlBtn.disabled = !entry;
    sendToDecoderBtn.disabled = !entry;
    sendToComparerBtn.disabled = !entry;
    commentInput.disabled = !entry;
    commentInput.value = entry?.comment || "";
    if (entry) {
      inspectorEmptyMsg.hidden = true;
      inspector.element.hidden = false;
      // For an edited entry, jump straight to whichever side was actually
      // edited (that's where the original/edited comparison shows up) —
      // otherwise there's nothing to see there without an extra click.
      const defaultTab = entry.editDiff?.kind;
      inspector.setItem(withBodyUnavailable(entry), { requestEditable: false, responseEditable: false, defaultTab });
    }
  }

  searchInput.addEventListener("input", () => {
    filters.search = searchInput.value;
    applyFilters();
  });
  regexCheckbox.addEventListener("change", () => {
    filters.searchRegex = regexCheckbox.checked;
    applyFilters();
  });
  methodSelect.addEventListener("change", () => {
    filters.methodFilter = methodSelect.value;
    applyFilters();
  });
  clearBtn.addEventListener("click", async () => {
    await ctx.api("history:clear");
    await refresh();
  });
  exportHarBtn.addEventListener("click", async () => {
    const har = buildHar(filtered.length ? filtered : entries);
    await downloadText(`zproxy-history-${Date.now()}.har`, JSON.stringify(har, null, 2), "application/json");
  });
  exportJsonBtn.addEventListener("click", async () => {
    await downloadText(`zproxy-history-${Date.now()}.json`, JSON.stringify(filtered.length ? filtered : entries, null, 2), "application/json");
  });
  exportPostmanBtn.addEventListener("click", async () => {
    const collection = buildPostmanCollection(filtered.length ? filtered : entries, `ZProxy export — ${new Date().toLocaleString()}`);
    await downloadText(`zproxy-history-${Date.now()}.postman_collection.json`, JSON.stringify(collection, null, 2), "application/json");
  });
  sendToRepeaterBtn.addEventListener("click", () => {
    const entry = entries.find((e) => e.id === selectedId);
    if (!entry) return;
    ctx.sharedState.repeaterQueue.push({ request: entry.request });
    ctx.navigateTo("repeater");
  });
  sendToIntruderBtn.addEventListener("click", () => {
    const entry = entries.find((e) => e.id === selectedId);
    if (!entry) return;
    ctx.sharedState.intruderQueue.push({ request: entry.request });
    ctx.navigateTo("intruder");
  });
  exportCurlBtn.addEventListener("click", async () => {
    const entry = entries.find((e) => e.id === selectedId);
    if (!entry) return;
    await downloadText(`zproxy-request-${entry.id}.sh`, requestToCurl(entry.request), "text/plain");
  });
  sendToDecoderBtn.addEventListener("click", () => {
    const entry = entries.find((e) => e.id === selectedId);
    if (!entry) return;
    ctx.sharedState.decoderText = entry.response?.body || entry.request?.body || "";
    ctx.navigateTo("decoder");
  });
  sendToComparerBtn.addEventListener("click", () => {
    const entry = entries.find((e) => e.id === selectedId);
    if (!entry) return;
    ctx.sharedState.comparerQueue.push({ request: entry.request, response: entry.response });
    ctx.navigateTo("comparer");
  });
  async function saveComment() {
    const entry = entries.find((e) => e.id === selectedId);
    if (!entry || (entry.comment || "") === commentInput.value) return;
    entry.comment = commentInput.value;
    await ctx.api("history:update", { id: entry.id, patch: { comment: entry.comment } });
    renderRows();
  }
  commentInput.addEventListener("blur", saveComment);
  commentInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") commentInput.blur();
  });

  // history:new-entry pushes can fire in rapid succession (many resources
  // completing at once); guard against an older, slower-resolving refresh()
  // overwriting `entries` with stale data after a newer call already
  // applied fresher data. See the identical issue/fix in intercept.js.
  let refreshToken = 0;

  async function refresh() {
    const myToken = ++refreshToken;
    const next = await ctx.api("history:get");
    if (myToken !== refreshToken) return;
    entries = next;
    applyFilters();
  }
  refresh();

  // Coalesced: one refetch + re-render per burst of completed requests, not one per request.
  const refreshSoon = coalesced(refresh);
  const unsub = ctx.onPush((event) => {
    if (event.type === "history:new-entry" || event.type === "history:entry-updated") refreshSoon();
  });

  // Keyboard shortcuts (Settings > Keyboard shortcuts) that make sense here.
  // See the ownership-check teardown below and app.js's global listener.
  const searchShortcut = () => searchInput.focus();
  const clearHistoryShortcut = () => clearBtn.click();
  const sendToRepeaterShortcut = () => sendToRepeaterBtn.click();
  ctx.sharedState.shortcutHandlers.search = searchShortcut;
  ctx.sharedState.shortcutHandlers.clearHistory = clearHistoryShortcut;
  ctx.sharedState.shortcutHandlers.sendToRepeater = sendToRepeaterShortcut;

  return () => {
    unsub();
    refreshSoon.cancel();
    const handlers = ctx.sharedState.shortcutHandlers;
    if (handlers.search === searchShortcut) delete handlers.search;
    if (handlers.clearHistory === clearHistoryShortcut) delete handlers.clearHistory;
    if (handlers.sendToRepeater === sendToRepeaterShortcut) delete handlers.sendToRepeater;
  };
}
