// Aggregates every passive security finding across all of History into one
// browsable table, grouped by finding TYPE (e.g. every "missing CSP header"
// occurrence becomes one row with a count) rather than one row per
// occurrence — with that many findings, a flat list of occurrences is much
// less useful than "here are the 6 kinds of thing found, and how often."
// Same checkResponse() the per-entry Security tab, the History ⚠ badge, and
// the Dashboard stat card all already use — this view adds nothing new to
// the security logic itself, just a better way to look at what it found.
import { createInspector } from "../../components/inspector.js";
import { infoIcon } from "../../components/tooltip.js";
import { makeResizable } from "../../components/resizable.js";
import { downloadText } from "../../components/export.js";
import { buildFindingsMarkdown } from "../../../parsers/findings-report.js";
import { SEVERITY_ORDER } from "../../../parsers/passive-checks.js";
import { findingsFor, coalesced } from "../../components/history-feed.js";
import { hostAndPath, withBodyUnavailable } from "../../../parsers/http.js";

const SEVERITY_CHIPS = ["high", "medium", "low", "info"];
const SEVERITY_BADGE_CLASS = { high: "zp-badge-danger", medium: "zp-badge-warn", low: "zp-badge-info", info: "" };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function severityBadge(severity) {
  return el("span", `zp-badge ${SEVERITY_BADGE_CLASS[severity] || ""}`.trim(), severity.charAt(0).toUpperCase() + severity.slice(1));
}

/**
 * Groups (entry, finding) occurrences by finding.id — the stable "kind of
 * finding" (e.g. "missing-csp", "cookie-missing-secure"), not by title,
 * since a title can embed a per-occurrence value (a specific cookie name)
 * that would otherwise keep every occurrence in its own group of one.
 * Each group's severity is the worst (highest-ranked) severity seen among
 * its occurrences — cookie-missing-httponly, for one real example, varies
 * between "low" and "medium" depending on whether the cookie's name looks
 * session-related, and the group should read as however bad its worst
 * occurrence actually is. title/detail come from the first occurrence seen.
 */
function groupFindings(entries) {
  const groups = new Map(); // finding.id -> group
  for (const entry of entries) {
    for (const finding of findingsFor(entry)) {
      let group = groups.get(finding.id);
      if (!group) {
        group = { id: finding.id, severity: finding.severity, title: finding.title, detail: finding.detail, occurrences: [] };
        groups.set(finding.id, group);
      } else if (SEVERITY_ORDER.indexOf(finding.severity) > SEVERITY_ORDER.indexOf(group.severity)) {
        group.severity = finding.severity;
      }
      group.occurrences.push({ entry, finding });
    }
  }
  return [...groups.values()];
}

export function renderFindings(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Findings"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Every passive security finding (missing headers, cookie flags, secret-shaped strings, reflected-unescaped input, ...) across all of History, grouped by kind of finding — the same zero-request heuristics as each entry's Security tab, just aggregated. Click a row to see every URL it showed up on. Not a scanner; finding nothing is not the same as \"secure.\""
    )
  );

  const toolbar = el("div", "zp-toolbar");
  const searchInput = document.createElement("input");
  searchInput.type = "text";
  searchInput.className = "zp-search-input";
  searchInput.placeholder = "Search title, detail, or an affected URL…";
  toolbar.appendChild(searchInput);
  for (const sev of SEVERITY_CHIPS) {
    const btn = el("button", "zp-filter-chip", sev.charAt(0).toUpperCase() + sev.slice(1));
    btn.type = "button";
    btn.dataset.severity = sev;
    toolbar.appendChild(btn);
  }
  toolbar.appendChild(infoIcon("Each severity chip is an independent on/off toggle — all are on by default; switch off the ones you don't want to see (e.g. Info). Each chip shows how many kinds of finding have that severity. Your choice is kept while the panel is open.", { label: "About severity filters" }));
  const exportBtn = el("button", "zp-btn zp-btn-small", "Export report");
  exportBtn.type = "button";
  toolbar.appendChild(exportBtn);
  toolbar.appendChild(
    infoIcon("Downloads every finding currently shown (filters apply) as a Markdown report — severity summary, explanation, and affected URLs — to start a write-up from. Confirm each item by hand before reporting it.", { label: "About Export report" })
  );
  container.appendChild(toolbar);

  const split = el("div", "zp-split");
  const top = el("div", "zp-split-top");
  const bottom = el("div", "zp-split-bottom");
  split.appendChild(top);
  split.appendChild(bottom);
  container.appendChild(split);
  makeResizable(split, top, bottom, { storageKey: "zproxy.split.findings", label: "Resize findings list" });

  const table = document.createElement("table");
  table.className = "zp-table";
  const columns = [
    { key: "severity", label: "Severity" },
    { key: "title", label: "Finding" },
    { key: "count", label: "Count" },
  ];
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  // Severities currently shown — each chip toggles its own membership.
  if (!ctx.sharedState.findingsSeverities) ctx.sharedState.findingsSeverities = [...SEVERITY_CHIPS];
  const filters = { search: "", severities: new Set(ctx.sharedState.findingsSeverities), sortKey: "severity", sortDir: "desc" };
  for (const col of columns) {
    const th = el("th", "", col.label);
    th.style.cursor = "pointer";
    th.addEventListener("click", () => {
      if (filters.sortKey === col.key) filters.sortDir = filters.sortDir === "asc" ? "desc" : "asc";
      else {
        filters.sortKey = col.key;
        filters.sortDir = col.key === "title" ? "asc" : "desc";
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

  const selectedCard = el("div", "zp-finding");
  selectedCard.hidden = true;
  bottom.appendChild(selectedCard);

  bottom.appendChild(el("div", "zp-subheading", "Affected URLs"));
  const urlList = el("div", "zp-pending-list");
  urlList.hidden = true;
  bottom.appendChild(urlList);

  const inspectorEmptyMsg = el("div", "zp-empty", "Select a finding above, then a URL below it, to see the full request/response.");
  bottom.appendChild(inspectorEmptyMsg);
  const inspector = createInspector();
  inspector.element.hidden = true;
  bottom.appendChild(inspector.element);

  let allGroups = [];
  let filtered = [];
  let selectedGroupId = null;
  let selectedEntryId = null;

  function matchesSearch(group, q) {
    if (!q) return true;
    const needle = q.toLowerCase();
    if (group.title.toLowerCase().includes(needle) || group.detail.toLowerCase().includes(needle)) return true;
    return group.occurrences.some((o) => o.entry.request.url.toLowerCase().includes(needle));
  }

  function sortValue(group, key) {
    switch (key) {
      case "severity":
        return SEVERITY_ORDER.indexOf(group.severity);
      case "title":
        return group.title;
      case "count":
        return group.occurrences.length;
      default:
        return "";
    }
  }

  function applyFilters() {
    filtered = allGroups.filter((g) => {
      if (!filters.severities.has(g.severity)) return false;
      if (!matchesSearch(g, filters.search)) return false;
      return true;
    });
    filtered.sort((a, b) => {
      const av = sortValue(a, filters.sortKey);
      const bv = sortValue(b, filters.sortKey);
      const cmp = av > bv ? 1 : av < bv ? -1 : 0;
      return filters.sortDir === "asc" ? cmp : -cmp;
    });
    for (const chip of toolbar.querySelectorAll(".zp-filter-chip")) {
      const sev = chip.dataset.severity;
      const n = allGroups.filter((g) => g.severity === sev).length;
      chip.textContent = `${sev.charAt(0).toUpperCase() + sev.slice(1)} ${n}`;
      chip.classList.toggle("active", filters.severities.has(sev));
      chip.setAttribute("aria-pressed", String(filters.severities.has(sev)));
    }
    renderRows();
  }

  exportBtn.addEventListener("click", async () => {
    const report = buildFindingsMarkdown(filtered, { version: chrome.runtime.getManifest().version });
    await downloadText(`zproxy-findings-${Date.now()}.md`, report, "text/markdown");
  });

  function renderRows() {
    tbody.textContent = "";
    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columns.length;
      td.className = "zp-empty";
      td.textContent =
        allGroups.length === 0
          ? "No passive findings in History yet."
          : filters.severities.size === 0
            ? "Every severity is switched off — turn one back on above."
            : "No findings match the current filters.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const group of filtered) {
      const tr = document.createElement("tr");
      tr.className = `zp-sev-${group.severity}${group.id === selectedGroupId ? " selected" : ""}`;
      tr.addEventListener("click", () => selectGroup(group));
      const sevTd = document.createElement("td");
      sevTd.appendChild(severityBadge(group.severity));
      tr.appendChild(sevTd);
      tr.appendChild(el("td", "", group.title));
      tr.appendChild(el("td", "", String(group.occurrences.length)));
      tbody.appendChild(tr);
    }
  }

  function deselectEntry() {
    selectedEntryId = null;
    inspectorEmptyMsg.hidden = false;
    inspector.element.hidden = true;
  }

  function selectGroup(group) {
    selectedGroupId = group.id;
    renderRows();
    deselectEntry();

    selectedCard.hidden = false;
    selectedCard.textContent = "";
    const title = el("div", "zp-finding-title");
    title.appendChild(severityBadge(group.severity));
    title.appendChild(document.createTextNode(group.title));
    selectedCard.appendChild(title);
    selectedCard.appendChild(el("div", "zp-finding-detail", group.detail));
    const urlCount = new Set(group.occurrences.map((o) => o.entry.request.url)).size;
    selectedCard.appendChild(
      el("div", "zp-finding-detail", `Seen ${group.occurrences.length} time${group.occurrences.length === 1 ? "" : "s"}, across ${urlCount} distinct URL${urlCount === 1 ? "" : "s"}.`)
    );

    urlList.hidden = false;
    urlList.textContent = "";
    for (const { entry } of group.occurrences) {
      const { host, path } = hostAndPath(entry.request.url);
      const card = el("div", "zp-pending-card" + (entry.id === selectedEntryId ? " selected" : ""));
      const summary = el("div", "zp-pending-summary");
      summary.appendChild(el("span", "zp-badge", entry.request.method || ""));
      summary.appendChild(el("span", "", `${host}${path}`));
      summary.appendChild(el("span", "zp-mono-small", new Date(entry.startedAt || 0).toLocaleTimeString()));
      summary.addEventListener("click", () => {
        selectedEntryId = entry.id;
        for (const c of urlList.children) c.classList.remove("selected");
        card.classList.add("selected");
        inspectorEmptyMsg.hidden = true;
        inspector.element.hidden = false;
        inspector.setItem(withBodyUnavailable(entry), { requestEditable: false, responseEditable: false, defaultTab: "response" });
      });
      card.appendChild(summary);
      urlList.appendChild(card);
    }
  }

  searchInput.addEventListener("input", () => {
    filters.search = searchInput.value;
    applyFilters();
  });
  for (const btn of toolbar.querySelectorAll(".zp-filter-chip")) {
    btn.addEventListener("click", () => {
      const sev = btn.dataset.severity;
      if (filters.severities.has(sev)) filters.severities.delete(sev);
      else filters.severities.add(sev);
      ctx.sharedState.findingsSeverities = [...filters.severities];
      applyFilters();
    });
  }

  let refreshToken = 0;
  async function refresh() {
    const myToken = ++refreshToken;
    const entries = await ctx.api("history:get");
    if (myToken !== refreshToken) return;
    allGroups = groupFindings(entries);
    applyFilters();
  }
  refresh();

  const refreshSoon = coalesced(refresh);
  const unsub = ctx.onPush((event) => {
    if (event.type === "history:new-entry" || event.type === "history:entry-updated") refreshSoon();
  });
  return () => {
    unsub();
    refreshSoon.cancel();
  };
}
