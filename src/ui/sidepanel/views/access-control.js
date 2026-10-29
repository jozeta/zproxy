// Access Control: Autorize/AuthMatrix-style authorization testing. Replays
// History requests (captured as whoever you're logged in as) once as-is and
// once per configured identity, and flags where another identity got the
// same thing the original user did. Pure logic lives in
// src/authz/access-control.js; sending goes through http-send.js, whose DNR
// override is what lets an identity's Cookie replace the browser's own.
import { infoIcon } from "../../components/tooltip.js";
import { sendRequest } from "../../components/http-send.js";
import { UNAUTHENTICATED_IDENTITY, applyIdentity, selectCandidates, judgeReplay, isSafeMethod } from "../../../authz/access-control.js";
import { hostAndPath, responseToRawHttp } from "../../../parsers/http.js";
import { diffText } from "../../../parsers/diff.js";

const MAX_STORED_BODY = 200_000;
const VERDICT_BADGES = {
  bypassed: ["zp-badge zp-badge-danger", "bypassed?"],
  different: ["zp-badge zp-badge-warn", "check"],
  enforced: ["zp-badge zp-badge-info", "enforced"],
  error: ["zp-badge zp-badge-warn", "error"],
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

let nextIdentityId = 1;

/** Keeps memory bounded across a large run — a result only needs enough body to compare and diff. */
function compact(result) {
  if (!result.ok) return { ok: false, error: result.error, response: null };
  const r = result.response;
  return { ok: true, response: { ...r, body: r.body.length > MAX_STORED_BODY ? r.body.slice(0, MAX_STORED_BODY) : r.body } };
}

export function renderAccessControl(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Access Control"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Finds broken access control: every matching History request is re-sent as captured, then once per identity below (e.g. a lower-privileged user, or no session at all), and the responses are compared. Browse the app as your highest-privileged user first so History holds the requests worth checking. Only test applications you're authorized to test."
    )
  );

  const state = (ctx.sharedState.accessControl ??= {
    identities: [],
    includeUnauthenticated: true,
    includeUnsafe: false,
    urlContains: "",
    rows: [],
    selected: null, // { rowIndex, identityId }
  });
  let abort = null;

  // --- Identities ---------------------------------------------------------
  const identitiesHeading = el("div", "zp-subheading", "Identities");
  identitiesHeading.appendChild(
    infoIcon(
      "Each identity is a set of headers that replace the captured request's own, one \"Name: value\" per line — typically another user's Cookie and/or Authorization. An empty value sends the request without that header. Headers you don't list are sent as captured. Kept in memory only (never saved to disk, since they're live session tokens) — gone when the side panel closes.",
      { label: "About identities" }
    )
  );
  container.appendChild(identitiesHeading);

  const unauthRow = el("div", "zp-checkbox-row");
  const unauthCheck = document.createElement("input");
  unauthCheck.type = "checkbox";
  unauthCheck.id = "ac-unauth";
  unauthCheck.checked = state.includeUnauthenticated;
  unauthCheck.addEventListener("change", () => (state.includeUnauthenticated = unauthCheck.checked));
  const unauthLabel = el("label", "", "Also test as Unauthenticated (no Cookie, no Authorization)");
  unauthLabel.htmlFor = unauthCheck.id;
  unauthRow.appendChild(unauthCheck);
  unauthRow.appendChild(unauthLabel);
  container.appendChild(unauthRow);

  const identityList = el("div");
  container.appendChild(identityList);

  function renderIdentities() {
    identityList.textContent = "";
    for (const identity of state.identities) {
      const card = el("div", "zp-rule-card");
      const nameRow = el("div", "zp-form-row");
      const nameInput = document.createElement("input");
      nameInput.type = "text";
      nameInput.value = identity.name;
      nameInput.placeholder = "Identity name, e.g. Regular user";
      nameInput.addEventListener("input", () => (identity.name = nameInput.value));
      const removeBtn = el("button", "zp-icon-btn", "✕");
      removeBtn.type = "button";
      removeBtn.title = "Remove identity";
      removeBtn.addEventListener("click", () => {
        state.identities.splice(state.identities.indexOf(identity), 1);
        renderIdentities();
      });
      nameRow.appendChild(nameInput);
      nameRow.appendChild(removeBtn);
      card.appendChild(nameRow);
      const headersArea = document.createElement("textarea");
      headersArea.placeholder = "Cookie: session=…\nAuthorization: Bearer …";
      headersArea.value = identity.headersText;
      headersArea.addEventListener("input", () => (identity.headersText = headersArea.value));
      card.appendChild(headersArea);
      identityList.appendChild(card);
    }
  }
  renderIdentities();

  const addIdentityBtn = el("button", "zp-btn zp-btn-small", "+ Add identity");
  addIdentityBtn.type = "button";
  addIdentityBtn.addEventListener("click", () => {
    state.identities.push({ id: `identity-${nextIdentityId++}`, name: `User ${state.identities.length + 2}`, headersText: "Cookie: " });
    renderIdentities();
  });
  container.appendChild(addIdentityBtn);

  // --- What to test -------------------------------------------------------
  container.appendChild(el("div", "zp-subheading", "Requests"));
  const filterRow = el("div", "zp-form-row");
  filterRow.appendChild(el("label", "", "URL contains"));
  const urlInput = document.createElement("input");
  urlInput.type = "text";
  urlInput.placeholder = "/api/ (empty = every in-scope History request)";
  urlInput.value = state.urlContains;
  urlInput.addEventListener("input", () => (state.urlContains = urlInput.value));
  filterRow.appendChild(urlInput);
  filterRow.appendChild(
    infoIcon("Static assets (images, CSS, fonts, scripts, media) are always skipped, and each method + URL is tested once (its newest capture).", { label: "About request selection" })
  );
  container.appendChild(filterRow);

  const unsafeRow = el("div", "zp-checkbox-row");
  const unsafeCheck = document.createElement("input");
  unsafeCheck.type = "checkbox";
  unsafeCheck.id = "ac-unsafe";
  unsafeCheck.checked = state.includeUnsafe;
  unsafeCheck.addEventListener("change", () => (state.includeUnsafe = unsafeCheck.checked));
  const unsafeLabel = el("label", "", "Include state-changing methods (POST, PUT, PATCH, DELETE, …)");
  unsafeLabel.htmlFor = unsafeCheck.id;
  unsafeRow.appendChild(unsafeCheck);
  unsafeRow.appendChild(unsafeLabel);
  unsafeRow.appendChild(
    infoIcon(
      "Off by default: each request is sent once per identity PLUS once as the original user, so a POST that creates/deletes something runs several times for real. Only enable on a test environment whose data you can lose.",
      { label: "About state-changing methods" }
    )
  );
  container.appendChild(unsafeRow);

  const runRow = el("div", "zp-pending-actions");
  const runBtn = el("button", "zp-btn zp-btn-primary zp-btn-small", "Run checks");
  runBtn.type = "button";
  const stopBtn = el("button", "zp-btn zp-btn-small zp-btn-danger", "Stop");
  stopBtn.type = "button";
  stopBtn.disabled = true;
  const progress = el("span", "zp-mono-small", "");
  runRow.appendChild(runBtn);
  runRow.appendChild(stopBtn);
  runRow.appendChild(progress);
  container.appendChild(runRow);

  // --- Results ------------------------------------------------------------
  const resultsHost = el("div");
  container.appendChild(resultsHost);
  const detailHost = el("div");
  container.appendChild(detailHost);

  function activeIdentities() {
    const list = state.identities.filter((i) => i.headersText.trim());
    return state.includeUnauthenticated ? [UNAUTHENTICATED_IDENTITY, ...list] : list;
  }

  function cellFor(row, identity) {
    const td = document.createElement("td");
    const replay = row.replays[identity.id];
    if (!replay) {
      td.textContent = "…";
      return td;
    }
    td.appendChild(el("span", "zp-mono-small", replay.ok ? `${replay.response.statusCode} · ${replay.response.body.length}b ` : "failed "));
    const verdict = judgeReplay(row.original.ok ? row.original.response : null, replay.ok ? replay.response : null);
    const badge = VERDICT_BADGES[verdict];
    if (badge) td.appendChild(el("span", badge[0], badge[1]));
    td.style.cursor = "pointer";
    td.addEventListener("click", () => {
      state.selected = { rowIndex: state.rows.indexOf(row), identityId: identity.id };
      renderDetail();
    });
    return td;
  }

  function renderResults() {
    resultsHost.textContent = "";
    if (state.rows.length === 0) return;
    const identities = state.rowsIdentities || [];
    const table = el("table", "zp-table");
    const thead = document.createElement("thead");
    const head = document.createElement("tr");
    for (const title of ["Method", "Host / path", "Original", ...identities.map((i) => i.name || "(unnamed)")]) head.appendChild(el("th", "", title));
    thead.appendChild(head);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    for (const row of state.rows) {
      const tr = document.createElement("tr");
      tr.appendChild(el("td", `zp-method zp-method-${row.request.method}`, row.request.method));
      const { host, path } = hostAndPath(row.request.url);
      tr.appendChild(el("td", "zp-mono-small", `${host}${path}`));
      tr.appendChild(el("td", "zp-mono-small", !row.original ? "…" : row.original.ok ? `${row.original.response.statusCode} · ${row.original.response.body.length}b` : "failed"));
      for (const identity of identities) tr.appendChild(cellFor(row, identity));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    resultsHost.appendChild(table);
    resultsHost.appendChild(
      el("p", "zp-hint", "bypassed? = this identity got what the original user got — confirm by hand before reporting. check = a different response worth a look. Click a cell to diff it against the original.")
    );
  }

  function renderDetail() {
    detailHost.textContent = "";
    const sel = state.selected;
    const row = sel && state.rows[sel.rowIndex];
    const replay = row?.replays[sel.identityId];
    if (!row || !replay || !row.original) return;
    const identity = (state.rowsIdentities || []).find((i) => i.id === sel.identityId);
    detailHost.appendChild(el("div", "zp-subheading", `${row.request.method} ${row.request.url} — original vs ${identity?.name || "identity"}`));
    if (!row.original.ok || !replay.ok) {
      detailHost.appendChild(el("div", "zp-warning", `⚠ ${!row.original.ok ? `Original send failed: ${row.original.error}` : `Replay failed: ${replay.error}`}`));
      return;
    }
    const { segments, truncated } = diffText(responseToRawHttp(row.original.response), responseToRawHttp(replay.response));
    if (truncated) detailHost.appendChild(el("div", "zp-warning", "⚠ Too large for a word-level diff — showing both as whole blocks."));
    const view = el("pre", "zp-diff-view");
    for (const seg of segments) {
      if (seg.type === "equal") view.appendChild(document.createTextNode(seg.text));
      else view.appendChild(el("span", seg.type === "removed" ? "zp-diff-removed" : "zp-diff-added", seg.text));
    }
    detailHost.appendChild(view);
  }

  async function run() {
    const identities = activeIdentities();
    if (identities.length === 0) {
      progress.textContent = "Add an identity with at least one header, or tick Unauthenticated.";
      return;
    }
    const history = await ctx.api("history:get");
    const candidates = selectCandidates(history, { includeUnsafe: state.includeUnsafe, urlContains: state.urlContains });
    if (candidates.length === 0) {
      progress.textContent = "No History requests match. Browse the target app (in Scope) first, or loosen the URL filter.";
      return;
    }
    const total = candidates.length * (identities.length + 1);
    const hosts = [...new Set(candidates.map((c) => hostAndPath(c.request.url).host))];
    const unsafeCount = candidates.filter((c) => !isSafeMethod(c.request.method)).length;
    const warning = unsafeCount ? `\n\n${unsafeCount} of them use state-changing methods and will each run ${identities.length + 1} times.` : "";
    if (!window.confirm(`Send ${total} real requests (${candidates.length} requests × ${identities.length + 1}) to ${hosts.join(", ")}?${warning}`)) return;

    abort = new AbortController();
    runBtn.disabled = true;
    stopBtn.disabled = false;
    state.rowsIdentities = identities.map((i) => ({ id: i.id, name: i.name }));
    state.rows = candidates.map((c) => ({ request: c.request, original: null, replays: {} }));
    state.selected = null;
    detailHost.textContent = "";
    renderResults();
    let done = 0;
    try {
      for (const row of state.rows) {
        if (abort.signal.aborted) break;
        row.original = compact(await sendRequest(row.request, { signal: abort.signal }));
        progress.textContent = `${++done}/${total}`;
        for (const identity of identities) {
          if (abort.signal.aborted) break;
          row.replays[identity.id] = compact(await sendRequest(applyIdentity(row.request, identity), { signal: abort.signal }));
          progress.textContent = `${++done}/${total}`;
        }
        renderResults();
      }
      progress.textContent = abort.signal.aborted ? `Stopped at ${done}/${total}.` : `Done — ${total} requests.`;
    } finally {
      abort = null;
      runBtn.disabled = false;
      stopBtn.disabled = true;
    }
  }

  runBtn.addEventListener("click", () => run());
  stopBtn.addEventListener("click", () => abort?.abort());

  renderResults();
  renderDetail();
  return () => abort?.abort();
}
