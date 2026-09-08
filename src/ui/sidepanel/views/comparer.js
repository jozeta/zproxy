// Word-level diff of two arbitrary blobs of text — Burp/ZAP "Comparer"
// equivalent. Either side can be typed/pasted directly, or loaded from a
// History entry or an open Repeater tab (as raw request/response text, via
// the same requestToRawHttp/responseToRawHttp used by the inspector's Raw
// tab) as a shortcut.
import { infoIcon } from "../../components/tooltip.js";
import { requestToRawHttp, responseToRawHttp } from "../../../parsers/http.js";
import { diffText } from "../../../parsers/diff.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function buildSide(ctx, label) {
  const col = el("div", "zp-comparer-col");
  col.appendChild(el("div", "zp-col-title", label));

  const loadRow = el("div", "zp-form-row");
  const sourceSelect = document.createElement("select");
  sourceSelect.appendChild(el("option", "", "— paste manually below —"));
  loadRow.appendChild(sourceSelect);
  const partSelect = document.createElement("select");
  for (const opt of ["Request", "Response"]) partSelect.appendChild(el("option", "", opt));
  loadRow.appendChild(partSelect);
  const loadBtn = el("button", "zp-btn zp-btn-small", "Load");
  loadBtn.type = "button";
  loadRow.appendChild(loadBtn);
  col.appendChild(loadRow);

  const textarea = document.createElement("textarea");
  textarea.style.minHeight = "160px";
  textarea.placeholder = "Paste raw text here, or pick a source above and click Load.";
  col.appendChild(textarea);

  let sources = []; // [{ label, request, response }]

  async function refreshSources() {
    const history = await ctx.api("history:get").catch(() => []);
    const repeaterTabs = ctx.sharedState.repeaterTabs || [];
    sources = [
      ...history
        .slice()
        .reverse()
        .slice(0, 50)
        .map((e) => ({ label: `History: ${e.request.method} ${e.request.url}`, request: e.request, response: e.response })),
      ...repeaterTabs.map((t) => ({ label: `Repeater #${t.id}: ${t.request.method} ${t.request.url}`, request: t.request, response: t.response })),
    ];
    const current = sourceSelect.value;
    sourceSelect.textContent = "";
    sourceSelect.appendChild(el("option", "", "— paste manually below —"));
    sources.forEach((s, idx) => {
      const opt = el("option", "", s.label);
      opt.value = String(idx);
      sourceSelect.appendChild(opt);
    });
    if ([...sourceSelect.options].some((o) => o.value === current)) sourceSelect.value = current;
  }

  function loadSource(source, part) {
    if (!source) return;
    if (part === "Request") {
      textarea.value = requestToRawHttp(source.request);
    } else if (source.response) {
      textarea.value = responseToRawHttp(source.response);
    } else {
      textarea.value = "";
      window.alert("That source has no response yet.");
    }
  }

  loadBtn.addEventListener("click", () => loadSource(sources[Number(sourceSelect.value)], partSelect.value));

  return {
    element: col,
    textarea,
    refreshSources,
    // Used by "Send to Comparer" (History/Intercept) to drop a {request,
    // response} pair straight into this side without going through the
    // History/Repeater picker dropdown above.
    loadPair(pair) {
      loadSource(pair, pair.response ? "Response" : "Request");
    },
  };
}

export function renderComparer(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Comparer"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Word-level diff of two arbitrary pieces of text — paste directly, or load a raw request/response from History or an open Repeater tab. Useful for spotting exactly what changed between two responses (e.g. a valid vs. invalid session, or before/after a payload)."
    )
  );

  const row = el("div", "zp-comparer-row");
  const left = buildSide(ctx, "A");
  const right = buildSide(ctx, "B");
  row.appendChild(left.element);
  row.appendChild(right.element);
  container.appendChild(row);

  const toolbar = el("div", "zp-toolbar");
  const compareBtn = el("button", "zp-btn zp-btn-primary zp-btn-small", "Compare");
  compareBtn.type = "button";
  toolbar.appendChild(compareBtn);
  toolbar.appendChild(
    infoIcon("Diffs A against B word-by-word. Struck-through red text was only in A; underlined green text is only in B.", { label: "About Compare" })
  );
  container.appendChild(toolbar);

  const truncatedNotice = el("div", "zp-warning", "");
  truncatedNotice.hidden = true;
  container.appendChild(truncatedNotice);

  container.appendChild(el("div", "zp-subheading", "Diff"));
  const diffEmpty = el("div", "zp-empty", "Click Compare to see the difference.");
  container.appendChild(diffEmpty);
  const diffView = el("pre", "zp-diff-view");
  diffView.hidden = true;
  container.appendChild(diffView);

  compareBtn.addEventListener("click", () => {
    const { segments, truncated } = diffText(left.textarea.value, right.textarea.value);
    truncatedNotice.hidden = !truncated;
    if (truncated) {
      truncatedNotice.textContent = "⚠ One side is too large for a full word-level diff — showing the two sides as whole removed/added blocks instead.";
    }
    diffEmpty.hidden = true;
    diffView.hidden = false;
    diffView.textContent = "";
    for (const seg of segments) {
      if (seg.type === "equal") {
        diffView.appendChild(document.createTextNode(seg.text));
      } else {
        const span = document.createElement("span");
        span.className = seg.type === "removed" ? "zp-diff-removed" : "zp-diff-added";
        span.textContent = seg.text;
        diffView.appendChild(span);
      }
    }
  });

  left.refreshSources();
  right.refreshSources();

  // Drain "Send to Comparer" hand-offs from History/Intercept — the first
  // queued item fills whichever side is currently empty (A first), a
  // second fills the other, so "send this, then send that" naturally
  // builds an A/B pair without the user touching the picker above.
  if (ctx.sharedState.comparerQueue && ctx.sharedState.comparerQueue.length) {
    for (const queued of ctx.sharedState.comparerQueue.splice(0, ctx.sharedState.comparerQueue.length)) {
      const target = !left.textarea.value.trim() ? left : right;
      target.loadPair(queued);
    }
  }
}
