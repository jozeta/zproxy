import { makeResizable } from "../../components/resizable.js";
import { createInspector } from "../../components/inspector.js";
import { infoIcon } from "../../components/tooltip.js";
import { defaultInterceptRule, INTERCEPT_RULE_FIELDS, INTERCEPT_RULE_OPERATORS } from "../../../interception/intercept-rules.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function summaryFor(pendingItem) {
  if (pendingItem.kind === "request") {
    return `${pendingItem.request.method} ${pendingItem.request.url}`;
  }
  return `${pendingItem.response.statusCode} ${pendingItem.response.statusText || ""}  ←  ${pendingItem.request.method} ${pendingItem.request.url}`;
}

// Order-insensitive so re-rendering the header table (which doesn't change
// order on its own) never falsely reads as "edited".
function headersKey(headers) {
  return (headers || [])
    .map((h) => `${h.name.toLowerCase()}:${h.value}`)
    .sort()
    .join("\n");
}

function requestChanged(original, edited) {
  if (!edited) return false;
  return (
    original.method !== edited.method ||
    original.url !== edited.url ||
    (original.body ?? "") !== (edited.body ?? "") ||
    headersKey(original.headers) !== headersKey(edited.headers)
  );
}

function responseChanged(original, edited) {
  if (!edited) return false;
  return (
    String(original.statusCode) !== String(edited.statusCode) ||
    (original.statusText || "") !== (edited.statusText || "") ||
    (original.body ?? "") !== (edited.body ?? "") ||
    headersKey(original.headers) !== headersKey(edited.headers)
  );
}

export function renderIntercept(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Intercept"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Requests and responses paused while Intercept is attached (header toggle) and pausing is on, for whichever attached tab is selected below. Every in-scope request pauses by default — not just the one you're interested in — so a single page load can leave several items queued here; use Forward all pending to release the rest after handling the one you care about, or add a rule under \"Pause only when\" to narrow it down."
    )
  );

  const pauseRow = el("div", "zp-checkbox-row");
  const pauseCheckbox = document.createElement("input");
  pauseCheckbox.type = "checkbox";
  pauseCheckbox.id = "intercept-pause-toggle";
  const pauseLabel = document.createElement("label");
  pauseLabel.htmlFor = "intercept-pause-toggle";
  pauseLabel.textContent = "Pause intercepted traffic (uncheck to auto-forward after Match/Replace rules run)";
  pauseRow.appendChild(pauseCheckbox);
  pauseRow.appendChild(pauseLabel);
  pauseRow.appendChild(
    infoIcon("When checked, every in-scope request/response pauses here for manual review. Uncheck to let Match/Replace rules still run, but auto-forward everything instead of holding it.", { label: "About pausing" })
  );
  container.appendChild(pauseRow);

  const stageRow = el("div", "zp-form-row");
  stageRow.appendChild(el("label", "", "Intercept"));
  const stageSelect = document.createElement("select");
  for (const opt of [
    { value: "both", label: "Requests and responses" },
    { value: "request", label: "Requests only" },
    { value: "response", label: "Responses only" },
  ]) {
    const optionEl = document.createElement("option");
    optionEl.value = opt.value;
    optionEl.textContent = opt.label;
    stageSelect.appendChild(optionEl);
  }
  stageRow.appendChild(stageSelect);
  stageRow.appendChild(
    infoIcon("Which stage(s) actually pause. Excluding a stage means it never pauses at all for any attached tab — cheaper than pausing and immediately forwarding it.", { label: "About stage" })
  );
  container.appendChild(stageRow);
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "A stage left unselected never pauses at all for any tab Intercept is attached to (applies immediately, no need to reattach) — also in Settings."
    )
  );

  // ---------- Conditional Intercept rules ----------
  container.appendChild(el("div", "zp-subheading", "Pause only when (optional)"));
  const rulesHost = el("div", "zp-header-rows");
  container.appendChild(rulesHost);
  const rulesAddRow = el("div", "zp-toolbar");
  const addRuleBtn = el("button", "zp-btn zp-btn-small", "+ Add rule");
  addRuleBtn.type = "button";
  rulesAddRow.appendChild(addRuleBtn);
  rulesAddRow.appendChild(
    infoIcon(
      "Leave empty to pause everything in scope (today's default). Add a rule to narrow that down — a request pauses for manual review only if it matches at least one enabled rule below. Match/Replace content rules still run either way; this only controls whether a human sees it. Applies to every attached tab.",
      { label: "About Pause only when" }
    )
  );
  container.appendChild(rulesAddRow);

  let interceptRules = [];

  function saveInterceptRules() {
    return ctx.api("interceptRules:save", { interceptRules }).catch((err) => window.alert(`ZProxy: ${err.message}`));
  }

  function renderInterceptRules() {
    rulesHost.textContent = "";
    interceptRules.forEach((rule, idx) => {
      const row = el("div", "zp-header-row");

      const enabledInput = document.createElement("input");
      enabledInput.type = "checkbox";
      enabledInput.checked = rule.enabled;
      enabledInput.title = "Enabled";
      enabledInput.addEventListener("change", () => {
        rule.enabled = enabledInput.checked;
        saveInterceptRules();
      });
      row.appendChild(enabledInput);

      const fieldSelect = document.createElement("select");
      for (const f of INTERCEPT_RULE_FIELDS) {
        const opt = document.createElement("option");
        opt.value = f;
        opt.textContent = f === "url" ? "URL" : f[0].toUpperCase() + f.slice(1);
        fieldSelect.appendChild(opt);
      }
      fieldSelect.value = rule.field;
      fieldSelect.addEventListener("change", () => {
        rule.field = fieldSelect.value;
        saveInterceptRules();
      });
      row.appendChild(fieldSelect);

      const opSelect = document.createElement("select");
      for (const o of INTERCEPT_RULE_OPERATORS) {
        const opt = document.createElement("option");
        opt.value = o;
        opt.textContent = o === "contains" ? "contains" : o === "equals" ? "equals" : "matches regex";
        opSelect.appendChild(opt);
      }
      opSelect.value = rule.operator;
      opSelect.addEventListener("change", () => {
        rule.operator = opSelect.value;
        saveInterceptRules();
      });
      row.appendChild(opSelect);

      const valueInput = document.createElement("input");
      valueInput.type = "text";
      valueInput.className = "zp-header-value";
      valueInput.placeholder = rule.operator === "regex" ? "regex pattern" : "value";
      valueInput.value = rule.value;
      valueInput.addEventListener("change", () => {
        rule.value = valueInput.value;
        saveInterceptRules();
      });
      row.appendChild(valueInput);

      const delBtn = el("button", "zp-icon-btn", "✕");
      delBtn.type = "button";
      delBtn.title = "Remove rule";
      delBtn.addEventListener("click", () => {
        interceptRules.splice(idx, 1);
        renderInterceptRules();
        saveInterceptRules();
      });
      row.appendChild(delBtn);

      rulesHost.appendChild(row);
    });
  }

  addRuleBtn.addEventListener("click", () => {
    interceptRules.push(defaultInterceptRule());
    renderInterceptRules();
    saveInterceptRules();
  });

  // ---------- Which attached tab this view is managing ----------
  // Independent of the browser's actual active tab: the header toggle
  // always attaches/detaches whichever tab you're currently browsing, but
  // more than one tab can be attached at once, and this view should be able
  // to look at any of them without forcing you to physically switch tabs.
  const tabPickerRow = el("div", "zp-form-row");
  tabPickerRow.hidden = true;
  tabPickerRow.appendChild(el("label", "", "Managing tab"));
  const tabPickerSelect = document.createElement("select");
  tabPickerRow.appendChild(tabPickerSelect);
  tabPickerRow.appendChild(
    infoIcon("Intercept can be attached to more than one tab at once — pick which attached tab's paused items this view shows and acts on. The header toggle always attaches/detaches whichever tab is currently active in the browser.", { label: "About Managing tab" })
  );
  container.appendChild(tabPickerRow);

  let viewingTabId = null;
  let attachedTabsList = [];

  async function refreshAttachedTabsList() {
    attachedTabsList = await ctx.api("intercept:attachedTabs");
    tabPickerRow.hidden = attachedTabsList.length === 0;
    if (viewingTabId == null || !attachedTabsList.some((t) => t.id === viewingTabId)) {
      const activeId = ctx.getTab()?.id;
      viewingTabId = attachedTabsList.some((t) => t.id === activeId) ? activeId : attachedTabsList[0]?.id ?? null;
    }
    tabPickerSelect.textContent = "";
    for (const t of attachedTabsList) {
      const opt = document.createElement("option");
      opt.value = String(t.id);
      opt.textContent = t.title || t.url || `Tab #${t.id}`;
      tabPickerSelect.appendChild(opt);
    }
    if (viewingTabId != null) tabPickerSelect.value = String(viewingTabId);
  }

  tabPickerSelect.addEventListener("change", () => {
    viewingTabId = Number(tabPickerSelect.value);
    deselect();
    refresh();
  });

  const notAttachedNotice = el(
    "div",
    "zp-empty",
    "Intercept isn't attached to any tab. Use the Intercept toggle in the header to attach it."
  );
  container.appendChild(notAttachedNotice);

  // Out-of-scope traffic is dropped silently by design (fail-closed Scope —
  // see docs/THREAT_MODEL.md C2), but a tester watching nothing happen has
  // no way to tell that apart from "the extension is just broken." This
  // makes the actual reason visible instead.
  const scopeMismatchNotice = el("div", "zp-warning");
  const scopeMismatchText = el("span", "", "");
  const scopeMismatchGoBtn = el("button", "zp-btn zp-btn-small", "Go to Scope");
  scopeMismatchGoBtn.type = "button";
  scopeMismatchGoBtn.addEventListener("click", () => ctx.navigateTo("scope"));
  scopeMismatchNotice.appendChild(scopeMismatchText);
  scopeMismatchNotice.appendChild(document.createElement("br"));
  scopeMismatchNotice.appendChild(scopeMismatchGoBtn);
  scopeMismatchNotice.hidden = true;
  container.appendChild(scopeMismatchNotice);

  const split = el("div", "zp-split");
  split.hidden = true;
  const top = el("div", "zp-split-top");
  // Fetch.enable's patterns cover every URL at both stages, so a single
  // page load can pause many requests at once (the main document plus
  // every CSS/JS/image it references) — not just the one you care about.
  // Forwarding only that one leaves the rest sitting in the queue, which
  // can block the page from finishing rendering at all (a render-blocking
  // stylesheet, say) even though the edit you wanted genuinely went
  // through. This releases everything else, unmodified, in one click,
  // without detaching Intercept (so it's still attached for next time).
  const listToolbar = el("div", "zp-toolbar");
  const forwardAllBtn = el("button", "zp-btn zp-btn-small", "Forward all pending");
  forwardAllBtn.type = "button";
  forwardAllBtn.hidden = true;
  listToolbar.appendChild(forwardAllBtn);
  listToolbar.appendChild(
    infoIcon("Releases every currently paused item, unmodified, in one click — without detaching Intercept. Useful when a page load left several unrelated resources paused.", { label: "About Forward all pending" })
  );
  top.appendChild(listToolbar);
  const list = el("div", "zp-pending-list");
  top.appendChild(list);
  const bottom = el("div", "zp-split-bottom");
  split.appendChild(top);
  split.appendChild(bottom);
  container.appendChild(split);
  makeResizable(split, top, bottom, { storageKey: "zproxy.split.intercept", minTop: 70, minBottom: 140, label: "Resize pending list" });

  const actions = el("div", "zp-pending-actions");
  // A single Forward button that relabels itself "Forward edited" the
  // moment the inspector's contents differ from what was actually
  // captured — no separate button, no silently-discarded edits from
  // clicking the wrong one. It always sends whatever is currently in the
  // inspector, which is the original untouched values when nothing changed.
  const forwardBtn = el("button", "zp-btn zp-btn-primary zp-btn-small", "Forward");
  const sendToRepeaterBtn = el("button", "zp-btn zp-btn-small", "Send to Repeater");
  const sendToIntruderBtn = el("button", "zp-btn zp-btn-small", "Send to Intruder");
  const dropBtn = el("button", "zp-btn zp-btn-danger zp-btn-small", "Drop");
  // Renamed from "Forward & don't intercept again" — that label reads as
  // "stop intercepting entirely," which it never did: it only stops pausing
  // THIS exact method+URL going forward (Intercept itself, and every other
  // URL, keeps pausing normally). Header toggle / Forward all pending are
  // the actual "stop intercepting" controls.
  const dontInterceptBtn = el("button", "zp-btn zp-btn-small", "Forward & stop intercepting this URL");
  const sendToDecoderBtn = el("button", "zp-btn zp-btn-small", "Send to Decoder");
  const sendToComparerBtn = el("button", "zp-btn zp-btn-small", "Send to Comparer");
  for (const b of [forwardBtn, sendToRepeaterBtn, sendToIntruderBtn, dropBtn, dontInterceptBtn, sendToDecoderBtn, sendToComparerBtn]) b.type = "button";
  actions.appendChild(forwardBtn);
  actions.appendChild(infoIcon("Sends the item exactly as shown in the inspector below — relabels itself \"Forward edited\" the moment you change anything.", { label: "About Forward" }));
  actions.appendChild(sendToRepeaterBtn);
  actions.appendChild(infoIcon("Copies the (possibly edited) request into a new Repeater tab, without releasing this paused item.", { label: "About Send to Repeater" }));
  actions.appendChild(sendToIntruderBtn);
  actions.appendChild(infoIcon("Loads the (possibly edited) request as Intruder's base request for an automated attack, without releasing this paused item.", { label: "About Send to Intruder" }));
  actions.appendChild(sendToDecoderBtn);
  actions.appendChild(infoIcon("Loads the (possibly edited) body — response body for a response-stage item, request body otherwise — into Decoder, without releasing this paused item.", { label: "About Send to Decoder" }));
  actions.appendChild(sendToComparerBtn);
  actions.appendChild(infoIcon("Queues this (possibly edited) item into Comparer's next empty side (A, then B), without releasing this paused item.", { label: "About Send to Comparer" }));
  actions.appendChild(dontInterceptBtn);
  actions.appendChild(infoIcon("Forwards this item and stops pausing this exact method+URL going forward, for this session. Everything else keeps pausing normally.", { label: "About stop intercepting this URL" }));
  actions.appendChild(dropBtn);
  actions.appendChild(infoIcon("Fails the request/response instead of letting it reach the network or the page.", { label: "About Drop" }));
  bottom.appendChild(actions);

  const inspectorEmptyMsg = el("div", "zp-empty", "Select a paused item above.");
  bottom.appendChild(inspectorEmptyMsg);
  const inspector = createInspector();
  inspector.element.hidden = true;
  bottom.appendChild(inspector.element);
  // Delegated listener: any edit anywhere in the inspector (method/url,
  // header add/remove/toggle/edit, body, status) re-checks whether the
  // current contents differ from what was actually captured.
  inspector.element.addEventListener("input", updateForwardLabel);
  inspector.element.addEventListener("change", updateForwardLabel);
  inspector.element.addEventListener("click", updateForwardLabel);

  let pending = { requests: [], responses: [] };
  let selectedKey = null; // `${kind}:${fetchRequestId}`
  let attached = false;

  function allItems() {
    return [...pending.requests, ...pending.responses].sort((a, b) => a.pausedAt - b.pausedAt);
  }

  function keyOf(item) {
    return `${item.kind}:${item.fetchRequestId}`;
  }

  function selected() {
    return allItems().find((i) => keyOf(i) === selectedKey) || null;
  }

  function renderList() {
    list.textContent = "";
    const items = allItems();
    forwardAllBtn.hidden = items.length === 0;
    forwardAllBtn.textContent = `Forward all pending (${items.length})`;
    if (items.length === 0) {
      list.appendChild(el("div", "zp-empty", "No requests are currently paused."));
    }
    for (const item of items) {
      const card = el("div", "zp-pending-card" + (keyOf(item) === selectedKey ? " selected" : ""));
      const summary = el("div", "zp-pending-summary");
      summary.appendChild(el("span", "zp-badge", item.kind === "request" ? "REQ" : "RES"));
      summary.appendChild(el("span", "", summaryFor(item)));
      summary.addEventListener("click", () => selectItem(keyOf(item)));
      card.appendChild(summary);
      list.appendChild(card);
    }
    dontInterceptBtn.hidden = selected()?.kind !== "request";
  }

  function updateForwardLabel() {
    const item = selected();
    if (!item) {
      forwardBtn.textContent = "Forward";
      return;
    }
    const changed =
      item.kind === "request"
        ? requestChanged(item.request, inspector.getEditedRequest())
        : responseChanged(item.response, inspector.getEditedResponse());
    forwardBtn.textContent = changed ? "Forward edited" : "Forward";
  }

  function selectItem(key) {
    selectedKey = key;
    const item = selected();
    renderList();
    const hasSelection = !!item;
    inspectorEmptyMsg.hidden = hasSelection;
    inspector.element.hidden = !hasSelection;
    actions.hidden = !hasSelection;
    forwardBtn.textContent = "Forward";
    if (!item) return;
    if (item.kind === "request") {
      inspector.setItem(
        { request: item.request, response: null },
        { requestEditable: true, responseEditable: false, defaultTab: "request" }
      );
    } else {
      inspector.setItem(
        { request: item.request, response: item.response },
        { requestEditable: false, responseEditable: true, defaultTab: "response" }
      );
    }
  }

  // Clears the selection AND the visible inspector/actions state. Just
  // setting selectedKey = null wasn't enough: only selectItem() ever
  // touched inspectorEmptyMsg/inspector.element's `hidden`, so after
  // forwarding/dropping the item the inspector kept showing the
  // just-forwarded (now stale) request/response, making it look like
  // Forward had done nothing even though it had actually gone out.
  function deselect() {
    selectedKey = null;
    inspectorEmptyMsg.hidden = false;
    inspector.element.hidden = true;
    actions.hidden = true;
    renderList();
  }

  async function doAction(action) {
    const item = selected();
    if (!item) return;
    const tabId = viewingTabId;
    if (tabId == null) return;
    const kind = item.kind;
    const fetchRequestId = item.fetchRequestId;
    try {
      if (action === "forward") {
        // One button, driven by whether the inspector's current contents
        // actually differ from what was captured — never a separate
        // "unmodified" button a click could land on by mistake and silently
        // drop an edit. When nothing changed this still takes the cheaper
        // native pass-through (Fetch.continueRequest/continueResponse with
        // no overrides) rather than re-encoding everything through
        // fulfillRequest for no reason.
        const edited = kind === "request" ? inspector.getEditedRequest() : inspector.getEditedResponse();
        const changed = kind === "request" ? requestChanged(item.request, edited) : responseChanged(item.response, edited);
        if (changed) {
          await ctx.api("intercept:forwardEdited", { tabId, kind, fetchRequestId, edited });
        } else {
          await ctx.api("intercept:forward", { tabId, kind, fetchRequestId });
        }
      } else if (action === "drop") {
        await ctx.api("intercept:drop", { tabId, kind, fetchRequestId });
      } else if (action === "forwardAndDontInterceptAgain") {
        // This button is request-only (dontInterceptBtn.hidden otherwise).
        // Bug this replaces: it used to always send the ORIGINAL captured
        // request, silently discarding whatever was in the inspector.
        const edited = inspector.getEditedRequest();
        await ctx.api("intercept:forwardAndDontInterceptAgain", { tabId, fetchRequestId, edited });
      }
    } catch (err) {
      window.alert(`ZProxy: ${err.message}`);
    }
    deselect();
    await refresh();
    ctx.refreshInterceptBadge?.();
  }

  forwardBtn.addEventListener("click", () => doAction("forward"));
  dropBtn.addEventListener("click", () => doAction("drop"));
  dontInterceptBtn.addEventListener("click", () => doAction("forwardAndDontInterceptAgain"));
  forwardAllBtn.addEventListener("click", async () => {
    if (viewingTabId == null) return;
    const items = allItems();
    if (items.length === 0) return;
    if (
      !window.confirm(
        `Forward all ${items.length} pending item(s) unmodified? If you're mid-edit on one, forward it individually first — this sends the original captured values for everything, including whatever's currently selected.`
      )
    ) {
      return;
    }
    await Promise.all(
      items.map((item) =>
        ctx.api("intercept:forward", { tabId: viewingTabId, kind: item.kind, fetchRequestId: item.fetchRequestId }).catch(() => {})
      )
    );
    deselect();
    await refresh();
    ctx.refreshInterceptBadge?.();
  });
  sendToRepeaterBtn.addEventListener("click", () => {
    const item = selected();
    if (!item) return;
    // Copies the (possibly edited) request into Repeater without touching
    // the paused item itself — it's still sitting here for Forward/Drop.
    const request = item.kind === "request" ? inspector.getEditedRequest() || item.request : item.request;
    ctx.sharedState.repeaterQueue.push({ request });
    ctx.navigateTo("repeater");
  });
  sendToIntruderBtn.addEventListener("click", () => {
    const item = selected();
    if (!item) return;
    const request = item.kind === "request" ? inspector.getEditedRequest() || item.request : item.request;
    ctx.sharedState.intruderQueue.push({ request });
    ctx.navigateTo("intruder");
  });
  sendToDecoderBtn.addEventListener("click", () => {
    const item = selected();
    if (!item) return;
    const body =
      item.kind === "response"
        ? inspector.getEditedResponse()?.body ?? item.response?.body
        : inspector.getEditedRequest()?.body ?? item.request?.body;
    ctx.sharedState.decoderText = body || "";
    ctx.navigateTo("decoder");
  });
  sendToComparerBtn.addEventListener("click", () => {
    const item = selected();
    if (!item) return;
    const request = item.kind === "request" ? inspector.getEditedRequest() || item.request : item.request;
    const response = item.kind === "response" ? inspector.getEditedResponse() || item.response : item.response;
    ctx.sharedState.comparerQueue.push({ request, response });
    ctx.navigateTo("comparer");
  });

  pauseCheckbox.addEventListener("change", async () => {
    await ctx.api("settings:update", { patch: { manualPauseEnabled: pauseCheckbox.checked } });
  });

  stageSelect.addEventListener("change", async () => {
    await ctx.api("settings:update", { patch: { interceptStage: stageSelect.value } });
  });

  // Forwarding a request commonly triggers a near-immediate new pause (the
  // response-stage pause for that same request), which pushes an
  // intercept:event that fires the listener below and calls refresh() again
  // — while the refresh() from the Forward click may still be awaiting its
  // own RPC round-trips. Without guarding against that overlap, whichever
  // call's slowest await happens to resolve last "wins" and repaints the
  // list, which can be the *older* call clobbering the newer one's result
  // with stale data — visibly, a just-forwarded item that never disappears.
  // refreshToken makes every call check, after each await, whether a newer
  // refresh() has since started; if so it abandons itself instead of
  // touching shared state or the DOM.
  let refreshToken = 0;

  async function refresh() {
    const myToken = ++refreshToken;
    const settings = await ctx.api("settings:get");
    if (myToken !== refreshToken) return;
    pauseCheckbox.checked = settings.manualPauseEnabled;
    stageSelect.value = settings.interceptStage;

    await refreshAttachedTabsList();
    if (myToken !== refreshToken) return;
    tabPickerSelect.disabled = attachedTabsList.length === 0;

    if (viewingTabId == null) {
      attached = false;
      notAttachedNotice.hidden = false;
      split.hidden = true;
      scopeMismatchNotice.hidden = true;
      pending = { requests: [], responses: [] };
      if (selectedKey) deselect();
      return;
    }

    const status = await ctx.api("intercept:status", { tabId: viewingTabId });
    if (myToken !== refreshToken) return;
    attached = status.attached;
    notAttachedNotice.hidden = attached;
    split.hidden = !attached;
    actions.hidden = true;

    const stats = status.stats || { seen: 0, outOfScope: 0 };
    const allOutOfScope = attached && stats.seen > 0 && stats.outOfScope === stats.seen;
    scopeMismatchNotice.hidden = !allOutOfScope;
    if (allOutOfScope) {
      const viewingTab = attachedTabsList.find((t) => t.id === viewingTabId);
      let host = "";
      try {
        host = new URL(viewingTab?.url || "").hostname;
      } catch {
        /* tab URL may be a chrome:// page or similar */
      }
      scopeMismatchText.textContent = `⚠ ZProxy has seen ${stats.seen} request${stats.seen === 1 ? "" : "s"} on this tab since attaching, but every one was outside Scope, so none paused.${host ? ` Check that Scope includes "${host}".` : ""}`;
    }

    if (!attached) {
      pending = { requests: [], responses: [] };
      if (selectedKey) deselect();
      return;
    }
    pending = await ctx.api("intercept:pending", { tabId: viewingTabId });
    if (myToken !== refreshToken) return;
    if (selectedKey && !allItems().some((i) => keyOf(i) === selectedKey)) {
      // The previously-selected item is gone (forwarded/dropped elsewhere,
      // or timed out) — clear the stale inspector view instead of leaving
      // it showing an item that no longer exists.
      deselect();
      return;
    }
    // Deliberately NOT re-calling selectItem(selectedKey) here: this refresh
    // can be triggered by an unrelated event (e.g. a different resource on
    // the same tab pausing) while the user is mid-edit on the currently
    // selected item. selectItem() re-renders the inspector from the
    // original captured data, which would silently wipe out those edits.
    // renderList() alone already keeps the list's selected-highlight and
    // the "Forward & don't intercept again" button's visibility correct.
    renderList();
  }

  // Loaded once, not inside refresh(): refresh() can fire many times a
  // minute while items pause/resolve, and rebuilding rulesHost's inputs
  // from scratch every time would blow away an edit still in progress in
  // one of them (the same class of bug the pending-item selection comment
  // above already guards against). Add/remove/toggle already call
  // renderInterceptRules() themselves after mutating the array.
  async function loadInterceptRules() {
    interceptRules = (await ctx.api("interceptRules:get")) || [];
    renderInterceptRules();
  }
  loadInterceptRules();
  refresh();

  const unsub = ctx.onPush((event) => {
    if (event.type !== "intercept:event") return;
    if (event.event.type === "attached" || event.event.type === "detached") {
      // The set of attached tabs changed — could affect the tab picker
      // regardless of which tab this view currently happens to be showing.
      refresh();
      return;
    }
    if (event.event.tabId !== viewingTabId) return;
    refresh();
  });

  // Keyboard shortcuts (Settings > Keyboard shortcuts). Clicking these
  // buttons is a safe no-op when nothing is selected/visible — doAction()
  // and the click handlers already guard on selected() being null.
  const forwardShortcut = () => forwardBtn.click();
  const sendToRepeaterShortcut = () => sendToRepeaterBtn.click();
  ctx.sharedState.shortcutHandlers.forward = forwardShortcut;
  ctx.sharedState.shortcutHandlers.sendToRepeater = sendToRepeaterShortcut;

  return () => {
    unsub();
    const handlers = ctx.sharedState.shortcutHandlers;
    if (handlers.forward === forwardShortcut) delete handlers.forward;
    if (handlers.sendToRepeater === sendToRepeaterShortcut) delete handlers.sendToRepeater;
  };
}
