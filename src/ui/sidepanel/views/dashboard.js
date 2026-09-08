import { infoIcon } from "../../components/tooltip.js";
import { checkResponse } from "../../../parsers/passive-checks.js";

export function renderDashboard(container, ctx) {
  container.textContent = "";
  const title = document.createElement("h2");
  title.className = "zp-view-title";
  title.textContent = "Dashboard";
  container.appendChild(title);

  const hint = document.createElement("p");
  hint.className = "zp-hint";
  hint.textContent =
    "ZProxy's core workflow: set a Scope → turn Intercept on for this tab → browse → edit the paused request/response → forward it.";
  container.appendChild(hint);

  const grid = document.createElement("div");
  grid.className = "zp-dashboard-grid";
  container.appendChild(grid);

  function statCard(label, info, onClick) {
    const card = document.createElement("div");
    card.className = "zp-stat-card";
    const value = document.createElement("div");
    value.className = "zp-stat-value";
    value.textContent = "…";
    const lbl = document.createElement("div");
    lbl.className = "zp-stat-label";
    const lblText = document.createElement("span");
    lblText.textContent = label;
    lbl.appendChild(lblText);
    if (info) lbl.appendChild(infoIcon(info, { label: `About ${label}` }));
    card.appendChild(value);
    card.appendChild(lbl);
    if (onClick) {
      card.style.cursor = "pointer";
      card.title = "Click to see the full list";
      card.addEventListener("click", onClick);
    }
    grid.appendChild(card);
    return value;
  }

  const historyStat = statCard("Requests captured", "Total in-scope requests recorded in History since it was last cleared.", () => ctx.navigateTo("history"));
  const scopeStat = statCard("Scope patterns", "Number of Include patterns configured in Scope. \"off\" means Scope is disabled and nothing is captured.", () => ctx.navigateTo("scope"));
  const rulesStat = statCard("Active rules", "Enabled Match/Replace rules — both the always-on \"static\" engine and the Intercept-only \"content\" engine.", () => ctx.navigateTo("match-replace"));
  const interceptStat = statCard("Attached tabs", "How many browser tabs currently have Intercept's debugger attached.", () => ctx.navigateTo("intercept"));
  const findingsStat = statCard(
    "Passive findings",
    "Total passive security findings (missing security headers, cookie flags, secret-shaped strings in a body, reflected-unescaped request values, ...) across every captured History entry — zero-request heuristics, not a scanner. Click to see the full list.",
    () => ctx.navigateTo("findings")
  );

  // history:new-entry/intercept:event pushes can fire in rapid succession;
  // guard against an older, slower-resolving refresh() overwriting the
  // stats with stale data after a newer call already rendered fresher
  // ones. See the identical issue/fix in intercept.js.
  let refreshToken = 0;

  async function refresh() {
    const myToken = ++refreshToken;
    const [history, scope, rules, attachedTabs] = await Promise.all([
      ctx.api("history:get"),
      ctx.api("scope:get"),
      ctx.api("rules:get"),
      ctx.api("intercept:attachedTabs"),
    ]);
    if (myToken !== refreshToken) return;
    historyStat.textContent = String(history.length);
    scopeStat.textContent = scope.enabled ? String(scope.include.length) : "off";
    rulesStat.textContent = String(rules.filter((r) => r.enabled).length);
    interceptStat.textContent = String(attachedTabs.length);
    findingsStat.textContent = String(history.reduce((sum, e) => sum + checkResponse(e.request, e.response).length, 0));
  }
  refresh();

  const steps = document.createElement("ol");
  steps.style.color = "var(--text-dim)";
  steps.style.fontSize = "12px";
  steps.style.lineHeight = "1.8";
  for (const step of [
    "Open a tab on an app you're authorized to test, then click Intercept in the header — this attaches ZProxy and auto-adds that tab's host to Scope. Grant host access when prompted (ZProxy can't see anything without it).",
    "Browse the target app — paused requests appear under Intercept.",
    "Edit headers/body, then Forward, Drop, or send to Repeater.",
    "Everything (in scope) also lands in History for later review/export.",
    "Broaden or narrow Scope any time (e.g. *.example.com wildcards, or Exclude a host you don't want touched).",
  ]) {
    const li = document.createElement("li");
    li.textContent = step;
    steps.appendChild(li);
  }
  container.appendChild(steps);

  const unsub = ctx.onPush((event) => {
    if (event.type === "history:new-entry" || event.type === "intercept:event") refresh();
  });
  return unsub;
}
