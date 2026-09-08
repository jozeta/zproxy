import { call } from "../components/api.js";
import { infoIcon } from "../components/tooltip.js";

const scopeBadge = document.getElementById("scope-badge");
const interceptToggle = document.getElementById("intercept-toggle");
const interceptLabel = document.getElementById("intercept-toggle-label");
const interceptRow = document.getElementById("intercept-row");
const tabInfo = document.getElementById("tab-info");
const openPanelBtn = document.getElementById("open-panel");
const openPanelRow = document.getElementById("open-panel-row");

scopeBadge.after(
  infoIcon("Which hosts ZProxy is allowed to see. Open the full panel's Scope tab to add or change hosts.", {
    label: "About Scope",
  })
);
interceptRow.appendChild(
  infoIcon(
    "Attaches ZProxy's debugger to this tab so its traffic can be paused and edited before it's sent. Also adds this tab's host to Scope automatically.",
    { label: "About Intercept" }
  )
);
openPanelRow.appendChild(
  infoIcon("Opens the full ZProxy side panel: History, Repeater, Cookies, Match/Replace rules, and Settings.", {
    label: "About the panel",
  })
);

let currentTab = null;

async function refreshScopeBadge() {
  try {
    const scope = await call("scope:get");
    const count = scope.enabled ? (scope.include || []).length : 0;
    scopeBadge.textContent = scope.enabled ? `Scope: ${count} pattern${count === 1 ? "" : "s"}` : "Scope: off";
    scopeBadge.classList.toggle("on", scope.enabled && count > 0);
  } catch {
    /* background not ready yet */
  }
}

// See the identical helper/comment in src/ui/sidepanel/app.js.
function isDebuggableUrl(url) {
  if (!url) return false;
  try {
    return ["http:", "https:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}

async function refreshInterceptState() {
  if (!currentTab) return;
  try {
    const { attached } = await call("intercept:status", { tabId: currentTab.id });
    interceptToggle.classList.toggle("on", attached);
    interceptLabel.textContent = attached ? "Intercept: ON" : "Intercept: OFF";
  } catch {
    interceptLabel.textContent = "Intercept: OFF";
  }
}

interceptToggle.addEventListener("click", async () => {
  if (!currentTab) return;
  const { attached } = await call("intercept:status", { tabId: currentTab.id });
  if (attached) {
    await call("intercept:detach", { tabId: currentTab.id });
  } else {
    if (!isDebuggableUrl(currentTab.url)) {
      window.alert(
        "ZProxy can't attach to this tab — it's a browser-internal or extension page, not a regular website. Switch to the site you want to test, then click Intercept again."
      );
      return;
    }
    const hasHosts = await call("permissions:hasHostAccess");
    if (!hasHosts && !(await call("permissions:requestHostAccess"))) return;
    let host = null;
    try {
      host = new URL(currentTab.url).hostname;
    } catch {
      /* chrome:// or similar — nothing to add to Scope */
    }
    const result = await call("intercept:attach", { tabId: currentTab.id, host });
    if (!result.ok) {
      const friendly = /chrome-extension:\/\/ URL of different extension/i.test(result.error)
        ? "this tab is showing another extension's page, which ZProxy isn't allowed to debug. Switch to the site you want to test and try again."
        : result.error;
      window.alert(`ZProxy could not attach the debugger: ${friendly}`);
    }
    refreshScopeBadge();
  }
  refreshInterceptState();
});

openPanelBtn.addEventListener("click", async () => {
  const win = await chrome.windows.getCurrent();
  await chrome.sidePanel.open({ windowId: win.id });
  window.close();
});

async function init() {
  [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabInfo.textContent = currentTab?.url || "";
  refreshScopeBadge();
  refreshInterceptState();
}

init();
