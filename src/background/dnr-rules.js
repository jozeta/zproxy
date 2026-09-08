// Translates "static" match/replace rules into declarativeNetRequest dynamic
// rules. This path needs no debugger and runs even when the side panel is
// closed — see docs/CAPABILITIES.md rows 3/5.
//
// Important, honest limitation: DNR conditions can only inspect the URL,
// method, and resource type — never the CURRENT value of a header or the
// body. So a "static" header rule always SETS a header unconditionally
// (optionally gated by a URL filter); it cannot say "if the header currently
// contains X". That kind of content-conditional rewrite is what the
// "content" engine rules (src/interception/match-replace.js) are for, and
// those require Intercept/debugger mode to see the actual bytes.
import { getRules } from "../storage/rules.js";

const RULE_ID_BASE = 10000;
const ALL_RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "stylesheet",
  "script",
  "image",
  "font",
  "object",
  "xmlhttprequest",
  "ping",
  "csp_report",
  "media",
  "websocket",
  "other",
];

function urlFilterToDnrCondition(urlFilter) {
  if (!urlFilter) return {};
  if (urlFilter.length > 1 && urlFilter.startsWith("/") && urlFilter.endsWith("/")) {
    return { regexFilter: urlFilter.slice(1, -1) };
  }
  return { urlFilter: `*${urlFilter}*` };
}

function toDnrRule(rule, index) {
  if (!rule.enabled || rule.engine !== "static") return null;
  const condition = { ...urlFilterToDnrCondition(rule.urlFilter), resourceTypes: ALL_RESOURCE_TYPES };

  if (rule.location === "header" && rule.headerName) {
    const headerEntry =
      rule.staticAction === "remove"
        ? { header: rule.headerName, operation: "remove" }
        : { header: rule.headerName, operation: "set", value: rule.staticValue ?? "" };
    return {
      id: RULE_ID_BASE + index,
      priority: 1,
      condition,
      action: {
        type: "modifyHeaders",
        ...(rule.scope === "response" ? { responseHeaders: [headerEntry] } : { requestHeaders: [headerEntry] }),
      },
    };
  }

  if (rule.location === "url" && rule.scope === "request" && rule.staticValue) {
    return {
      id: RULE_ID_BASE + index,
      priority: 1,
      condition,
      action: { type: "redirect", redirect: { url: rule.staticValue } },
    };
  }

  return null;
}

export async function syncDnrRules() {
  const rules = await getRules();
  const addRules = rules.map(toDnrRule).filter(Boolean);
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((r) => r.id);
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  return addRules;
}
