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
//
// Scope: DNR applies rules browser-wide unless the condition itself narrows
// them, so every rule is gated on requestDomains derived from Scope here —
// otherwise a static "set Authorization" rule would be sent to every site
// the tester visits (docs/THREAT_MODEL.md C2). requestDomains can't express
// everything scope.js can, so the translation errs toward matching LESS:
//  - "*.example.com" -> "example.com" (same set: DNR also matches subdomains)
//  - "example.com"   -> "example.com" (slightly broader: DNR also matches
//    its subdomains — the one unavoidable approximation)
//  - a mid-pattern wildcard ("api-*.example.com") can't be expressed at all
//    and is skipped, so those hosts get no static rules (fails closed)
//  - a pattern restricted by scheme, port, or path ("example.com/api/")
//    can't be expressed either — requestDomains is host-only — so as an
//    Include it's skipped (static rules never reach that host's other
//    paths). As an Exclude it's ignored: excluding the whole host instead
//    would switch static rules off for the very target being tested, and
//    the host is in Scope via some other Include anyway, so this never lets
//    a rule reach an out-of-scope HOST.
// Excludes map the same way into excludedRequestDomains, where "also
// matches subdomains" only ever excludes more. No usable include -> no
// static rules at all, matching isInScope()'s fail-closed behavior.
import { getRules, getScope } from "../storage/rules.js";
import { isHostOnlyPattern } from "./scope.js";

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

/** Scope host pattern -> DNR domain, or null when DNR can't express it. */
export function scopePatternToDnrDomain(pattern) {
  if (!isHostOnlyPattern(pattern)) return null;
  const p = (pattern || "").trim().toLowerCase();
  const domain = p.startsWith("*.") ? p.slice(2) : p;
  if (!domain || domain.includes("*")) return null;
  return domain;
}

/** {requestDomains, excludedRequestDomains?} for a scope config, or null when nothing is in scope. */
export function scopeToDnrDomains(scope) {
  if (!scope?.enabled) return null;
  const requestDomains = [...new Set((scope.include || []).map(scopePatternToDnrDomain).filter(Boolean))];
  if (requestDomains.length === 0) return null;
  const excludedRequestDomains = [...new Set((scope.exclude || []).map(scopePatternToDnrDomain).filter(Boolean))];
  return excludedRequestDomains.length ? { requestDomains, excludedRequestDomains } : { requestDomains };
}

export function toDnrRule(rule, index, scopeDomains) {
  if (!rule.enabled || rule.engine !== "static" || !scopeDomains) return null;
  const condition = { ...urlFilterToDnrCondition(rule.urlFilter), ...scopeDomains, resourceTypes: ALL_RESOURCE_TYPES };

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

// Serialized: each sync removes every existing id and re-adds the same
// RULE_ID_BASE+index ids, so two overlapping syncs (a rules save racing a
// scope save) could interleave into a duplicate-id rejection.
let syncChain = Promise.resolve();

export function syncDnrRules() {
  const run = syncChain.then(syncDnrRulesNow);
  syncChain = run.catch(() => {});
  return run;
}

async function syncDnrRulesNow() {
  const [rules, scope] = await Promise.all([getRules(), getScope()]);
  const scopeDomains = scopeToDnrDomains(scope);
  const addRules = rules.map((rule, index) => toDnrRule(rule, index, scopeDomains)).filter(Boolean);
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((r) => r.id);
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  return addRules;
}
