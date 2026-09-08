// Pure rule-application logic, shared by:
//  - the declarativeNetRequest translator (for header/URL rules, no debugger needed)
//  - the debugger-based Fetch interceptors (for body rules, which have no
//    non-debugger path — see docs/CAPABILITIES.md row 6/10).
//
// Rule shape:
// {
//   id, name, enabled: boolean,
//   scope: "request" | "response",
//   location: "url" | "header" | "body",
//   headerName: string | null,   // required when location === "header"
//   matchType: "contains" | "regex",
//   match: string,
//   replace: string,
// }

export function compileRule(rule) {
  if (rule.matchType !== "regex") return { ...rule, regex: null, regexError: null };
  try {
    return { ...rule, regex: new RegExp(rule.match, "g"), regexError: null };
  } catch (err) {
    return { ...rule, regex: null, regexError: err.message };
  }
}

export function applyStringRule(rule, input) {
  if (!rule.enabled || typeof input !== "string" || !rule.match) return input;
  if (rule.matchType === "regex") {
    if (!rule.regex) return input;
    return input.replace(rule.regex, rule.replace ?? "");
  }
  return input.split(rule.match).join(rule.replace ?? "");
}

function relevantRules(rules, scope, location) {
  return rules.filter((r) => r.enabled && r.scope === scope && r.location === location).map(compileRule);
}

export function applyRulesToUrl(rules, url, scope = "request") {
  return relevantRules(rules, scope, "url").reduce((acc, rule) => applyStringRule(rule, acc), url);
}

export function applyRulesToHeaders(rules, headers, scope) {
  let result = headers.slice();
  for (const rule of relevantRules(rules, scope, "header")) {
    result = result.map((h) => {
      if (rule.headerName && h.name.toLowerCase() !== rule.headerName.toLowerCase()) return h;
      return { name: h.name, value: applyStringRule(rule, h.value) };
    });
  }
  return result;
}

export function applyRulesToBody(rules, body, scope) {
  if (typeof body !== "string") return body;
  return relevantRules(rules, scope, "body").reduce((acc, rule) => applyStringRule(rule, acc), body);
}

/** Supports plain substring matching, or /regex/ delimited by leading+trailing slashes. */
export function urlMatchesFilter(url, filter) {
  if (!filter) return true;
  if (filter.length > 1 && filter.startsWith("/") && filter.endsWith("/")) {
    try {
      return new RegExp(filter.slice(1, -1)).test(url);
    } catch {
      return false;
    }
  }
  return url.includes(filter);
}
