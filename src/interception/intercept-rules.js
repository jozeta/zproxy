// Conditional Intercept rules — narrows WHICH in-scope, in-stage request
// actually pauses for manual review, vs. auto-forwarding it (Match/Replace
// content rules still run regardless; this only controls whether a human
// sees it). An empty or all-disabled rule list means "pause everything" —
// today's behavior, unchanged — adding an enabled rule is what narrows it,
// never something required to keep the current default. Matches OR
// semantics across enabled rules, same mental model as Scope's include list.
export function defaultInterceptRule() {
  return { id: `intercept-rule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, enabled: true, field: "url", operator: "contains", value: "" };
}

export const INTERCEPT_RULE_FIELDS = ["url", "method", "body"];
export const INTERCEPT_RULE_OPERATORS = ["contains", "equals", "regex"];

function fieldValue(request, field) {
  switch (field) {
    case "url":
      return request?.url || "";
    case "method":
      return request?.method || "";
    case "body":
      return request?.body || "";
    default:
      return "";
  }
}

function ruleMatches(rule, request) {
  const haystack = fieldValue(request, rule.field);
  const needle = rule.value || "";
  switch (rule.operator) {
    case "contains":
      return haystack.toLowerCase().includes(needle.toLowerCase());
    case "equals":
      return haystack.toLowerCase() === needle.toLowerCase();
    case "regex":
      try {
        return new RegExp(needle).test(haystack);
      } catch {
        return false; // invalid pattern — never matches, rather than throwing mid-pause
      }
    default:
      return false;
  }
}

/**
 * True if `request` ({url, method, body}) should actually pause for manual
 * review, given the configured rules. No enabled rules at all -> pause
 * everything (the pre-existing, unnarrowed behavior). Otherwise: pauses iff
 * it matches at least one enabled rule.
 */
export function shouldPauseForRules(request, rules) {
  const enabled = (rules || []).filter((r) => r.enabled);
  if (enabled.length === 0) return true;
  return enabled.some((r) => ruleMatches(r, request));
}
