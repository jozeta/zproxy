// Turns the Findings view's grouped findings into a Markdown report — a
// starting point for a pentest write-up, not a finished one: every item is
// a passive heuristic that still needs manual confirmation, and the report
// says so up front.
import { SEVERITY_ORDER } from "./passive-checks.js";

const MAX_URLS_PER_FINDING = 25;

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Markdown-escapes the characters that would otherwise break a list item or inline code. */
function escapeMd(text) {
  return String(text).replace(/([\\`*_[\]<>|])/g, "\\$1");
}

/**
 * `groups` is [{ id, severity, title, detail, occurrences: [{ entry }] }]
 * (findings.js's groupFindings). Most severe first, then most frequent.
 */
export function buildFindingsMarkdown(groups, { generatedAt = new Date(), version = "" } = {}) {
  const sorted = [...groups].sort(
    (a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) || b.occurrences.length - a.occurrences.length
  );
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const g of sorted) counts[g.severity]++;

  const lines = [
    "# ZProxy passive findings",
    "",
    `Generated ${generatedAt.toISOString()}${version ? ` by ZProxy ${version}` : ""}.`,
    "",
    "These are passive, zero-request heuristics over captured traffic. Each one is a lead to confirm by hand, not a verified vulnerability — and finding nothing does not mean the application is secure.",
    "",
    "| Severity | Findings |",
    "|---|---|",
    ...[...SEVERITY_ORDER].reverse().map((s) => `| ${capitalize(s)} | ${counts[s]} |`),
    "",
  ];

  for (const g of sorted) {
    const urls = [...new Set(g.occurrences.map((o) => o.entry.request.url))];
    lines.push(`## ${capitalize(g.severity)}: ${escapeMd(g.title)}`, "", escapeMd(g.detail), "", `Seen ${g.occurrences.length} time(s) on ${urls.length} URL(s):`, "");
    for (const url of urls.slice(0, MAX_URLS_PER_FINDING)) lines.push(`- \`${url.replace(/`/g, "%60")}\``);
    if (urls.length > MAX_URLS_PER_FINDING) lines.push(`- …and ${urls.length - MAX_URLS_PER_FINDING} more`);
    lines.push("");
  }
  if (sorted.length === 0) lines.push("No passive findings in the captured History.", "");
  return lines.join("\n");
}
