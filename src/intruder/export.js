// CSV export of Intruder results (one row per request, in send order).
// Payloads are attacker-style strings by design, so every cell is guarded
// against spreadsheet formula injection: a cell starting with = + - @ (or a
// tab/CR) is prefixed with ' so Excel/Sheets show it as text instead of
// evaluating it — e.g. a "=cmd|' /C calc'!A0" payload stays inert.

function csvCell(value) {
  let s = value == null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** CSV text for `results` (Intruder rows). `grepTerms` add one yes/no column each. */
export function resultsToCsv(results, grepTerms = []) {
  const header = ["#", "Payload(s)", "Status", "Length", "Time (ms)", ...grepTerms.map((t) => `Grep: ${t}`), "Error"];
  const lines = [header.map(csvCell).join(",")];
  for (const r of [...results].sort((a, b) => a.index - b.index)) {
    const body = r.response?.body ?? "";
    lines.push(
      [r.index, r.payloads.join(" | "), r.status ?? "", r.length ?? "", r.timeMs ?? "", ...grepTerms.map((t) => (r.response && body.includes(t) ? "yes" : "")), r.error ?? ""]
        .map(csvCell)
        .join(",")
    );
  }
  return lines.join("\r\n");
}
