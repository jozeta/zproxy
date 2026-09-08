// Minimal, dependency-free JSON syntax highlighting. Builds DOM nodes with
// createElement/textContent only — never innerHTML — so captured JSON can
// never be interpreted as markup. See docs/SECURITY.md "Preview isolation".
const TOKEN_RE = /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\btrue\b|\bfalse\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

export function renderJsonPretty(container, jsonText) {
  container.textContent = "";
  const pre = document.createElement("pre");
  pre.className = "zp-json";
  let lastIndex = 0;
  let match;
  TOKEN_RE.lastIndex = 0;
  while ((match = TOKEN_RE.exec(jsonText))) {
    if (match.index > lastIndex) {
      pre.appendChild(document.createTextNode(jsonText.slice(lastIndex, match.index)));
    }
    const token = match[0];
    const span = document.createElement("span");
    if (token.startsWith('"')) {
      span.className = /:\s*$/.test(token) ? "zp-json-key" : "zp-json-string";
    } else if (token === "true" || token === "false") {
      span.className = "zp-json-boolean";
    } else if (token === "null") {
      span.className = "zp-json-null";
    } else {
      span.className = "zp-json-number";
    }
    span.textContent = token;
    pre.appendChild(span);
    lastIndex = TOKEN_RE.lastIndex;
  }
  pre.appendChild(document.createTextNode(jsonText.slice(lastIndex)));
  container.appendChild(pre);
  return pre;
}
