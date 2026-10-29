// Parses a cURL command line (as copied from browser DevTools' "Copy as
// cURL", or written by hand) into a ZProxy request {method, url, headers,
// body}. Handles POSIX shell quoting — '…', "…" with backslash escapes, $'…'
// ANSI-C quoting (Chrome's bash export uses it), and backslash-newline line
// continuations — plus the flags that change the request. Flags that only
// affect curl's own behaviour (-k, -s, --compressed, -L, …) are ignored.
// The inverse, requestToCurl(), lives in http.js.

/** Splits a shell command into words, honouring quotes and escapes. Throws on an unterminated quote. */
export function shellSplit(command) {
  const words = [];
  let current = "";
  let inWord = false;
  const s = command.replace(/\\\r?\n/g, " ");
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (/\s/.test(ch)) {
      if (inWord) words.push(current);
      current = "";
      inWord = false;
      continue;
    }
    inWord = true;
    if (ch === "'") {
      const end = s.indexOf("'", i + 1);
      if (end === -1) throw new Error("Unterminated ' quote");
      current += s.slice(i + 1, end);
      i = end;
    } else if (ch === "$" && s[i + 1] === "'") {
      let j = i + 2;
      for (; j < s.length && s[j] !== "'"; j++) {
        if (s[j] === "\\" && j + 1 < s.length) {
          const next = s[++j];
          const map = { n: "\n", t: "\t", r: "\r", "\\": "\\", "'": "'", '"': '"' };
          if (next === "x" && /^[0-9a-f]{2}$/i.test(s.slice(j + 1, j + 3))) {
            current += String.fromCharCode(parseInt(s.slice(j + 1, j + 3), 16));
            j += 2;
          } else if (next === "u" && /^[0-9a-f]{4}$/i.test(s.slice(j + 1, j + 5))) {
            current += String.fromCharCode(parseInt(s.slice(j + 1, j + 5), 16));
            j += 4;
          } else {
            current += map[next] ?? next;
          }
        } else {
          current += s[j];
        }
      }
      if (j >= s.length) throw new Error("Unterminated $' quote");
      i = j;
    } else if (ch === '"') {
      let j = i + 1;
      for (; j < s.length && s[j] !== '"'; j++) {
        if (s[j] === "\\" && j + 1 < s.length && '"\\$`'.includes(s[j + 1])) j++;
        current += s[j];
      }
      if (j >= s.length) throw new Error('Unterminated " quote');
      i = j;
    } else if (ch === "\\" && i + 1 < s.length) {
      current += s[++i];
    } else {
      current += ch;
    }
  }
  if (inWord) words.push(current);
  return words;
}

const DATA_FLAGS = new Set(["-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "--json"]);
const VALUE_FLAGS_IGNORED = new Set(["-o", "--output", "-m", "--max-time", "--connect-timeout", "-x", "--proxy", "-w", "--write-out", "--retry", "-E", "--cert", "--cacert", "--key", "-c", "--cookie-jar", "-K", "--config", "--resolve", "--limit-rate"]);

/** {method, url, headers, body} from a cURL command; throws a readable Error if it isn't one. */
export function parseCurl(command) {
  const words = shellSplit(command.trim());
  if (words[0] !== "curl") throw new Error("Doesn't start with curl");
  let url = null;
  let method = null;
  const headers = [];
  const data = [];
  let isJson = false;
  let headOnly = false;
  for (let i = 1; i < words.length; i++) {
    const w = words[i];
    const value = () => {
      if (i + 1 >= words.length) throw new Error(`${w} needs a value`);
      return words[++i];
    };
    if (w === "-X" || w === "--request") method = value().toUpperCase();
    else if (w === "-H" || w === "--header") {
      const h = value();
      const idx = h.indexOf(":");
      if (idx > 0) headers.push({ name: h.slice(0, idx).trim(), value: h.slice(idx + 1).trim() });
    } else if (DATA_FLAGS.has(w)) {
      if (w === "--json") isJson = true;
      data.push(value());
    } else if (w === "-b" || w === "--cookie") headers.push({ name: "Cookie", value: value() });
    else if (w === "-A" || w === "--user-agent") headers.push({ name: "User-Agent", value: value() });
    else if (w === "-e" || w === "--referer") headers.push({ name: "Referer", value: value() });
    else if (w === "-u" || w === "--user") headers.push({ name: "Authorization", value: `Basic ${btoa(value())}` });
    else if (w === "-I" || w === "--head") headOnly = true;
    else if (w === "--url") url = value();
    else if (VALUE_FLAGS_IGNORED.has(w)) value();
    else if (!w.startsWith("-") && url === null) url = w;
    // Any other flag (-k, -s, -L, --compressed, …) only changes curl's behaviour, not the request.
  }
  if (!url) throw new Error("No URL found");
  if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
  const body = data.length ? data.join("&") : "";
  if (isJson && !headers.some((h) => h.name.toLowerCase() === "content-type")) headers.push({ name: "Content-Type", value: "application/json" });
  if (data.length && !isJson && !headers.some((h) => h.name.toLowerCase() === "content-type")) {
    headers.push({ name: "Content-Type", value: "application/x-www-form-urlencoded" });
  }
  return { method: method || (headOnly ? "HEAD" : data.length ? "POST" : "GET"), url, httpVersion: "HTTP/1.1", headers, body };
}
