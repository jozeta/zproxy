export function tryParseJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

export function prettyPrintJson(text, indent = 2) {
  const result = tryParseJson(text);
  if (!result.ok) return text;
  return JSON.stringify(result.value, null, indent);
}

export function minifyJson(text) {
  const result = tryParseJson(text);
  if (!result.ok) return text;
  return JSON.stringify(result.value);
}

export function looksLikeJson(text, contentType = "") {
  if (contentType && contentType.toLowerCase().includes("json")) return true;
  if (typeof text !== "string") return false;
  const trimmed = text.trim();
  return trimmed.startsWith("{") || trimmed.startsWith("[");
}
