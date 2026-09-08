// Binary-safe base64 <-> UTF-8 text helpers.
// CDP's Fetch domain requires postData/body to be base64-encoded over the wire
// (confirmed against the Fetch domain spec: continueRequest.postData and
// fulfillRequest.body are both "Encoded as a base64 string when passed over JSON").
export function textToBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToText(base64) {
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function formatBytes(size) {
  if (size == null || Number.isNaN(size)) return "—";
  if (size < 1024) return `${size} B`;
  const units = ["KB", "MB", "GB"];
  let value = size / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unitIndex]}`;
}

export function truncate(str, max) {
  if (typeof str !== "string" || str.length <= max) return str;
  return `${str.slice(0, max)}…`;
}
