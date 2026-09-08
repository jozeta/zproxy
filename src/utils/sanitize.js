// Every view that renders captured (untrusted) traffic MUST go through here.
// Never use innerHTML/insertAdjacentHTML/document.write with request/response
// data anywhere else in the codebase — see docs/SECURITY.md "Preview isolation".

/** Set text content on an element without ever parsing it as markup. */
export function setTextSafely(element, text) {
  element.textContent = text ?? "";
}

/**
 * Renders an HTML body in a sandboxed iframe with scripting disabled.
 * `allow-scripts` and `allow-same-origin` are both intentionally omitted:
 * without allow-same-origin the frame is treated as opaque-origin, so even if
 * `allow-scripts` were mistakenly added later, script would still have no
 * access to cookies/storage/extension APIs. As written, scripts do not run
 * at all in this frame.
 */
export function renderSandboxedPreview(container, htmlText) {
  container.textContent = "";
  const iframe = document.createElement("iframe");
  iframe.setAttribute("sandbox", "");
  iframe.setAttribute("referrerpolicy", "no-referrer");
  iframe.srcdoc = htmlText ?? "";
  iframe.className = "zp-sandboxed-preview";
  container.appendChild(iframe);
  return iframe;
}

/** For the rare case text must be embedded in an HTML attribute/string we build manually. */
export function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
