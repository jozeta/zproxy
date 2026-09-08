// Shared "Session handling macro" editor for Repeater and Intruder — a
// request to send first, and a Search - Extract-style wildcard query to
// pull one value out of its response, substituted wherever {{macro}}
// appears in the real request's URL/headers/body. See src/intruder/macro.js
// for the pure substitution/extraction logic this drives.
import { infoIcon } from "./tooltip.js";
import { MACRO_TOKEN } from "../../intruder/macro.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/**
 * `macro` is the mutable state object itself (e.g. a Repeater tab's
 * `.macro`, or Intruder's `state.macro`) — every input here mutates it in
 * place on "input"/"change", matching how the rest of Repeater/Intruder
 * already treat their shared state objects. `onChange` (optional) fires
 * after every mutation, for a caller that needs to react immediately (e.g.
 * re-running a total-requests estimate).
 */
export function buildMacroEditor(macro, onChange) {
  const wrap = el("div");
  wrap.appendChild(el("div", "zp-subheading", "Session handling macro"));

  const enableRow = el("div", "zp-checkbox-row");
  const enableCheckbox = document.createElement("input");
  enableCheckbox.type = "checkbox";
  const enableId = `macro-enabled-${Math.random().toString(36).slice(2, 8)}`;
  enableCheckbox.id = enableId;
  enableCheckbox.checked = macro.enabled;
  const enableLabel = document.createElement("label");
  enableLabel.htmlFor = enableId;
  enableLabel.textContent = "Run a macro request first, and substitute the extracted value into {{macro}}";
  enableRow.appendChild(enableCheckbox);
  enableRow.appendChild(enableLabel);
  enableRow.appendChild(
    infoIcon(
      `Sends the request below before every real request, extracts one value from its response (Search - Extract wildcard syntax — * and ?, first match), and substitutes it into every "${MACRO_TOKEN}" placeholder in your actual request's URL, headers, or body. Fixes the common case of a CSRF/session token that rotates on every response, which would otherwise make a single captured request go stale immediately. Use ${MACRO_TOKEN} in your real request wherever the fresh value should go.`,
      { label: "About session handling macros" }
    )
  );
  wrap.appendChild(enableRow);

  const fieldsHost = el("div");
  fieldsHost.hidden = !macro.enabled;
  wrap.appendChild(fieldsHost);

  const line = el("div", "zp-req-line");
  const methodInput = document.createElement("input");
  methodInput.type = "text";
  methodInput.className = "zp-method-input";
  methodInput.value = macro.method;
  const urlInput = document.createElement("input");
  urlInput.type = "text";
  urlInput.className = "zp-url-input";
  urlInput.placeholder = "https://example.com/refresh-token";
  urlInput.value = macro.url;
  line.appendChild(methodInput);
  line.appendChild(urlInput);
  fieldsHost.appendChild(line);

  fieldsHost.appendChild(el("div", "zp-subheading", "Headers (one per line: Name: value)"));
  const headersArea = document.createElement("textarea");
  headersArea.style.minHeight = "60px";
  headersArea.value = macro.headersText;
  fieldsHost.appendChild(headersArea);

  fieldsHost.appendChild(el("div", "zp-subheading", "Body"));
  const bodyArea = document.createElement("textarea");
  bodyArea.style.minHeight = "50px";
  bodyArea.value = macro.body;
  fieldsHost.appendChild(bodyArea);

  const extractRow = el("div", "zp-form-row");
  extractRow.appendChild(el("label", "", "Extract value"));
  const extractInput = document.createElement("input");
  extractInput.type = "text";
  extractInput.placeholder = 'e.g. name="csrf_token" value="*">';
  extractInput.value = macro.extractQuery;
  extractRow.appendChild(extractInput);
  extractRow.appendChild(
    infoIcon(`Wildcard query (* = any text, ? = one character) run against the macro response's body/headers — the first match becomes the value substituted into ${MACRO_TOKEN}.`, { label: "About Extract value" })
  );
  fieldsHost.appendChild(extractRow);

  const statusMsg = el("div", "zp-hint", "");
  statusMsg.hidden = true;
  fieldsHost.appendChild(statusMsg);

  function commit() {
    onChange?.();
  }

  enableCheckbox.addEventListener("change", () => {
    macro.enabled = enableCheckbox.checked;
    fieldsHost.hidden = !macro.enabled;
    commit();
  });
  methodInput.addEventListener("input", () => {
    macro.method = methodInput.value.trim() || "GET";
    commit();
  });
  urlInput.addEventListener("input", () => {
    macro.url = urlInput.value;
    commit();
  });
  headersArea.addEventListener("input", () => {
    macro.headersText = headersArea.value;
    commit();
  });
  bodyArea.addEventListener("input", () => {
    macro.body = bodyArea.value;
    commit();
  });
  extractInput.addEventListener("input", () => {
    macro.extractQuery = extractInput.value;
    commit();
  });

  return {
    element: wrap,
    setStatus(text, isError) {
      statusMsg.hidden = !text;
      statusMsg.textContent = text || "";
      statusMsg.className = isError ? "zp-warning" : "zp-hint";
    },
  };
}
