// Standalone scratch encode/decode/hash utility — Burp/ZAP "Decoder"
// equivalent. Operates on whatever text is pasted in; Encode/Decode
// transform it in place (repeatable, so double-encoding is just clicking
// Encode twice), and hashes are computed live off the same text.
import { infoIcon } from "../../components/tooltip.js";
import { DECODER_MODES } from "../../../parsers/decoder.js";
import { sha1Hex, sha256Hex, sha384Hex, sha512Hex } from "../../../utils/hash.js";

const HASHES = [
  { id: "sha1", label: "SHA-1", fn: sha1Hex },
  { id: "sha256", label: "SHA-256", fn: sha256Hex },
  { id: "sha384", label: "SHA-384", fn: sha384Hex },
  { id: "sha512", label: "SHA-512", fn: sha512Hex },
];

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function renderDecoder(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Decoder"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Paste text below, pick a mode, then Encode/Decode — each click transforms the text in place, so repeated encoding/decoding chains naturally. Hashes below update automatically as the text changes."
    )
  );

  if (!ctx.sharedState.decoderText) ctx.sharedState.decoderText = "";
  const state = ctx.sharedState;

  const textarea = document.createElement("textarea");
  textarea.style.minHeight = "160px";
  textarea.placeholder = "Paste or type text to encode/decode/hash…";
  textarea.value = state.decoderText;
  container.appendChild(textarea);

  const modeToolbar = el("div", "zp-toolbar");
  container.appendChild(modeToolbar);
  const errorMsg = el("div", "zp-warning");
  errorMsg.hidden = true;
  container.appendChild(errorMsg);

  for (const mode of DECODER_MODES) {
    const group = el("span", "zp-toolbar");
    group.style.marginBottom = "0";
    group.appendChild(el("span", "zp-hint", mode.label));
    const encodeBtn = el("button", "zp-btn zp-btn-small", "Encode");
    encodeBtn.type = "button";
    const decodeBtn = el("button", "zp-btn zp-btn-small", "Decode");
    decodeBtn.type = "button";
    encodeBtn.addEventListener("click", () => {
      errorMsg.hidden = true;
      textarea.value = mode.encode(textarea.value);
      onTextChanged();
    });
    decodeBtn.addEventListener("click", () => {
      const result = mode.decode(textarea.value);
      if (!result.ok) {
        errorMsg.hidden = false;
        errorMsg.textContent = `⚠ ${mode.label}: ${result.error}`;
        return;
      }
      errorMsg.hidden = true;
      textarea.value = result.value;
      onTextChanged();
    });
    group.appendChild(encodeBtn);
    group.appendChild(decodeBtn);
    modeToolbar.appendChild(group);
  }
  modeToolbar.appendChild(infoIcon("HTML entities covers the five dangerous characters (& < > \" ') plus a handful of common named/numeric entities — not the full HTML5 entity list.", { label: "About HTML entities" }));

  container.appendChild(el("div", "zp-subheading", "Hashes"));
  const hashBox = el("div", "zp-json-box");
  hashBox.style.maxHeight = "none";
  const hashRows = {};
  for (const h of HASHES) {
    const row = el("div", "zp-mono-small");
    const label = el("span", "", `${h.label}: `);
    label.style.color = "var(--text-faint)";
    const value = el("span", "", "");
    row.appendChild(label);
    row.appendChild(value);
    hashBox.appendChild(row);
    hashRows[h.id] = value;
  }
  container.appendChild(hashBox);

  let hashToken = 0;
  async function refreshHashes() {
    const myToken = ++hashToken;
    const text = textarea.value;
    for (const h of HASHES) hashRows[h.id].textContent = "computing…";
    for (const h of HASHES) {
      const digest = await h.fn(text);
      if (myToken !== hashToken) return;
      hashRows[h.id].textContent = digest;
    }
  }

  function onTextChanged() {
    state.decoderText = textarea.value;
    refreshHashes();
  }

  textarea.addEventListener("input", onTextChanged);
  refreshHashes();
}
