// Standalone scratch encode/decode/hash utility — Burp/ZAP "Decoder"
// equivalent. Operates on whatever text is pasted in; Encode/Decode
// transform it in place (repeatable, so double-encoding is just clicking
// Encode twice, and Undo steps back), Smart decode unwraps layered
// encodings automatically, and the Inspect panel and hashes update live
// off the same text.
import { infoIcon } from "../../components/tooltip.js";
import { DECODER_MODES, smartDecode, describeTimestamp } from "../../../parsers/decoder.js";
import { isJwtLike, decodeJwt } from "../../../parsers/jwt.js";
import { sha1Hex, sha256Hex, sha384Hex, sha512Hex, md5Hex, crc32Hex, hmacSha256Hex } from "../../../utils/hash.js";

const HASHES = [
  { id: "md5", label: "MD5", fn: md5Hex },
  { id: "sha1", label: "SHA-1", fn: sha1Hex },
  { id: "sha256", label: "SHA-256", fn: sha256Hex },
  { id: "sha384", label: "SHA-384", fn: sha384Hex },
  { id: "sha512", label: "SHA-512", fn: sha512Hex },
  { id: "crc32", label: "CRC-32", fn: crc32Hex },
];
const MAX_UNDO = 50;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function button(label, className = "zp-btn zp-btn-small") {
  const b = el("button", className, label);
  b.type = "button";
  return b;
}

export function renderDecoder(container, ctx) {
  container.textContent = "";
  container.appendChild(el("h2", "zp-view-title", "Decoder"));
  container.appendChild(
    el(
      "p",
      "zp-hint",
      "Paste text, pick an encoding, then Encode or Decode — each click transforms the text in place, so chains like Base64 → URL are just two clicks (Undo steps back). Smart decode peels layered encodings automatically. Inspect and the hashes below update as you type."
    )
  );

  if (!ctx.sharedState.decoderText) ctx.sharedState.decoderText = "";
  if (!ctx.sharedState.decoderMode) ctx.sharedState.decoderMode = "base64";
  const state = ctx.sharedState;
  const undoStack = [];

  const textarea = document.createElement("textarea");
  textarea.style.minHeight = "150px";
  textarea.placeholder = "Paste or type text to encode, decode, inspect, or hash…";
  textarea.value = state.decoderText;
  container.appendChild(textarea);

  const toolbar = el("div", "zp-toolbar");
  const modeSelect = document.createElement("select");
  for (const mode of DECODER_MODES) {
    const o = document.createElement("option");
    o.value = mode.id;
    o.textContent = mode.label;
    modeSelect.appendChild(o);
  }
  modeSelect.value = state.decoderMode;
  const encodeBtn = button("Encode");
  const decodeBtn = button("Decode");
  const smartBtn = button("Smart decode", "zp-btn zp-btn-small zp-btn-primary");
  const undoBtn = button("Undo");
  const copyBtn = button("Copy");
  toolbar.append(modeSelect, encodeBtn, decodeBtn);
  toolbar.appendChild(
    infoIcon(
      "URL (all chars) percent-encodes every byte, which slips past filters that only look for literal characters. Gzip takes and produces base64 (compressed data isn't text). HTML entities covers the dangerous characters plus common named/numeric entities — not the full HTML5 list.",
      { label: "About encodings" }
    )
  );
  toolbar.append(smartBtn);
  toolbar.appendChild(infoIcon("Repeatedly applies whichever decoding clearly fits — URL, Base64/Base64url, hex, HTML entities, Unicode escapes — until the text stops changing, and shows each step. Handy for a cookie that's Base64 inside URL-encoding.", { label: "About Smart decode" }));
  toolbar.append(undoBtn, copyBtn);
  container.appendChild(toolbar);

  const message = el("div", "zp-warning");
  message.hidden = true;
  container.appendChild(message);
  const stepsLine = el("p", "zp-hint", "");
  stepsLine.hidden = true;
  container.appendChild(stepsLine);

  container.appendChild(el("div", "zp-subheading", "Inspect"));
  const inspectBox = el("div", "zp-json-box");
  inspectBox.style.maxHeight = "260px";
  container.appendChild(inspectBox);

  const hashHeading = el("div", "zp-subheading", "Hashes");
  hashHeading.appendChild(infoIcon("Click a value to copy it. MD5 and CRC-32 are for recognizing legacy hashes and checksums — never use them to secure anything.", { label: "About hashes" }));
  container.appendChild(hashHeading);
  const hashBox = el("div", "zp-json-box");
  hashBox.style.maxHeight = "none";
  container.appendChild(hashBox);
  const hashRows = {};
  function hashRow(id, label) {
    const row = el("div", "zp-mono-small");
    const name = el("span", "", `${label}: `);
    name.style.color = "var(--text-faint)";
    const value = el("span", "", "");
    value.style.cursor = "copy";
    value.title = "Click to copy";
    value.addEventListener("click", () => navigator.clipboard?.writeText(value.textContent).catch(() => {}));
    row.append(name, value);
    hashBox.appendChild(row);
    hashRows[id] = value;
  }
  for (const h of HASHES) hashRow(h.id, h.label);
  const hmacRow = el("div", "zp-form-row");
  hmacRow.style.marginTop = "8px";
  hmacRow.appendChild(el("label", "", "HMAC-SHA-256 key"));
  const hmacKey = document.createElement("input");
  hmacKey.type = "text";
  hmacKey.placeholder = "secret key (e.g. to check a webhook signature)";
  hmacKey.value = state.decoderHmacKey || "";
  hmacRow.appendChild(hmacKey);
  hashBox.appendChild(hmacRow);
  hashRow("hmac", "HMAC-SHA-256");

  function setMessage(text) {
    message.hidden = !text;
    message.textContent = text ? `⚠ ${text}` : "";
  }

  function replaceText(value) {
    undoStack.push(textarea.value);
    if (undoStack.length > MAX_UNDO) undoStack.shift();
    textarea.value = value;
    onTextChanged();
  }

  function currentMode() {
    return DECODER_MODES.find((m) => m.id === modeSelect.value) || DECODER_MODES[0];
  }

  encodeBtn.addEventListener("click", async () => {
    setMessage("");
    stepsLine.hidden = true;
    replaceText(await currentMode().encode(textarea.value));
  });

  decodeBtn.addEventListener("click", async () => {
    stepsLine.hidden = true;
    const mode = currentMode();
    const result = await mode.decode(textarea.value);
    if (!result.ok) {
      setMessage(`${mode.label}: ${result.error}`);
      return;
    }
    setMessage("");
    replaceText(result.value);
  });

  smartBtn.addEventListener("click", () => {
    setMessage("");
    const steps = smartDecode(textarea.value);
    if (steps.length === 0) {
      stepsLine.hidden = false;
      stepsLine.textContent = "Nothing to decode — the text doesn't look encoded.";
      return;
    }
    stepsLine.hidden = false;
    stepsLine.textContent = `Decoded ${steps.length} layer${steps.length === 1 ? "" : "s"}: ${steps.map((s) => s.label).join(" → ")}`;
    replaceText(steps[steps.length - 1].value);
  });

  undoBtn.addEventListener("click", () => {
    if (!undoStack.length) return;
    textarea.value = undoStack.pop();
    setMessage("");
    stepsLine.hidden = true;
    onTextChanged();
  });

  copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(textarea.value);
      copyBtn.textContent = "Copied";
    } catch {
      copyBtn.textContent = "Clipboard blocked";
    }
    setTimeout(() => (copyBtn.textContent = "Copy"), 1400);
  });

  modeSelect.addEventListener("change", () => (state.decoderMode = modeSelect.value));

  function renderInspect() {
    inspectBox.textContent = "";
    const text = textarea.value;
    const line = (label, value) => {
      const row = el("div", "zp-mono-small");
      const name = el("span", "", `${label}: `);
      name.style.color = "var(--text-faint)";
      row.append(name, el("span", "", value));
      inspectBox.appendChild(row);
    };
    line("Length", `${[...text].length} characters, ${new TextEncoder().encode(text).length} bytes (UTF-8)`);
    const trimmed = text.trim();
    const ts = describeTimestamp(trimmed);
    if (ts) line("Timestamp", `${ts.iso} · Unix ${ts.unixSeconds} · ${ts.unixMs} ms`);
    if (isJwtLike(trimmed)) {
      const jwt = decodeJwt(trimmed);
      if (jwt.ok) {
        line("JWT header", JSON.stringify(jwt.header));
        line("JWT payload", JSON.stringify(jwt.payload, null, 2));
        for (const claim of ["iat", "nbf", "exp"]) {
          if (typeof jwt.payload[claim] === "number") line(`JWT ${claim}`, new Date(jwt.payload[claim] * 1000).toISOString());
        }
        line("JWT signature", "not verified — decoding proves nothing about authenticity");
      }
    }
  }

  let hashToken = 0;
  async function refreshHashes() {
    const myToken = ++hashToken;
    const text = textarea.value;
    for (const id of Object.keys(hashRows)) hashRows[id].textContent = "computing…";
    for (const h of HASHES) {
      const digest = await h.fn(text);
      if (myToken !== hashToken) return;
      hashRows[h.id].textContent = digest;
    }
    hashRows.hmac.textContent = hmacKey.value ? await hmacSha256Hex(hmacKey.value, text) : "(enter a key)";
  }

  function onTextChanged() {
    state.decoderText = textarea.value;
    renderInspect();
    refreshHashes();
  }

  textarea.addEventListener("input", onTextChanged);
  hmacKey.addEventListener("input", () => {
    state.decoderHmacKey = hmacKey.value;
    refreshHashes();
  });
  onTextChanged();
}
