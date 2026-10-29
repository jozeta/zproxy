// A drag handle between the two stacked panes of a .zp-split (pending list
// over inspector in Intercept, editor over response in Repeater). Drag it,
// or focus it and use ↑/↓ (Shift for bigger steps); double-click resets.
// The chosen height is remembered per split in localStorage — a per-viewer
// layout convenience, nothing sensitive.

/** Pure — clamps a requested top-pane height so both panes keep their minimums. */
export function clampSplit(requested, total, minTop, minBottom) {
  const max = Math.max(minTop, total - minBottom);
  return Math.round(Math.min(max, Math.max(minTop, requested)));
}

function readStored(key) {
  try {
    const v = Number(localStorage.getItem(key));
    return Number.isFinite(v) && v > 0 ? v : null;
  } catch {
    return null;
  }
}

function writeStored(key, value) {
  try {
    if (value == null) localStorage.removeItem(key);
    else localStorage.setItem(key, String(value));
  } catch {
    /* storage unavailable — the size just isn't remembered */
  }
}

/**
 * Inserts a resizer between `top` and `bottom` (both children of `split`).
 * `storageKey` names the remembered height; `minTop`/`minBottom` in px.
 */
export function makeResizable(split, top, bottom, { storageKey, minTop = 80, minBottom = 120, label = "Resize panes" } = {}) {
  const handle = document.createElement("div");
  handle.className = "zp-resizer";
  handle.tabIndex = 0;
  handle.setAttribute("role", "separator");
  handle.setAttribute("aria-orientation", "horizontal");
  handle.setAttribute("aria-label", label);
  handle.title = `${label} — drag, or use the arrow keys. Double-click to reset.`;
  split.insertBefore(handle, bottom);

  function apply(height) {
    if (height == null) {
      top.style.flex = "";
      handle.removeAttribute("aria-valuenow");
      return;
    }
    const total = split.clientHeight || height + minBottom;
    const clamped = clampSplit(height, total, minTop, minBottom);
    top.style.flex = `0 0 ${clamped}px`;
    handle.setAttribute("aria-valuenow", String(clamped));
    return clamped;
  }

  const stored = storageKey ? readStored(storageKey) : null;
  if (stored) requestAnimationFrame(() => apply(stored));

  handle.addEventListener("pointerdown", (ev) => {
    ev.preventDefault();
    handle.setPointerCapture(ev.pointerId);
    handle.classList.add("dragging");
    document.body.classList.add("zp-resizing");
    const startY = ev.clientY;
    const startHeight = top.getBoundingClientRect().height;
    const onMove = (e) => apply(startHeight + (e.clientY - startY));
    const onUp = () => {
      handle.classList.remove("dragging");
      document.body.classList.remove("zp-resizing");
      handle.removeEventListener("pointermove", onMove);
      handle.removeEventListener("pointerup", onUp);
      handle.removeEventListener("pointercancel", onUp);
      if (storageKey) writeStored(storageKey, Math.round(top.getBoundingClientRect().height));
    };
    handle.addEventListener("pointermove", onMove);
    handle.addEventListener("pointerup", onUp);
    handle.addEventListener("pointercancel", onUp);
  });

  handle.addEventListener("keydown", (ev) => {
    if (ev.key !== "ArrowUp" && ev.key !== "ArrowDown") return;
    ev.preventDefault();
    const step = (ev.shiftKey ? 60 : 20) * (ev.key === "ArrowUp" ? -1 : 1);
    const next = apply(top.getBoundingClientRect().height + step);
    if (storageKey) writeStored(storageKey, next);
  });

  handle.addEventListener("dblclick", () => {
    apply(null);
    if (storageKey) writeStored(storageKey, null);
  });

  return handle;
}
