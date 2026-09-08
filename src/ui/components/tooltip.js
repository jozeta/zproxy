// Small "i" info icon that shows a hover/focus tooltip. Appended to
// document.body and positioned with fixed coordinates computed from the
// icon's bounding rect, rather than a CSS-only absolute-positioned popup —
// the side panel is full of overflow:auto scroll containers (.zp-main,
// .zp-split-top, .zp-tab-panels, ...) which would otherwise clip a tooltip
// that overflows their bounds. Tooltip text is always a static, developer-
// authored string (never captured traffic), so plain textContent is enough —
// no sanitize.js involvement needed here.
let activeTooltip = null;
let activeIcon = null;

function clampLeft(left, width) {
  const margin = 8;
  return Math.max(margin, Math.min(left, window.innerWidth - width - margin));
}

function positionTooltip(icon, tooltip) {
  const rect = icon.getBoundingClientRect();
  const margin = 8;
  tooltip.style.left = "0px";
  tooltip.style.top = "0px";
  const tw = tooltip.offsetWidth;
  const th = tooltip.offsetHeight;

  let left = clampLeft(rect.left + rect.width / 2 - tw / 2, tw);
  let top = rect.top - th - margin;
  let placement = "top";
  if (top < margin) {
    top = rect.bottom + margin;
    placement = "bottom";
  }

  const arrowLeft = Math.max(10, Math.min(rect.left + rect.width / 2 - left, tw - 10));
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
  tooltip.style.setProperty("--zp-tooltip-arrow-left", `${arrowLeft}px`);
  tooltip.dataset.placement = placement;
}

export function hideActiveTooltip() {
  activeTooltip?.remove();
  activeTooltip = null;
  activeIcon = null;
}

// Scroll events don't bubble but do fire in the capture phase, so this
// catches scrolling inside any of the panel's inner scroll containers
// (.zp-main, .zp-split-top, .zp-tab-panels, ...), not just the window —
// otherwise a tooltip left open mid-hover would drift away from its icon.
if (typeof window !== "undefined") {
  window.addEventListener("scroll", hideActiveTooltip, true);
}

function showTooltip(icon, text) {
  if (activeIcon === icon) return;
  hideActiveTooltip();
  const tooltip = document.createElement("div");
  tooltip.className = "zp-tooltip";
  tooltip.setAttribute("role", "tooltip");
  tooltip.textContent = text;
  document.body.appendChild(tooltip);
  positionTooltip(icon, tooltip);
  activeTooltip = tooltip;
  activeIcon = icon;
}

/** A small circular "i" badge. Hover or focus it to show `text` in a floating tooltip. Meant to sit right after a label, input, or button to explain what it does. */
export function infoIcon(text, { label = "More info" } = {}) {
  const icon = document.createElement("button");
  icon.type = "button";
  icon.className = "zp-info-icon";
  icon.textContent = "i";
  icon.setAttribute("aria-label", label);
  icon.addEventListener("mouseenter", () => showTooltip(icon, text));
  icon.addEventListener("mouseleave", () => {
    if (activeIcon === icon) hideActiveTooltip();
  });
  icon.addEventListener("focus", () => showTooltip(icon, text));
  icon.addEventListener("blur", () => {
    if (activeIcon === icon) hideActiveTooltip();
  });
  // Purely informational — never actually submits/toggles anything, so a
  // stray click (e.g. via keyboard activation) shouldn't do anything else.
  icon.addEventListener("click", (e) => e.preventDefault());
  return icon;
}
