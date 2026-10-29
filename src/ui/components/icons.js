// ZProxy's icon set: 24×24, 1.6px round strokes, drawn for this tool rather
// than pulled from a library (no remote calls — docs/SECURITY.md). Built
// with createElementNS from plain shape data, never markup strings, so the
// no-HTML-sink rule (tests/security.no-eval.test.js) holds here too.
const SVG_NS = "http://www.w3.org/2000/svg";

// Each icon is a list of [tag, attributes] shapes.
const ICONS = {
  // A Z drawn as a fjord: two horizontal strands joined by one diagonal cut.
  logo: [
    ["path", { d: "M5 6.5h12.5L6.5 17.5H19" }],
    ["circle", { cx: "19", cy: "6.5", r: "1.4", fill: "currentColor", stroke: "none" }],
  ],
  dashboard: [
    ["rect", { x: "3.5", y: "3.5", width: "7", height: "9", rx: "1.5" }],
    ["rect", { x: "13.5", y: "3.5", width: "7", height: "5", rx: "1.5" }],
    ["rect", { x: "13.5", y: "11.5", width: "7", height: "9", rx: "1.5" }],
    ["rect", { x: "3.5", y: "15.5", width: "7", height: "5", rx: "1.5" }],
  ],
  history: [
    ["path", { d: "M4 12a8 8 0 1 0 2.35-5.66" }],
    ["path", { d: "M4 4v3.5h3.5" }],
    ["path", { d: "M12 8v4.2l2.8 1.8" }],
  ],
  findings: [
    ["path", { d: "M12 3.2 19 6v5.4c0 4.3-2.9 7.7-7 9.4-4.1-1.7-7-5.1-7-9.4V6z" }],
    ["path", { d: "M12 8.5v4" }],
    ["circle", { cx: "12", cy: "15.6", r: "0.9", fill: "currentColor", stroke: "none" }],
  ],
  intercept: [
    ["circle", { cx: "12", cy: "12", r: "8.5" }],
    ["path", { d: "M10 9v6M14 9v6" }],
  ],
  websockets: [
    ["path", { d: "M4 9h13.5M14.5 5.5 18 9l-3.5 3.5" }],
    ["path", { d: "M20 15H6.5M9.5 11.5 6 15l3.5 3.5" }],
  ],
  repeater: [
    ["path", { d: "M17.5 4.5 20 7l-2.5 2.5" }],
    ["path", { d: "M4 12V10a3 3 0 0 1 3-3h13" }],
    ["path", { d: "M6.5 19.5 4 17l2.5-2.5" }],
    ["path", { d: "M20 12v2a3 3 0 0 1-3 3H4" }],
  ],
  intruder: [
    ["circle", { cx: "12", cy: "12", r: "7.5" }],
    ["circle", { cx: "12", cy: "12", r: "2.2" }],
    ["path", { d: "M12 2.5v4M12 17.5v4M2.5 12h4M17.5 12h4" }],
  ],
  "access-control": [
    ["circle", { cx: "8", cy: "12", r: "3.8" }],
    ["path", { d: "M11.8 12H20.5M17.5 12v3M20.5 12v2.2" }],
  ],
  cookies: [
    ["path", { d: "M20.4 12.6A8.5 8.5 0 1 1 11.4 3.6a3 3 0 0 0 4 4 3 3 0 0 0 5 5z" }],
    ["circle", { cx: "9", cy: "10", r: "0.9", fill: "currentColor", stroke: "none" }],
    ["circle", { cx: "13.5", cy: "15", r: "0.9", fill: "currentColor", stroke: "none" }],
    ["circle", { cx: "8.5", cy: "15.5", r: "0.9", fill: "currentColor", stroke: "none" }],
  ],
  decoder: [
    ["path", { d: "M8.5 5.5c-2 0-2.5 1-2.5 2.5v2c0 1.2-.7 2-2 2 1.3 0 2 .8 2 2v2c0 1.5.5 2.5 2.5 2.5" }],
    ["path", { d: "M15.5 5.5c2 0 2.5 1 2.5 2.5v2c0 1.2.7 2 2 2-1.3 0-2 .8-2 2v2c0 1.5-.5 2.5-2.5 2.5" }],
  ],
  comparer: [
    ["rect", { x: "3.5", y: "4.5", width: "7", height: "15", rx: "1.5" }],
    ["rect", { x: "13.5", y: "4.5", width: "7", height: "15", rx: "1.5" }],
    ["path", { d: "M6 9h2M6 12h2M16 12h2M16 15h2" }],
  ],
  "match-replace": [
    ["path", { d: "M4 8.5h12M13 5l3.5 3.5L13 12" }],
    ["path", { d: "M20 15.5H8M11 12l-3.5 3.5L11 19" }],
  ],
  scope: [
    ["circle", { cx: "12", cy: "12", r: "8.5" }],
    ["path", { d: "M3.5 12h17" }],
    ["path", { d: "M12 3.5c2.3 2.4 3.4 5.2 3.4 8.5s-1.1 6.1-3.4 8.5c-2.3-2.4-3.4-5.2-3.4-8.5S9.7 5.9 12 3.5z" }],
  ],
  settings: [
    ["path", { d: "M4 7h9M17 7h3M4 17h3M11 17h9" }],
    ["circle", { cx: "15", cy: "7", r: "2" }],
    ["circle", { cx: "9", cy: "17", r: "2" }],
  ],
  info: [
    ["circle", { cx: "12", cy: "12", r: "8.5" }],
    ["path", { d: "M12 11v5" }],
    ["circle", { cx: "12", cy: "7.8", r: "0.9", fill: "currentColor", stroke: "none" }],
  ],
};

export const ICON_NAMES = Object.freeze(Object.keys(ICONS));

/** An <svg> element for `name` (empty if unknown). Decorative by default — pass a `label` to expose it to screen readers. */
export function icon(name, { size = 16, label = null, className = "zp-icon" } = {}) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("class", className);
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else {
    svg.setAttribute("aria-hidden", "true");
  }
  for (const [tag, attrs] of ICONS[name] || []) {
    const shape = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) shape.setAttribute(k, v);
    svg.appendChild(shape);
  }
  return svg;
}
