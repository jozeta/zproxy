// Which side-panel views can be hidden from the navigation (Settings →
// Navigation), and which views the nav actually shows. Hiding only removes
// the nav entry: a hidden view still opens when something navigates to it
// directly (e.g. History's "Send to Decoder", or clicking the Scope badge),
// and shows in the nav for as long as it's the active view, so you're never
// on a page with no highlighted entry.
export const HIDEABLE_VIEWS = [
  { id: "findings", label: "Findings" },
  { id: "websockets", label: "WebSockets" },
  { id: "access-control", label: "Access Control" },
  { id: "cookies", label: "Cookies" },
  { id: "decoder", label: "Decoder" },
  { id: "comparer", label: "Comparer" },
  { id: "match-replace", label: "Match/Replace" },
  { id: "scope", label: "Scope" },
];

const HIDEABLE_IDS = new Set(HIDEABLE_VIEWS.map((v) => v.id));

/** `views` minus the hidden ones — except the active view, and never a view that isn't hideable. */
export function visibleViews(views, hiddenIds = [], activeId = null) {
  const hidden = new Set((hiddenIds || []).filter((id) => HIDEABLE_IDS.has(id)));
  return views.filter((v) => !hidden.has(v.id) || v.id === activeId);
}

/**
 * The hidden-views list after a Scope change: Scope is removed from it on
 * the change that first defines a scope (wasDefined false → isDefined true),
 * so the user can find what they just set up. Returns null when nothing
 * should change — including every later change, so re-hiding Scope sticks.
 */
export function hiddenViewsAfterScopeChange(hiddenIds, wasDefined, isDefined) {
  if (wasDefined || !isDefined || !(hiddenIds || []).includes("scope")) return null;
  return hiddenIds.filter((id) => id !== "scope");
}
