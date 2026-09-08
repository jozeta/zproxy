// Parses/matches the free-text keyboard shortcut strings configured in
// Settings (e.g. "Ctrl+Shift+F", see SETTINGS_DEFAULTS.shortcuts in
// src/storage/settings.js) against a real KeyboardEvent. Cmd/Meta on macOS
// is treated as an alias for "Ctrl" so the same shortcut string works on
// both platforms without a separate per-OS setting.
//
// Known, permanent limitation: a combo the browser itself reserves at the
// chrome-UI level (e.g. Ctrl+R for reload, Ctrl+T for a new tab) never
// reaches this page's keydown listener at all — no amount of
// preventDefault() here can override that. Pick shortcuts Chrome doesn't
// already own if you want them to actually fire.

const MODIFIER_ALIASES = {
  ctrl: "ctrl",
  control: "ctrl",
  cmd: "ctrl",
  command: "ctrl",
  meta: "ctrl",
  shift: "shift",
  alt: "alt",
  option: "alt",
};

/** {ctrl, shift, alt, key} (key lowercased, e.g. "enter", "f"), or null for an empty/modifier-only string. */
export function parseShortcut(str) {
  const parts = (str || "")
    .split("+")
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) return null;
  const mods = { ctrl: false, shift: false, alt: false };
  let key = null;
  for (const part of parts) {
    const lower = part.toLowerCase();
    if (MODIFIER_ALIASES[lower]) mods[MODIFIER_ALIASES[lower]] = true;
    else key = lower;
  }
  if (!key) return null;
  return { ...mods, key };
}

export function matchesShortcut(event, str) {
  const parsed = parseShortcut(str);
  if (!parsed || !event) return false;
  return (
    Boolean(event.ctrlKey || event.metaKey) === parsed.ctrl &&
    Boolean(event.shiftKey) === parsed.shift &&
    Boolean(event.altKey) === parsed.alt &&
    (event.key || "").toLowerCase() === parsed.key
  );
}
