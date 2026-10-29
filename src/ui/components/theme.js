// Applies settings.theme ("dark" | "light" | "system") as <html data-theme>,
// which sidepanel.css and popup.css key their Nordic palettes on.
//
// The resolved setting is also remembered in localStorage — a per-viewer
// convenience only — and applied the moment this module loads, before the
// first paint. Without it, every open would paint the dark default first
// and then visibly fade to light once settings:get came back.
const STORAGE_KEY = "zproxy.theme";
const systemDark = typeof window !== "undefined" && window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
let themeSetting = "dark";

export function resolveTheme(setting, prefersDark) {
  if (setting === "light") return "light";
  if (setting === "system") return prefersDark ? "dark" : "light";
  return "dark";
}

export function applyTheme(setting) {
  themeSetting = setting || "dark";
  document.documentElement.dataset.theme = resolveTheme(themeSetting, systemDark?.matches ?? true);
  try {
    localStorage.setItem(STORAGE_KEY, themeSetting);
  } catch {
    /* storage unavailable — the theme still applies, it just isn't remembered */
  }
}

if (typeof document !== "undefined") {
  let remembered = null;
  try {
    remembered = localStorage.getItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
  applyTheme(remembered || "dark");
  systemDark?.addEventListener("change", () => applyTheme(themeSetting));
}
