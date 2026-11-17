// Applies the theme (light or dark) before the page renders. Until the user
// picks one, the page follows the system setting.
// Loaded synchronously in <head> so there is no flash of the wrong theme.
"use strict";
(() => {
  const KEY = "mancar-theme";
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  let fallback = null; // used when browser storage is blocked
  const valid = (v) => (v === "light" || v === "dark" ? v : null);
  // the saved choice, or null to follow the system
  const read = () => {
    try {
      return valid(window.localStorage.getItem(KEY));
    } catch {
      return fallback;
    }
  };
  const apply = () => {
    const theme = read() || (media.matches ? "dark" : "light");
    document.documentElement.dataset.theme = theme;
    // keep the header switch in step, also when the system setting flips
    document.querySelectorAll("[data-theme-choice]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themeChoice === theme)));
  };
  apply();
  media.addEventListener("change", apply);
  window.mancarTheme = {
    get: read,
    set(pref) {
      fallback = valid(pref);
      try {
        window.localStorage.setItem(KEY, fallback);
      } catch {
        /* kept in memory for this page */
      }
      apply();
    },
  };
})();
