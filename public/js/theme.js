/* global localStorage, matchMedia */

(function () {
  function systemPrefersDark() {
    return (
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    );
  }

  function storedTheme() {
    try {
      var t = localStorage.getItem("theme");
      return t === "dark" || t === "light" ? t : null;
    } catch (e) {
      return null;
    }
  }

  function currentTheme() {
    var attr = document.documentElement.getAttribute("data-theme");
    if (attr === "dark" || attr === "light") return attr;
    var stored = storedTheme();
    if (stored) return stored;
    return systemPrefersDark() ? "dark" : "light";
  }

  function applyTheme(theme, persist) {
    document.documentElement.setAttribute("data-theme", theme);
    if (persist) {
      try {
        localStorage.setItem("theme", theme);
      } catch (e) {}
    }
    updateToggle(theme);
  }

  function updateToggle(theme) {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;

    var isDark = theme === "dark";
    btn.textContent = isDark ? "Theme: Dark" : "Theme: Light";
    btn.setAttribute("aria-pressed", isDark ? "true" : "false");
    btn.setAttribute(
      "aria-label",
      isDark ? "Switch to light mode" : "Switch to dark mode"
    );
    btn.title = isDark ? "Switch to light mode" : "Switch to dark mode";
  }

  function init() {
    var btn = document.getElementById("theme-toggle");
    var theme = currentTheme();
    updateToggle(theme);

    if (btn) {
      btn.addEventListener("click", function () {
        var next = currentTheme() === "dark" ? "light" : "dark";
        applyTheme(next, true);
      });
    }

    // If the user hasn't set a preference, track system changes.
    if (!storedTheme() && window.matchMedia) {
      var mq = window.matchMedia("(prefers-color-scheme: dark)");
      var handler = function () {
        // Only update if the user still hasn't chosen a persistent theme.
        if (!storedTheme()) applyTheme(systemPrefersDark() ? "dark" : "light", false);
      };
      if (mq.addEventListener) mq.addEventListener("change", handler);
      else if (mq.addListener) mq.addListener(handler);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
