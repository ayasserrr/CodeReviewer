// Applied synchronously, before first paint, so the page never flashes the wrong theme.
// A separate file (not inline) so the Content-Security-Policy can forbid inline scripts.
(function () {
  var stored = null;
  try {
    stored = localStorage.getItem("codereviewer.theme");
  } catch (e) {
    // storage blocked (private mode): fall back to the system preference
  }
  var theme = stored === "light" || stored === "dark"
    ? stored
    : (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  document.documentElement.setAttribute("data-theme", theme);
})();
