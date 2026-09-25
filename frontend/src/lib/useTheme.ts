import { useCallback, useEffect, useState } from "react";

export type Theme = "dark" | "light";

const STORAGE_KEY = "codereviewer.theme";
const THEME_COLOR: Record<Theme, string> = { dark: "#1a1a1a", light: "#f4f3f1" };

function currentTheme(): Theme {
  // index.html's inline script already set this on <html> before React mounted.
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

/** Reads/writes the `data-theme` attribute set by index.html's anti-flash script. */
export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(currentTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLOR[theme]);
    localStorage.setItem(STORAGE_KEY, theme);
  }, [theme]);

  const toggle = useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), []);
  return [theme, toggle];
}
