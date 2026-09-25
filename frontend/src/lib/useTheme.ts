import { useCallback, useSyncExternalStore } from "react";

export type Theme = "dark" | "light";

const STORAGE_KEY = "codereviewer.theme";
const THEME_COLOR: Record<Theme, string> = { dark: "#141414", light: "#f6f5f2" };
const listeners = new Set<() => void>();

function currentTheme(): Theme {
  // index.html's inline script already set this on <html> before React mounted.
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

function setTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLOR[theme]);
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // storage unavailable (private mode) — the choice just won't persist
  }
  listeners.forEach((notify) => notify());
}

function subscribe(notify: () => void): () => void {
  listeners.add(notify);
  return () => listeners.delete(notify);
}

/** One shared theme for every component (navbar button and user menu stay in sync). */
export function useTheme(): [Theme, () => void] {
  const theme = useSyncExternalStore(subscribe, currentTheme);
  const toggle = useCallback(() => setTheme(currentTheme() === "dark" ? "light" : "dark"), []);
  return [theme, toggle];
}
