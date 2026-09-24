import { useEffect, useRef } from "react";

/** Calls `fn` now and then every `intervalMs` while `active`; pauses while the tab is hidden. */
export function usePolling(fn: () => void | Promise<void>, intervalMs: number, active: boolean): void {
  const saved = useRef(fn);
  saved.current = fn;

  useEffect(() => {
    if (!active) return;
    let timer: number | undefined;
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      if (document.visibilityState === "visible") await saved.current();
      if (!cancelled) timer = window.setTimeout(tick, intervalMs);
    };
    tick();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [intervalMs, active]);
}
