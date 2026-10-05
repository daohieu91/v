// GitHub Pages cannot send frame-ancestors and a <meta> CSP ignores it, so this external script is the
// clickjacking defence. It only acts when the top window is on ANOTHER origin; framing within our own
// origin (index.html embedding l2.html) is untouched.
export interface FramingWindow { self: unknown; top: { location: { href: string } } | null; location: { href: string } }
export function topIsCrossOrigin(w: FramingWindow): boolean {
  if (w.top === null || w.top === w.self) return false;
  try { void w.top.location.href; return false; } catch { return true; }
}
export function guardFraming(w: Window): void {
  if (!topIsCrossOrigin(w as unknown as FramingWindow)) return;
  w.document.documentElement.style.display = 'none';
  try { (w.top as Window).location.replace(w.location.href); } catch { /* blocked: stay hidden */ }
}
