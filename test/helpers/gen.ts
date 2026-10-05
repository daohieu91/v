// The vectors' `generators` (verify-vectors.json), as RGBA bytes (alpha 255). Same text as phash_ref.py synth/noise/flat.
export function synth(w: number, h: number, seed: number): Uint8Array {
  const o = new Uint8Array(w * h * 4); const cw = Math.max(1, Math.floor(w / 7)), ch = Math.max(1, Math.floor(h / 5));
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = Math.floor(i / w);
    o[4 * i] = (Math.floor((x * 255) / w) + seed * 13) & 255;
    o[4 * i + 1] = (Math.floor((y * 255) / h) + seed * 29) & 255;
    o[4 * i + 2] = (Math.floor(x / cw) + Math.floor(y / ch) + seed) % 2 === 0 ? 40 : 210;
    o[4 * i + 3] = 255;
  }
  return o;
}
export function noise(w: number, h: number, seed: number): Uint8Array {
  const o = new Uint8Array(w * h * 4); let s = seed >>> 0;
  for (let i = 0; i < w * h; i++) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0; const v = s >>> 8;
    o[4 * i] = (v >>> 16) & 255; o[4 * i + 1] = (v >>> 8) & 255; o[4 * i + 2] = v & 255; o[4 * i + 3] = 255;
  }
  return o;
}
export function flat(w: number, h: number, argb: number): Uint8Array {
  const o = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) { o[4 * i] = (argb >>> 16) & 255; o[4 * i + 1] = (argb >>> 8) & 255; o[4 * i + 2] = argb & 255; o[4 * i + 3] = 255; }
  return o;
}
/** The near-black floor scenes (P26): c = (x·32 div w) + 32·(y·32 div h); R = G = B = 1 if c < seed, else 0. */
export function cells(w: number, h: number, seed: number): Uint8Array {
  const o = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = Math.floor(i / w); const c = Math.floor((x * 32) / w) + 32 * Math.floor((y * 32) / h); const v = c < seed ? 1 : 0;
    o[4 * i] = v; o[4 * i + 1] = v; o[4 * i + 2] = v; o[4 * i + 3] = 255;
  }
  return o;
}
export const GEN: Record<string, (w: number, h: number, seed: number) => Uint8Array> = { synth, noise, flat, cells };
