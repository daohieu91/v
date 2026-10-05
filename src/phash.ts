/**
 * 64-bit DCT fingerprint (spec §4.2): a step-for-step port of the app's PerceptualHash.kt KDoc (Task 6 + P20 round). The golden
 * vectors prove the two agree bit for bit. Integer arithmetic only: no float, no canvas scaler, no Math.cos. Every intermediate value
 * is an exact integer below 2⁵³, so plain `number` maths is exact; the 64 hash bits are assembled as a BigInt.
 */
import { TEXTURE_FLOOR } from './config';
export const TABLE: readonly (readonly number[])[] = [
  [4091, 4052, 3973, 3857, 3703, 3513, 3290, 3035, 2751, 2440, 2106, 1751, 1380, 995, 601, 201, -201, -601, -995, -1380, -1751, -2106, -2440, -2751, -3035, -3290, -3513, -3703, -3857, -3973, -4052, -4091],
  [4076, 3920, 3612, 3166, 2598, 1931, 1189, 401, -401, -1189, -1931, -2598, -3166, -3612, -3920, -4076, -4076, -3920, -3612, -3166, -2598, -1931, -1189, -401, 401, 1189, 1931, 2598, 3166, 3612, 3920, 4076],
  [4052, 3703, 3035, 2106, 995, -201, -1380, -2440, -3290, -3857, -4091, -3973, -3513, -2751, -1751, -601, 601, 1751, 2751, 3513, 3973, 4091, 3857, 3290, 2440, 1380, 201, -995, -2106, -3035, -3703, -4052],
  [4017, 3406, 2276, 799, -799, -2276, -3406, -4017, -4017, -3406, -2276, -799, 799, 2276, 3406, 4017, 4017, 3406, 2276, 799, -799, -2276, -3406, -4017, -4017, -3406, -2276, -799, 799, 2276, 3406, 4017],
  [3973, 3035, 1380, -601, -2440, -3703, -4091, -3513, -2106, -201, 1751, 3290, 4052, 3857, 2751, 995, -995, -2751, -3857, -4052, -3290, -1751, 201, 2106, 3513, 4091, 3703, 2440, 601, -1380, -3035, -3973],
  [3920, 2598, 401, -1931, -3612, -4076, -3166, -1189, 1189, 3166, 4076, 3612, 1931, -401, -2598, -3920, -3920, -2598, -401, 1931, 3612, 4076, 3166, 1189, -1189, -3166, -4076, -3612, -1931, 401, 2598, 3920],
  [3857, 2106, -601, -3035, -4091, -3290, -995, 1751, 3703, 3973, 2440, -201, -2751, -4052, -3513, -1380, 1380, 3513, 4052, 2751, 201, -2440, -3973, -3703, -1751, 995, 3290, 4091, 3035, 601, -2106, -3857],
  [3784, 1567, -1567, -3784, -3784, -1567, 1567, 3784, 3784, 1567, -1567, -3784, -3784, -1567, 1567, 3784, 3784, 1567, -1567, -3784, -3784, -1567, 1567, 3784, 3784, 1567, -1567, -3784, -3784, -1567, 1567, 3784],
];
export const SIDE_MAX = 1024;
const MIN_SIDE = 32;
type Frame = readonly [number, number, number, number];

/** SealFrame.xRange / yRange: [ (lo·size) div 255, min(size, (hi·size + 254) div 255) ). No `|0`: lo·size can exceed 2³¹. */
const range = (lo: number, hi: number, size: number): [number, number] =>
  [Math.floor((lo * size) / 255), Math.min(size, Math.floor((hi * size + 254) / 255))];

/**
 * Step 1 (preflight F-M9: the same integer 2×2 halving as the app): while max(W, H) > 1024 and min(W, H) ≥ 64, W' = W div 2,
 * H' = H div 2 and per channel c' = (c00 + c01 + c10 + c11 + 2) div 4; an odd last column / row is dropped; each halving rounds on its
 * own. Returns RGBA (alpha 255) and the number of halvings. The input is never mutated; with no halving it is returned as is.
 */
export function halveToMax(rgba: ArrayLike<number>, w: number, h: number): { rgba: ArrayLike<number>; w: number; h: number; halvings: number } {
  let px = rgba; let k = 0;
  while (Math.max(w, h) > SIDE_MAX && Math.min(w, h) >= 2 * MIN_SIDE) {
    const nw = Math.floor(w / 2), nh = Math.floor(h / 2); const out = new Uint8Array(nw * nh * 4);
    for (let y = 0; y < nh; y++) {
      const r0 = 2 * y * w * 4, r1 = r0 + w * 4;
      for (let x = 0; x < nw; x++) {
        const a = r0 + 8 * x, b = r1 + 8 * x, o = (y * nw + x) * 4;
        for (let c = 0; c < 3; c++) out[o + c] = (px[a + c] + px[a + 4 + c] + px[b + c] + px[b + 4 + c] + 2) >> 2;
        out[o + 3] = 255;
      }
    }
    px = out; w = nw; h = nh; k++;
  }
  return { rgba: px, w, h, halvings: k };
}

/** The hash and the Step 7 texture of one image, from one pass (PerceptualHash.Fingerprint). `flat` → the app seals with NO_FINGERPRINT. */
export interface Fingerprint { hash: bigint; texture: number; flat: boolean }
const fp = (hash: bigint, texture: number): Fingerprint => ({ hash, texture, flat: texture < TEXTURE_FLOOR });

/**
 * The hash of a W × H RGBA image (row-major; alpha ignored) with the stamp rectangle `frame` (1/255ths) masked out.
 * Degenerate input (W or H < 32, or fewer than W·H pixels) hashes to 0, as in the app. Memory: one halved RGBA copy when a halving is
 * due (¼ of the input) plus a W·H luma array of the shrunk size; callers keep inputs bounded (Task 21: ≤ 4096 px per side).
 */
export function phashRgba(rgba: ArrayLike<number>, w0: number, h0: number, frame: Frame): bigint {
  return fingerprintRgba(rgba, w0, h0, frame).hash;
}

/**
 * Steps 0–7: the hash (Steps 1–6) and the texture (Step 7, P26): over the same 32 × 32 cells s, after the Step 3 mask fill,
 * texture = 1024·Σs² − (Σs)² (= 1024² × the cell variance). S ≤ 261 120 and 1024·Q < 2³⁶, so `number` is exact (the Kotlin Long fits).
 * Degenerate input has hash 0 and texture 0.
 */
export function fingerprintRgba(rgba: ArrayLike<number>, w0: number, h0: number, frame: Frame): Fingerprint {
  if (w0 < MIN_SIDE || h0 < MIN_SIDE || rgba.length < w0 * h0 * 4) return fp(0n, 0);
  const { rgba: px, w, h, halvings } = halveToMax(rgba, w0, h0);
  // Step 2: BT.601 integer luma.
  const y = new Uint8Array(w * h);
  for (let i = 0; i < w * h; i++) { const o = 4 * i; y[i] = Math.floor((299 * px[o] + 587 * px[o + 1] + 114 * px[o + 2] + 500) / 1000); }
  // Step 3: mask fill, with the +1 end-edge dilation after any halving (P20 b).
  let [x0, x1] = range(frame[0], frame[2], w); let [y0, y1] = range(frame[1], frame[3], h);
  if (halvings > 0 && x0 < x1 && y0 < y1) { x1 = Math.min(w, x1 + 1); y1 = Math.min(h, y1 + 1); }
  let sum = 0; let cnt = 0;
  for (let r = 0; r < h; r++) {
    const inRow = r >= y0 && r < y1;
    for (let c = 0; c < w; c++) if (!inRow || c < x0 || c >= x1) { sum += y[r * w + c]; cnt++; }
  }
  const fill = cnt === 0 ? 128 : Math.floor((sum + Math.floor(cnt / 2)) / cnt);
  for (let r = y0; r < y1; r++) for (let c = x0; c < x1; c++) y[r * w + c] = fill;
  // Step 4: box (area) downscale to 32 × 32.
  const s = new Array<number>(1024);
  for (let j = 0; j < 32; j++) {
    const ya = Math.floor((j * h) / 32), yb = Math.floor(((j + 1) * h) / 32);
    for (let i = 0; i < 32; i++) {
      const xa = Math.floor((i * w) / 32), xb = Math.floor(((i + 1) * w) / 32);
      let acc = 0; for (let yy = ya; yy < yb; yy++) for (let xx = xa; xx < xb; xx++) acc += y[yy * w + xx];
      const n = (xb - xa) * (yb - ya); s[j * 32 + i] = Math.floor((acc + Math.floor(n / 2)) / n);
    }
  }
  // Step 7: texture of the cells (computed here, from the same cells; the DCT below does not change them).
  let sumS = 0, sumSq = 0; for (let k = 0; k < 1024; k++) { sumS += s[k]; sumSq += s[k] * s[k]; }
  const texture = 1024 * sumSq - sumS * sumS;
  // Step 5: unnormalised integer DCT-II, u, v = 1..8 (TABLE row u−1), rows then columns.
  const R: number[][] = [];
  for (let yy = 0; yy < 32; yy++) { const row: number[] = []; for (let u = 0; u < 8; u++) { let a = 0; for (let x = 0; x < 32; x++) a += TABLE[u][x] * s[yy * 32 + x]; row.push(a); } R.push(row); }
  const f: number[] = [];                                       // k = (v−1)·8 + (u−1)
  for (let v = 0; v < 8; v++) for (let u = 0; u < 8; u++) { let a = 0; for (let yy = 0; yy < 32; yy++) a += TABLE[v][yy] * R[yy][u]; f.push(a); }
  // Step 6: median bits; numeric sort (the default sort is lexicographic); strictly greater; bit k is bit 63 − k.
  const q = [...f].sort((a, b) => a - b); const mid2 = q[31] + q[32];
  let hash = 0n; for (let k = 0; k < 64; k++) if (2 * f[k] > mid2) hash |= 1n << BigInt(63 - k);
  return fp(hash, texture);
}
export function hamming(a: bigint, b: bigint): number { let x = a ^ b; let n = 0; while (x) { n += Number(x & 1n); x >>= 1n; } return n; }
/** The one text form of a hash: exactly 16 lowercase hex digits, zero-padded. */
export const phashHex = (h: bigint): string => h.toString(16).padStart(16, '0');
