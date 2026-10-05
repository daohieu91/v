import jsQR from 'jsqr';
import { URL_PREFIX } from './config';
export type Img = { data: Uint8ClampedArray; w: number; h: number };
export type Step = { kind: 'full' | 'scale' | 'corner' | 'band'; x0: number; y0: number; w: number; h: number };
const SCALES = [1600, 1000] as const;

const jsqrScan = (im: Img): string | null => {
  const r = jsQR(im.data, im.w, im.h, { inversionAttempts: 'dontInvert' }); return r && r.data.startsWith(URL_PREFIX) ? r.data : null; };

/**
 * Ruling P22, in this order: the whole image; downscaled to ~1600 and ~1000 px wide (never upscaled: zxing/jsQR miss some full-size
 * 12 MP photos and read their 1600-px copy); the bottom-right stamp corner (every MVP template puts the QR there) at full resolution;
 * then the whole bottom band.
 */
export function scanPlan(w: number, h: number): Step[] {
  const p: Step[] = [{ kind: 'full', x0: 0, y0: 0, w, h }];
  for (const t of SCALES) if (w > t) p.push({ kind: 'scale', x0: 0, y0: 0, w: t, h: Math.max(1, Math.round((h * t) / w)) });
  const cx = Math.floor(w * 0.55), cy = Math.floor(h * 0.5);
  p.push({ kind: 'corner', x0: cx, y0: cy, w: w - cx, h: h - cy }, { kind: 'band', x0: 0, y0: cy, w, h: h - cy });
  return p;
}
/** Area (box) average to tw × th. */
function resize(im: Img, tw: number, th: number): Img {
  const out = new Uint8ClampedArray(tw * th * 4);
  for (let y = 0; y < th; y++) {
    const ya = Math.floor((y * im.h) / th), yb = Math.max(ya + 1, Math.floor(((y + 1) * im.h) / th));
    for (let x = 0; x < tw; x++) {
      const xa = Math.floor((x * im.w) / tw), xb = Math.max(xa + 1, Math.floor(((x + 1) * im.w) / tw));
      let r = 0, g = 0, b = 0; const n = (xb - xa) * (yb - ya);
      for (let yy = ya; yy < yb; yy++) for (let xx = xa, i = (yy * im.w + xa) * 4; xx < xb; xx++, i += 4) { r += im.data[i]; g += im.data[i + 1]; b += im.data[i + 2]; }
      const o = (y * tw + x) * 4; out[o] = r / n; out[o + 1] = g / n; out[o + 2] = b / n; out[o + 3] = 255;
    }
  }
  return { data: out, w: tw, h: th };
}
function crop(im: Img, s: Step): Img {
  const out = new Uint8ClampedArray(s.w * s.h * 4);
  for (let y = 0; y < s.h; y++) { const a = ((y + s.y0) * im.w + s.x0) * 4; out.set(im.data.subarray(a, a + s.w * 4), y * s.w * 4); }
  return { data: out, w: s.w, h: s.h };
}
/** The seal URL in the picture, or null after every step of the plan missed. Each step's buffer is dropped before the next. */
export function findSealUrl(im: Img, scan: (im: Img) => string | null = jsqrScan): string | null {
  for (const s of scanPlan(im.w, im.h)) {
    const r = scan(s.kind === 'full' ? im : s.kind === 'scale' ? resize(im, s.w, s.h) : crop(im, s));
    if (r) return r;
  }
  return null;
}
