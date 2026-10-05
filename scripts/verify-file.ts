// Task 23: run the page's level-1 pipeline on a real photo from a shell, with the same modules (no browser).
// Usage: npm run verify-file -- <photo.jpg>   Prints one JSON line; no coordinates, no file name. Exit 2 = no code.
import jpeg from 'jpeg-js'; import { readFileSync } from 'node:fs';
import { checkSeal } from '../src/crypto'; import { payloadFromUrl } from '../src/payload'; import { hamming, phashRgba } from '../src/phash';
import { findSealUrl } from '../src/qr'; import { verdict } from '../src/verdict'; import { jpegInfo } from '../src/image';
const bytes = readFileSync(process.argv[2]);
const img = jpeg.decode(bytes, { useTArray: true, formatAsRGBA: true, maxMemoryUsageInMB: 2048 });
/** EXIF orientation applied as the browser does (from-image): display(dx, dy) ← stored pixel. */
function orient(d: Uint8Array, w: number, h: number, o: number) {
  if (o <= 1 || o > 8) return { data: Uint8ClampedArray.from(d), w, h };
  const swap = o >= 5, W = swap ? h : w, H = swap ? w : h, out = new Uint8ClampedArray(W * H * 4);
  for (let dy = 0; dy < H; dy++) for (let dx = 0; dx < W; dx++) {
    const [sx, sy] = o === 2 ? [w - 1 - dx, dy] : o === 3 ? [w - 1 - dx, h - 1 - dy] : o === 4 ? [dx, h - 1 - dy]
      : o === 5 ? [dy, dx] : o === 6 ? [dy, h - 1 - dx] : o === 7 ? [w - 1 - dy, h - 1 - dx] : [w - 1 - dy, dx];
    const s = (sy * w + sx) * 4, t = (dy * W + dx) * 4; out[t] = d[s]; out[t + 1] = d[s + 1]; out[t + 2] = d[s + 2]; out[t + 3] = 255; }
  return { data: out, w: W, h: H };
}
const im = orient(img.data, img.width, img.height, jpegInfo(new Uint8Array(bytes.buffer, bytes.byteOffset, Math.min(bytes.length, 512 * 1024)))?.orientation ?? 1);
const url = findSealUrl(im);                                     // P22: full, ~1600, ~1000, corner, bottom band
if (!url) { console.log('NO_CODE'); process.exit(2); }
const p = payloadFromUrl(url); const seal = p ? checkSeal(p) : null;
// Full-size pixels: phashRgba does the app's own integer halvings (F-M9), exactly as the page does for photos up to 4096 px.
const dist = p ? hamming(phashRgba(im.data, im.w, im.h, p.fields.frame), p.fields.phash) : null;
const v = verdict({ payload: p, seal, hamming: dist, level2: null });
console.log(JSON.stringify({ verdict: v.color, headline: v.headline, distance: dist, time: p?.fields.epochSeconds ?? null, keyId: seal?.keyIdHex ?? null, size: [im.w, im.h] }));
