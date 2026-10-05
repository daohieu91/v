// Task 23: run the page's level-1 pipeline on a real photo from a shell, with the same modules (no browser).
// Usage: npm run verify-file -- <photo.jpg>   Prints one JSON line; no coordinates, no file name. Exit 2 = no code.
import jpeg from 'jpeg-js'; import { readFileSync } from 'node:fs';
import { checkSeal } from '../src/crypto'; import { payloadFromUrl } from '../src/payload'; import { hamming, phashRgba } from '../src/phash';
import { findSealUrl } from '../src/qr'; import { verdict } from '../src/verdict';
const img = jpeg.decode(readFileSync(process.argv[2]), { useTArray: true, formatAsRGBA: true, maxMemoryUsageInMB: 1024 });
const im = { data: Uint8ClampedArray.from(img.data), w: img.width, h: img.height };
const url = findSealUrl(im);                                     // P22: full, ~1600, ~1000, corner, bottom band
if (!url) { console.log('NO_CODE'); process.exit(2); }
const p = payloadFromUrl(url); const seal = p ? checkSeal(p) : null;
// Full-size pixels: phashRgba does the app's own integer halvings (F-M9), exactly as the page does for photos up to 4096 px.
const dist = p ? hamming(phashRgba(im.data, im.w, im.h, p.fields.frame), p.fields.phash) : null;
const v = verdict({ payload: p, seal, hamming: dist, level2: null });
console.log(JSON.stringify({ verdict: v.color, headline: v.headline, distance: dist, time: p?.fields.epochSeconds ?? null, keyId: seal?.keyIdHex ?? null, size: [im.w, im.h] }));
