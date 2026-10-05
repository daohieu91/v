// Derived e2e fixtures, made from the app's sealed.jpg (synthetic scene, synthetic ocean coordinates: P3). Deterministic; re-run with
// `npx tsx scripts/make-fixtures.ts`. Neither output carries GPS: maybe_edited.jpg has no metadata at all, rotated_portrait_48mp.jpg
// has one EXIF tag (Orientation = 6) and nothing else.
import jpeg from 'jpeg-js'; import { readFileSync, writeFileSync } from 'node:fs';
const src = jpeg.decode(readFileSync('e2e/fixtures/sealed.jpg'), { useTArray: true, formatAsRGBA: true });
const W = src.width, H = src.height;

// 1. A light filter (vignette, strength 2.5) over the whole photo: the "maybe lightly edited" band (distance 12 in node).
const v = Buffer.alloc(W * H * 4);
for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) { const d = (x / W - 0.5) ** 2 + (y / H - 0.5) ** 2, f = 1 - 2.5 * d, i = (y * W + x) * 4;
  for (let c = 0; c < 3; c++) v[i + c] = Math.max(0, Math.min(255, Math.round(src.data[i + c] * f))); v[i + 3] = 255; }
writeFileSync('e2e/fixtures/maybe_edited.jpg', jpeg.encode({ data: v, width: W, height: H }, 90).data);

// 2. 48 MP stored as portrait (6000 × 8000) with EXIF Orientation 6, so it DISPLAYS as the sealed landscape photo at 4× (8000 × 6000).
// raw(rx, ry) = display(dx = RH − 1 − ry, dy = rx), display = sealed.jpg upscaled 4× (nearest).
const RW = H * 4, RH = W * 4, raw = Buffer.alloc(RW * RH * 4);
for (let ry = 0; ry < RH; ry++) for (let rx = 0; rx < RW; rx++) { const dx = RH - 1 - ry, dy = rx, s = ((dy >> 2) * W + (dx >> 2)) * 4, o = (ry * RW + rx) * 4;
  raw[o] = src.data[s]; raw[o + 1] = src.data[s + 1]; raw[o + 2] = src.data[s + 2]; raw[o + 3] = 255; }
const enc = jpeg.encode({ data: raw, width: RW, height: RH }, 80).data;
const tiff = [0x4d, 0x4d, 0, 42, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0];
const body = [...Buffer.from('Exif\0\0', 'binary'), ...tiff];
const app1 = Buffer.from([0xff, 0xe1, (body.length + 2) >> 8, (body.length + 2) & 255, ...body]);
writeFileSync('e2e/fixtures/rotated_portrait_48mp.jpg', Buffer.concat([enc.subarray(0, 2), app1, enc.subarray(2)]));
