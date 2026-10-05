// Derived e2e fixtures, made from the app's sealed.jpg (synthetic scene, synthetic ocean coordinates: P3). Deterministic; re-run with
// `npx tsx scripts/make-fixtures.ts`. No output carries GPS: maybe_edited.jpg and the two NO_FINGERPRINT fixtures have no metadata at
// all, rotated_portrait_48mp.jpg has one EXIF tag (Orientation = 6) and nothing else.
import jpeg from 'jpeg-js'; import QRCode from 'qrcode'; import { readFileSync, writeFileSync } from 'node:fs';
import { cells, synth } from '../test/helpers/gen';
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

// 3. NO_FINGERPRINT (P26/P28): the vectors' v1_case7 seal (flag bit 7, phash 0, synthetic ocean point 30.12345, 140.54321) printed as a QR on
// two synthetic scenes from the vectors' generators. dark_sealed.jpg: the `cells` near-black scene (luma 0/1) — the kind of photo the
// app seals without a fingerprint, so the page says "too dark or flat to compare". bright_sealed.jpg: the same seal on the `synth`
// scene (full of detail) — a NO_FINGERPRINT seal moved onto another photo, so the page must say red (texture > 8 × TEXTURE_FLOOR).
// The QR (error correction M, as the app's QrRenderer; 3 px/module, the app's floor) sits on a white panel well inside the seal's
// frame [4, 202, 252, 255], so the fingerprint mask covers it, JPEG ringing included.
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const c7 = V.payloads.find((p: { name: string }) => p.name === 'v1_case7');
if (!c7?.fields.noFingerprint || c7.fields.frame.join() !== '4,202,252,255') throw new Error('v1_case7 changed: re-check the panel geometry');
const qr = QRCode.create(c7.url, { errorCorrectionLevel: 'M' }).modules; const MOD = 3, QZ = 4, QS = (qr.size + 2 * QZ) * MOD;
const FW = 1600, FH = 1200, PX0 = 48, PX1 = 1560, PY0 = 970, PY1 = 1192;   // frame in px: x [25, 1582), y [950, 1200)
if (PY1 - PY0 < QS + 10) throw new Error('QR does not fit the panel');
function stamp(scene: Uint8Array): Buffer {
  const o = Buffer.from(scene); const qx = PX1 - 10 - QS, qy = PY0 + 5;
  for (let y = PY0; y < PY1; y++) for (let x = PX0; x < PX1; x++) {
    const mx = Math.floor((x - qx) / MOD) - QZ, my = Math.floor((y - qy) / MOD) - QZ;
    const dark = mx >= 0 && my >= 0 && mx < qr.size && my < qr.size && qr.get(my, mx) === 1;
    const i = (y * FW + x) * 4; o[i] = o[i + 1] = o[i + 2] = dark ? 0 : 255; o[i + 3] = 255;
  }
  return o;
}
writeFileSync('e2e/fixtures/dark_sealed.jpg', jpeg.encode({ data: stamp(cells(FW, FH, 400)), width: FW, height: FH }, 90).data);
writeFileSync('e2e/fixtures/bright_sealed.jpg', jpeg.encode({ data: stamp(synth(FW, FH, 5)), width: FW, height: FH }, 90).data);
