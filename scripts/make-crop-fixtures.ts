// P41/P41b fixtures: a LOW-TEXTURE sealed photo (the acceptance ❌1d class: a 10 % top crop of such a photo kept its fingerprint
// distance ≤ 8 and read green), and crops/shares of it. Deterministic; re-run with `npx tsx scripts/make-crop-fixtures.ts`.
// The photo is composed here, not by the app: a 2000 × 1500 soft "wall" with a COMPACT_END-like transparent bottom-right panel. The QR sits exactly
// where the app's layout puts it (src/geometry.ts, the port of StampLayout.kt + QrRenderer.kt, itself checked against the app-made
// e2e/fixtures/sealed.jpg and real M20 photos), and its seal is a real v1 payload (105 B) signed by the vectors' PUBLIC TEST KEY over
// this picture's own fingerprint and aspect. Synthetic ocean coordinates (P3). No metadata in any output.
import jpeg from 'jpeg-js'; import QRCode from 'qrcode'; import { readFileSync, writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js'; import { sha256 } from '@noble/hashes/sha2.js';
import { URL_PREFIX } from '../src/config';
import { aspectOf, model, qrLeftPx, qrSidePx, SEAL_SIDE_MODULES } from '../src/geometry';
import { b64urlEncode, decodePayload, encodeHeader, type SealFields } from '../src/payload';
import { fingerprintRgba } from '../src/phash';
import { checkSeal } from '../src/crypto';

const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const W = 2000, H = 1500;
// The scene: soft light and shadow on a wall (two slow sinusoids, luma ~110–240). Chosen because its fingerprint barely moves under a crop
// (distance 0–14 for 3–10 % off any side, measured): the picture-hash alone would call these crops green or "maybe edited".
const img = new Uint8Array(W * H * 4);
for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
  const g = 175 + 40 * Math.sin(x / 300) + 25 * Math.cos(y / 260);
  const i = (y * W + x) * 4; img[i] = Math.round(g + 6); img[i + 1] = Math.round(g); img[i + 2] = Math.round(g - 10); img[i + 3] = 255;
}
// The panel, as StampLayout.place() for a COMPACT_END template (transparent background, 60 % wide, right-aligned: the app's third
// template) whose tallest item is the QR: panelH = side + 2·pad, top = H − margin − panelH. Only the QR is drawn: the panel is transparent.
const side = qrSidePx(W, H), pad = Math.fround(W * 0.02), margin = pad;
const panelW = Math.fround(W * 0.6), panelH = side + 2 * pad, top = H - margin - panelH, left = W - margin - panelW, right = W - margin, bottom = top + panelH;
// SealFrame.fromPanel: outward rounding plus one unit of margin.
const lo = (v: number, size: number) => Math.min(255, Math.max(0, Math.floor((v / size) * 255) - 1));
const hi = (v: number, size: number) => Math.min(255, Math.max(0, Math.ceil((v / size) * 255) + 1));
const frame: [number, number, number, number] = [lo(left, W), lo(top, H), hi(right, W), hi(bottom, H)];
// The seal: this picture's fingerprint (the stamp masked by the frame, so the QR drawn later does not change it).
const fp = fingerprintRgba(img, W, H, frame); if (fp.flat) throw new Error('scene too flat: it would be NO_FINGERPRINT');
const tk = V.testKey as { d: string; keyTag: number };
const fields: SealFields = { version: 1, epochSeconds: 1791190582, tzOffsetMinutes: 420, autoTime: true, clockSkewSeconds: 1, softwareKey: false,
  location: { latE5: 3012345, lngE5: 14054321, accuracyM: 5, ageTens: 0, approximate: false, stale: false }, phash: fp.hash, frame, keyTag: tk.keyTag,
  noFingerprint: false, aspect: aspectOf(W, H), locationWithheld: false };
const msg = encodeHeader(fields, 0);
const sig = p256.sign(sha256(msg), Uint8Array.from(Buffer.from(tk.d, 'hex')), { prehash: false, lowS: true, format: 'recovered' });
const v = sig[0] as 0 | 1;
const payload = new Uint8Array(105); payload.set(encodeHeader(fields, v)); payload.set(sig.subarray(1, 65), 41);
const p = decodePayload(payload); if (!checkSeal(p).ok) throw new Error('the test key did not seal it');
const url = URL_PREFIX + b64urlEncode(payload); if (url.length !== 171) throw new Error('not a v1 URL');
// The QR, as QrRenderer.bitmap at StampLayout's square: version 9-M, cell = side div 61, remainder centred, 4-module quiet zone.
const qr = QRCode.create(url, { errorCorrectionLevel: 'M' }).modules; if (qr.size !== 53) throw new Error('not version 9');
const cell = Math.floor(side / SEAL_SIDE_MODULES), qx = qrLeftPx(W, side), qy = Math.floor(top + pad);
const origin = Math.floor((side - cell * SEAL_SIDE_MODULES) / 2) + 4 * cell;
const m = model(W, H, frame[1])!; if (m.symX !== qx + origin || qy + origin < m.symYlo || qy + origin > m.symYhi) throw new Error('model and drawing disagree');
for (let y = qy; y < qy + side; y++) for (let x = qx; x < qx + side; x++) {
  const mx = Math.floor((x - qx - origin) / cell), my = Math.floor((y - qy - origin) / cell);
  const dark = x - qx >= origin && y - qy >= origin && mx < 53 && my < 53 && qr.get(my, mx) === 1;
  const i = (y * W + x) * 4; img[i] = img[i + 1] = img[i + 2] = dark ? 0 : 255;
}
const enc = (d: Uint8Array, w: number, h: number, q: number) => jpeg.encode({ data: d, width: w, height: h }, q).data;
writeFileSync('e2e/fixtures/flat_sealed.jpg', enc(img, W, H, 92));
// The ❌1d case, as a fixture for the browsers: 10 % off the top. And one QR-losing crop (10 % off the right cuts the QR) for I4.
const crop = (dx0: number, dy0: number, w: number, h: number) => { const o = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) o.set(img.subarray(((y + dy0) * W + dx0) * 4, ((y + dy0) * W + dx0 + w) * 4), y * w * 4); return o; };
writeFileSync('e2e/fixtures/flat_crop_top10.jpg', enc(crop(0, 150, W, H - 150), W, H - 150, 92));
writeFileSync('e2e/fixtures/flat_crop_right10.jpg', enc(crop(0, 0, W - 200, H), W - 200, H, 92));
console.log('written; fragment', url.slice(URL_PREFIX.length));
