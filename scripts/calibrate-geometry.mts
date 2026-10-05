// P41/P41b calibration (final review I5): measures, on app-made photos and their unedited "shares", the aspect difference and the QR
// residual (src/geometry.ts) — their maximum sets ASPECT_TOL and GEOMETRY_TOL — then the detection rate on crops.
// Usage: npx tsx scripts/calibrate-geometry.mts <dir-or-file>...   (prints a table; writes nothing; no image, path or coordinate is logged)
// Corpus kinds, told apart by the payload in the QR:
//  - a v1 payload (105 B): its own frame and aspect, the current sizing rule (P27a);
//  - a 103-B payload (Task 10B's real Galaxy M20 photos, before P27a): its frame bytes (same offsets), the aspect of the file, and the
//    sizing rule they were made with (0.1525·w only);
//  - anything else (random-content QRs from the 10C layout spike: real StampLayout output, payload not a seal): x and size only.
// Shares: decoded like the page (sharp = libjpeg-turbo, as Chromium/Firefox), resized (lanczos3, cubic, linear, nearest) to a long side of
// 2560, 2048, 1600, 1280, 960 and re-encoded at JPEG q65, q75, q85 and q92, plus the original itself. Crops: 2, 3, 5 and 10 % off ONE side,
// and 5 and 10 % off two adjacent sides keeping the aspect (proportional), each then shared at 1600 q75.
import sharp from 'sharp'; import { readdirSync, readFileSync, statSync } from 'node:fs'; import { join } from 'node:path';
import { aspectOf, qrResidual, qrSidePx, ASPECT_TOL, GEOMETRY_TOL } from '../src/geometry';
import { findSeal } from '../src/qr';

const f32 = Math.fround;
const oldSide = (w: number, h: number) => Math.max(0, Math.min(Math.max(Math.floor(f32(w * f32(0.1525)) + 0.5), 183), Math.trunc(f32(w * 0.25)),
  Math.trunc(f32(f32(h * f32(0.6)) - f32(f32(2 * w) * f32(0.02))))));
const files = process.argv.slice(2).flatMap(p => statSync(p).isDirectory() ? readdirSync(p).filter(f => /__orig\.png$|\.jpe?g$/i.test(f)).map(f => join(p, f)) : [p]);
type Row = { kind: string; aspect: number | null; resid: number | null };
const ok: Row[] = []; const crops: Record<string, Row[]> = {};
let n = 0;
async function rgba(buf: Buffer) { const { data, info } = await sharp(buf).rotate().ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return { data: new Uint8ClampedArray(data.buffer, data.byteOffset, data.length), w: info.width, h: info.height }; }
async function measure(buf: Buffer, seal: { y0: number | null; aspect: number; side: (w: number, h: number) => number }): Promise<Row | null> {
  const im = await rgba(buf); const hit = findSeal(im); if (!hit) return null;
  const aspect = Math.abs(aspectOf(im.w, im.h) - seal.aspect) / seal.aspect;
  const resid = hit.finders ? qrResidual(hit.finders, im.w, im.h, seal.y0, seal.aspect, seal.side) : null;
  return { kind: '', aspect, resid };
}
for (const f of files) {
  const src = readFileSync(f); const im = await rgba(src); const hit = findSeal(im); if (!hit) { console.log('skip (no QR)'); continue; }
  const b = Buffer.from(hit.url.split('#')[1], 'base64url');
  const seal = b.length === 105 ? { y0: b[32] as number | null, aspect: (b[39] << 8) | b[40], side: qrSidePx, tag: 'v1' }
    : b.length === 103 && b[31] <= b[33] && b[32] <= b[34] ? { y0: b[32] as number | null, aspect: aspectOf(im.w, im.h), side: oldSide, tag: 'm20-pre-P27a' }
    : { y0: null, aspect: aspectOf(im.w, im.h), side: qrSidePx, tag: 'layout-only' };
  n++;
  const long = Math.max(im.w, im.h);
  const variants: [string, Buffer][] = [['orig', src]];
  for (const L of (process.env.QUICK ? [1600] : [2560, 2048, 1600, 1280, 1080, 1000, 960, 720])) if (L < long) for (const kernel of ['lanczos3', 'cubic', 'linear', 'nearest'] as const)
    for (const q of (process.env.QUICK ? [75] : [65, 75, 85, 92])) {
      const w = im.w >= im.h ? L : Math.round((im.w * L) / im.h), h = im.w >= im.h ? Math.round((im.h * L) / im.w) : L;
      variants.push([`${L}/${kernel}/q${q}`, await sharp(src).rotate().resize(w, h, { kernel, fit: 'fill' }).jpeg({ quality: q }).toBuffer()]);
    }
  for (const [k, v] of variants) { const r = await measure(v, seal); if (r) ok.push({ ...r, kind: `${seal.tag} ${k}` }); else console.log(`${seal.tag} ${k}: QR not read (excluded)`); }
  const share = (x: Buffer, w: number, h: number) => { const L = 1600, s = L / Math.max(w, h); return sharp(x).resize(Math.round(w * s), Math.round(h * s), { kernel: 'lanczos3', fit: 'fill' }).jpeg({ quality: 75 }).toBuffer(); };
  for (const pct of [2, 3, 5, 10]) for (const side of ['top', 'bottom', 'left', 'right'] as const) {
    const dx = side === 'left' || side === 'right' ? Math.round((im.w * pct) / 100) : 0, dy = side === 'top' || side === 'bottom' ? Math.round((im.h * pct) / 100) : 0;
    const c = await sharp(src).rotate().extract({ left: side === 'left' ? dx : 0, top: side === 'top' ? dy : 0, width: im.w - dx, height: im.h - dy }).png().toBuffer();
    const r = await measure(await share(c, im.w - dx, im.h - dy), seal); (crops[`${side} ${pct}%`] ??= []).push(r ? { ...r, kind: seal.tag } : { kind: 'QR lost', aspect: null, resid: null });
  }
  for (const pct of [5, 10]) for (const corner of ['top-left', 'top-right', 'bottom-left']) {
    const dx = Math.round((im.w * pct) / 100), dy = Math.round((im.h * pct) / 100);
    const c = await sharp(src).rotate().extract({ left: corner.endsWith('left') ? dx : 0, top: corner.startsWith('top') ? dy : 0, width: im.w - dx, height: im.h - dy }).png().toBuffer();
    const r = await measure(await share(c, im.w - dx, im.h - dy), seal); (crops[`proportional ${corner} ${pct}%`] ??= []).push(r ? { ...r, kind: seal.tag } : { kind: 'QR lost', aspect: null, resid: null });
  }
}
const max = (xs: (number | null)[]) => Math.max(...xs.filter((x): x is number => x !== null));
console.log(`\n${n} originals, ${ok.length} unedited variants read`);
console.log(`unedited: max aspect delta ${max(ok.map(r => r.aspect)).toFixed(5)}, max QR residual ${max(ok.map(r => r.resid)).toFixed(3)} modules`);
for (const t of ['v1', 'm20-pre-P27a', 'layout-only']) { const s = ok.filter(r => r.kind.startsWith(t)); if (s.length)
  console.log(`  ${t}: ${s.length} variants, max aspect ${max(s.map(r => r.aspect)).toFixed(5)}, max residual ${max(s.map(r => r.resid)).toFixed(3)}`); }
const worst = [...ok].sort((a, b) => (b.resid ?? 0) - (a.resid ?? 0)).slice(0, 5); console.log('  worst residuals:', worst.map(r => `${r.kind}=${r.resid?.toFixed(2)}`).join(', '));
const flagged = ok.filter(r => (r.aspect ?? 0) > ASPECT_TOL || (r.resid ?? 0) > GEOMETRY_TOL);
// P45: 'unknown' (no finders, or not an upright square: tilt over ~2°) caps the verdict at yellow, so an unedited share must never be unknown.
const unknown = ok.filter(r => r.resid === null);
console.log(`unknown (no finders / tilt): ${unknown.length} of ${ok.length} unedited ${unknown.slice(0, 20).map(r => r.kind).join(', ')}`);
console.log(`with ASPECT_TOL ${ASPECT_TOL}, GEOMETRY_TOL ${GEOMETRY_TOL}: ${flagged.length} unedited flagged ${flagged.map(r => r.kind).join(', ')}`);
console.log('\ncrop → flagged / total (QR lost counts as not flagged here: the page then says "no code" or caps at yellow anyway)');
for (const [k, rs] of Object.entries(crops)) {
  const hit = rs.filter(r => (r.aspect ?? 0) > ASPECT_TOL || (r.resid ?? 0) > GEOMETRY_TOL).length; const lost = rs.filter(r => r.kind === 'QR lost').length;
  if (process.env.VERBOSE) console.log('    ', rs.map(r => `${r.kind}:${r.aspect?.toFixed(4)}/${r.resid?.toFixed(2)}`).join('  '));
  console.log(`  ${k.padEnd(28)} ${hit}/${rs.length}${lost ? ` (QR lost ${lost})` : ''}  min aspect ${rs.some(r => r.aspect !== null) ? Math.min(...rs.filter(r => r.aspect !== null).map(r => r.aspect!)).toFixed(4) : '-'}  min residual ${rs.some(r => r.resid !== null) ? Math.min(...rs.filter(r => r.resid !== null).map(r => r.resid!)).toFixed(2) : '-'}`);
}
